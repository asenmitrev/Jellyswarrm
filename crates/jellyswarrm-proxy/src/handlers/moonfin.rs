//! The Seerr subset of the Moonfin companion plugin API.
//!
//! Moonfin clients only enable their Seerr features when the server answers
//! `/Moonfin/Ping` and `/Moonfin/Seerr/*`. Jellyswarrm serves these itself so
//! Seerr (which is connected to Jellyswarrm) sees the same virtual users.
//! Contract: <https://github.com/Moonfin-Client/Plugin> (`SeerrProxyController`).

use std::{sync::LazyLock, time::Duration};

use axum::{
    body::{Body, Bytes},
    extract::{FromRequestParts, State},
    http::{header, request::Parts, HeaderMap, HeaderValue, Method, StatusCode, Uri},
    response::{IntoResponse, Response},
    routing::{any, delete, get, post},
    Json, Router,
};
use serde::Deserialize;
use serde_json::{json, Value};
use tracing::{info, warn};

use crate::{
    request_preprocessing::resolve_request_identity_from_headers_uri, seerr_sessions::SeerrSession,
    user_authorization_service::User, AppState,
};

/// Seerr gets rechecked at most this often when a client asks for status.
const SESSION_FRESHNESS: chrono::TimeDelta = chrono::TimeDelta::minutes(5);
const CSRF_COOKIES: [&str; 2] = ["XSRF-TOKEN", "_csrf"];

// Redirects are not followed: a redirected login means the Seerr URL is wrong
// and following it would drop the session cookie.
static SEERR_CLIENT: LazyLock<reqwest::Client> = LazyLock::new(|| {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(30))
        .user_agent("Jellyswarrm-Moonfin")
        .build()
        .expect("seerr client")
});

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/Ping", get(ping))
        // Legacy alias kept by the plugin for pre-rename clients.
        .nest("/Seerr", seerr_routes())
        .nest("/Jellyseerr", seerr_routes())
        // Other Moonfin features are not provided; never forward them to a backend.
        // An explicit route, since the proxy's outer catch-all would win over a fallback.
        .route("/{*rest}", any(|| async { StatusCode::NOT_FOUND }))
}

fn seerr_routes() -> Router<AppState> {
    Router::new()
        .route("/Config", get(config))
        .route("/Login", post(login))
        .route("/Status", get(status))
        .route("/Validate", get(validate))
        .route("/Logout", delete(logout))
        .route("/Api/{*path}", any(api_proxy))
}

/// The authenticated virtual user. Read-only API keys may only read.
pub struct MoonfinUser(pub User);

impl FromRequestParts<AppState> for MoonfinUser {
    type Rejection = StatusCode;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, StatusCode> {
        let identity = resolve_request_identity_from_headers_uri(&parts.headers, &parts.uri, state)
            .await
            .map_err(|_| StatusCode::UNAUTHORIZED)?;
        let user = identity.user.ok_or(StatusCode::UNAUTHORIZED)?;
        let token = identity
            .auth
            .as_ref()
            .and_then(|auth| auth.token_ref())
            .ok_or(StatusCode::UNAUTHORIZED)?;
        if !matches!(parts.method, Method::GET | Method::HEAD)
            && state
                .user_authorization
                .is_read_only_api_key(token)
                .await
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        {
            return Err(StatusCode::FORBIDDEN);
        }
        Ok(Self(user))
    }
}

struct SeerrSettings {
    url: Option<String>,
    display_name: String,
    server_name: String,
}

async fn seerr_settings(state: &AppState) -> SeerrSettings {
    let cfg = state.config.read().await;
    SeerrSettings {
        url: cfg.effective_seerr_url(),
        display_name: cfg
            .seerr_display_name
            .as_deref()
            .map(str::trim)
            .filter(|name| !name.is_empty())
            .unwrap_or("Seerr")
            .to_string(),
        server_name: cfg.server_name.clone(),
    }
}

fn error_response(status: StatusCode, body: Value) -> Response {
    (status, Json(body)).into_response()
}

fn not_enabled() -> Response {
    error_response(
        StatusCode::SERVICE_UNAVAILABLE,
        json!({ "error": "Seerr integration is not enabled", "success": false }),
    )
}

fn storage_error(error: sqlx::Error) -> Response {
    warn!("Seerr session storage failed: {error}");
    StatusCode::INTERNAL_SERVER_ERROR.into_response()
}

async fn ping(State(state): State<AppState>, MoonfinUser(_): MoonfinUser) -> Json<Value> {
    let settings = seerr_settings(&state).await;
    // `settingsSyncEnabled` is deliberately omitted: Moonfin clients treat an
    // explicit `false` as "plugin unavailable" and switch Seerr off with it.
    // Without it they probe the settings endpoints, get 404s and skip syncing.
    Json(json!({
        "installed": true,
        "version": env!("CARGO_PKG_VERSION"),
        "serverName": settings.server_name,
        "seerrEnabled": settings.url.is_some(),
        "seerrUrl": settings.url,
        "mdblistAvailable": false,
        "tmdbAvailable": false,
        "messagesSupported": false,
        "recommendationsSupported": false,
    }))
}

async fn config(State(state): State<AppState>, MoonfinUser(_): MoonfinUser) -> Json<Value> {
    let settings = seerr_settings(&state).await;
    Json(json!({
        "enabled": settings.url.is_some(),
        "url": settings.url,
        "displayName": settings.display_name,
        "variant": "seerr",
        "userEnabled": true,
    }))
}

#[derive(Deserialize)]
struct LoginRequest {
    #[serde(alias = "Username")]
    username: Option<String>,
    #[serde(alias = "Password")]
    password: Option<String>,
    #[serde(alias = "AuthType", rename = "authType")]
    auth_type: Option<String>,
}

async fn login(
    State(state): State<AppState>,
    MoonfinUser(user): MoonfinUser,
    Json(request): Json<LoginRequest>,
) -> Response {
    let Some(seerr_url) = seerr_settings(&state).await.url else {
        return not_enabled();
    };
    let auth_type = request.auth_type.as_deref().unwrap_or("jellyfin");
    if auth_type.eq_ignore_ascii_case("quickconnect") {
        return error_response(
            StatusCode::UNAUTHORIZED,
            json!({
                "error": "Quick Connect sign in to Seerr is not supported by Jellyswarrm. Sign in with your password.",
                "errorCode": "sso_unsupported",
                "success": false,
            }),
        );
    }
    let Some(username) = request.username.filter(|name| !name.trim().is_empty()) else {
        return error_response(
            StatusCode::BAD_REQUEST,
            json!({ "error": "Username is required" }),
        );
    };
    let password = request.password.unwrap_or_default();

    let (endpoint, payload) = if auth_type.eq_ignore_ascii_case("local") {
        (
            "auth/local",
            json!({ "email": username, "password": password }),
        )
    } else {
        (
            "auth/jellyfin",
            json!({ "username": username, "password": password }),
        )
    };

    let csrf = fetch_csrf(&seerr_url).await;
    let mut builder = SEERR_CLIENT
        .post(format!("{seerr_url}/api/v1/{endpoint}"))
        .header(header::ORIGIN, origin_of(&seerr_url))
        .header(header::REFERER, format!("{seerr_url}/"))
        .json(&payload);
    builder = csrf.apply(builder, None);

    let response = match builder.send().await {
        Ok(response) => response,
        Err(error) => {
            warn!("Cannot reach Seerr at {seerr_url}: {error}");
            return error_response(
                StatusCode::UNAUTHORIZED,
                json!({ "error": format!("Cannot reach Seerr: {error}"), "success": false }),
            );
        }
    };

    let status = response.status();
    if status.is_redirection() {
        return error_response(
            StatusCode::UNAUTHORIZED,
            json!({
                "error": "Seerr redirected the login request. Verify the Seerr URL in Jellyswarrm matches its public address (https and any sub-path).",
                "success": false,
            }),
        );
    }
    if !status.is_success() {
        warn!("Seerr login failed for {username}: {status}");
        let error = if status == reqwest::StatusCode::FORBIDDEN {
            "Access denied. Make sure you have a Seerr account.".to_string()
        } else {
            format!("Authentication failed: {status}")
        };
        return error_response(
            StatusCode::UNAUTHORIZED,
            json!({ "error": error, "success": false }),
        );
    }

    let Some((cookie_name, cookie_value)) = session_cookie(response.headers()) else {
        return error_response(
            StatusCode::UNAUTHORIZED,
            json!({ "error": "No session cookie received from Seerr", "success": false }),
        );
    };
    let body: Value = response.json().await.unwrap_or(Value::Null);
    let now = chrono::Utc::now();
    let mut session = SeerrSession {
        user_id: user.id.clone(),
        cookie_name,
        cookie_value,
        seerr_user_id: 0,
        display_name: Some(username.clone()),
        avatar: None,
        permissions: 0,
        created_at: now,
        last_validated: now,
    };
    apply_seerr_user(&mut session, &body);

    if let Err(error) = state
        .user_authorization
        .seerr_sessions()
        .save(&session)
        .await
    {
        return storage_error(error);
    }
    info!(
        "Seerr session created for {} (Seerr user {})",
        user.original_username, session.seerr_user_id
    );

    Json(json!({
        "success": true,
        "seerrUserId": session.seerr_user_id,
        "jellyseerrUserId": session.seerr_user_id,
        "displayName": session.display_name,
        "avatar": session.avatar,
        "permissions": session.permissions,
    }))
    .into_response()
}

async fn status(State(state): State<AppState>, MoonfinUser(user): MoonfinUser) -> Response {
    let Some(seerr_url) = seerr_settings(&state).await.url else {
        return Json(json!({ "enabled": false, "authenticated": false, "url": null }))
            .into_response();
    };
    let session = match current_session(&state, &seerr_url, &user, Some(SESSION_FRESHNESS)).await {
        Ok(session) => session,
        Err(error) => return storage_error(error),
    };
    Json(json!({
        "enabled": true,
        "authenticated": session.is_some(),
        "url": seerr_url,
        "seerrUserId": session.as_ref().map(|s| s.seerr_user_id),
        "jellyseerrUserId": session.as_ref().map(|s| s.seerr_user_id),
        "displayName": session.as_ref().and_then(|s| s.display_name.clone()),
        "avatar": session.as_ref().and_then(|s| s.avatar.clone()),
        "permissions": session.as_ref().map_or(0, |s| s.permissions),
        "sessionCreated": session.as_ref().map(|s| s.created_at.timestamp_millis()),
        "lastValidated": session.as_ref().map(|s| s.last_validated.timestamp_millis()),
    }))
    .into_response()
}

async fn validate(State(state): State<AppState>, MoonfinUser(user): MoonfinUser) -> Response {
    let Some(seerr_url) = seerr_settings(&state).await.url else {
        return Json(json!({ "valid": false, "lastValidated": null })).into_response();
    };
    match current_session(&state, &seerr_url, &user, None).await {
        Ok(session) => Json(json!({
            "valid": session.is_some(),
            "lastValidated": session.map(|s| s.last_validated.timestamp_millis()),
        }))
        .into_response(),
        Err(error) => storage_error(error),
    }
}

async fn logout(State(state): State<AppState>, MoonfinUser(user): MoonfinUser) -> Response {
    let store = state.user_authorization.seerr_sessions();
    let session = match store.get(&user.id).await {
        Ok(session) => session,
        Err(error) => return storage_error(error),
    };
    if let (Some(seerr_url), Some(session)) = (seerr_settings(&state).await.url, session) {
        let csrf = fetch_csrf(&seerr_url).await;
        let builder = SEERR_CLIENT.post(format!("{seerr_url}/api/v1/auth/logout"));
        if let Err(error) = csrf.apply(builder, Some(&session)).send().await {
            warn!("Seerr logout request failed: {error}");
        }
    }
    if let Err(error) = store.delete(&user.id).await {
        return storage_error(error);
    }
    Json(json!({ "success": true, "message": "Logged out from Seerr" })).into_response()
}

async fn api_proxy(
    State(state): State<AppState>,
    MoonfinUser(user): MoonfinUser,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Some(seerr_url) = seerr_settings(&state).await.url else {
        return not_enabled();
    };
    if !matches!(
        method,
        Method::GET | Method::POST | Method::PUT | Method::DELETE
    ) {
        return StatusCode::METHOD_NOT_ALLOWED.into_response();
    }
    let Some(path) = api_path(uri.path()) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let store = state.user_authorization.seerr_sessions();
    let session = match store.get(&user.id).await {
        Ok(Some(session)) => session,
        Ok(None) => {
            return error_response(
                StatusCode::UNAUTHORIZED,
                json!({ "error": "Not authenticated with Seerr", "code": "NO_SESSION" }),
            )
        }
        Err(error) => return storage_error(error),
    };

    let mut target = format!("{seerr_url}/api/v1/{path}");
    if let Some(query) = uri.query() {
        target.push('?');
        target.push_str(query);
    }

    let csrf = if method == Method::GET {
        CsrfTokens::default()
    } else {
        fetch_csrf(&seerr_url).await
    };
    let mut builder = SEERR_CLIENT.request(method, &target);
    if !body.is_empty() {
        let content_type = headers
            .get(header::CONTENT_TYPE)
            .cloned()
            .unwrap_or_else(|| HeaderValue::from_static("application/json"));
        builder = builder
            .header(header::CONTENT_TYPE, content_type)
            .body(body);
    }
    if let Some(accept) = headers.get(header::ACCEPT) {
        builder = builder.header(header::ACCEPT, accept.clone());
    }
    let response = match csrf.apply(builder, Some(&session)).send().await {
        Ok(response) => response,
        Err(error) => {
            warn!("Failed to proxy Seerr request {path}: {error}");
            return error_response(
                StatusCode::BAD_GATEWAY,
                json!({ "error": format!("Cannot reach Seerr: {error}") }),
            );
        }
    };

    let status = response.status();
    // Seerr answers 403 both for permission denials and for sessions it no
    // longer knows; only clear the session once Seerr confirms it is dead.
    if matches!(
        status,
        reqwest::StatusCode::UNAUTHORIZED | reqwest::StatusCode::FORBIDDEN
    ) && check_session(&seerr_url, &session).await == SessionCheck::Dead
    {
        if let Err(error) = store.delete(&user.id).await {
            return storage_error(error);
        }
        return error_response(
            StatusCode::UNAUTHORIZED,
            json!({ "error": "Seerr session expired", "code": "SESSION_EXPIRED" }),
        );
    }

    if status.is_success() {
        if let Some((name, value)) = session_cookie(response.headers()) {
            if name == session.cookie_name && value != session.cookie_value {
                let rotated = SeerrSession {
                    cookie_value: value,
                    ..session.clone()
                };
                if let Err(error) = store.save(&rotated).await {
                    warn!("Failed to store rotated Seerr cookie: {error}");
                }
            }
        }
    }

    let content_type = response.headers().get(header::CONTENT_TYPE).cloned();
    let bytes = match response.bytes().await {
        Ok(bytes) => bytes,
        Err(error) => {
            warn!("Failed to read Seerr response for {path}: {error}");
            return StatusCode::BAD_GATEWAY.into_response();
        }
    };
    let mut proxied = Response::new(Body::from(bytes));
    *proxied.status_mut() =
        StatusCode::from_u16(status.as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
    if let Some(content_type) = content_type {
        proxied
            .headers_mut()
            .insert(header::CONTENT_TYPE, content_type);
    }
    proxied
}

/// The part of the request path after the `Api/` segment, still percent-encoded.
fn api_path(path: &str) -> Option<&str> {
    let start = path.to_ascii_lowercase().find("/api/")? + "/api/".len();
    let rest = &path[start..];
    (!rest.is_empty()).then_some(rest)
}

fn origin_of(url: &str) -> String {
    url::Url::parse(url)
        .map(|url| url.origin().ascii_serialization())
        .unwrap_or_else(|_| url.to_string())
}

/// Returns the stored session, confirming it with Seerr when it is older than
/// `max_age` (always when `None`). A dead session is removed.
async fn current_session(
    state: &AppState,
    seerr_url: &str,
    user: &User,
    max_age: Option<chrono::TimeDelta>,
) -> Result<Option<SeerrSession>, sqlx::Error> {
    let store = state.user_authorization.seerr_sessions();
    let Some(mut session) = store.get(&user.id).await? else {
        return Ok(None);
    };
    let now = chrono::Utc::now();
    if max_age.is_some_and(|max_age| now - session.last_validated < max_age) {
        return Ok(Some(session));
    }
    match check_session(seerr_url, &session).await {
        SessionCheck::Alive(me) => {
            apply_seerr_user(&mut session, &me);
            session.last_validated = now;
            store.save(&session).await?;
            Ok(Some(session))
        }
        SessionCheck::Dead => {
            store.delete(&user.id).await?;
            Ok(None)
        }
        // Seerr being unreachable says nothing about the session itself.
        SessionCheck::Unknown => Ok(Some(session)),
    }
}

#[derive(Debug, PartialEq)]
enum SessionCheck {
    Alive(Value),
    Dead,
    Unknown,
}

async fn check_session(seerr_url: &str, session: &SeerrSession) -> SessionCheck {
    let request = SEERR_CLIENT
        .get(format!("{seerr_url}/api/v1/auth/me"))
        .header(header::COOKIE, cookie_header(&[], Some(session)));
    match request.send().await {
        Ok(response) if response.status().is_success() => {
            SessionCheck::Alive(response.json().await.unwrap_or(Value::Null))
        }
        Ok(response)
            if matches!(
                response.status(),
                reqwest::StatusCode::UNAUTHORIZED | reqwest::StatusCode::FORBIDDEN
            ) =>
        {
            SessionCheck::Dead
        }
        _ => SessionCheck::Unknown,
    }
}

fn apply_seerr_user(session: &mut SeerrSession, user: &Value) {
    if let Some(id) = user.get("id").and_then(Value::as_i64) {
        session.seerr_user_id = id;
    }
    if let Some(name) = user.get("displayName").and_then(Value::as_str) {
        session.display_name = Some(name.to_string());
    }
    if let Some(avatar) = user.get("avatar").and_then(Value::as_str) {
        session.avatar = Some(avatar.to_string());
    }
    if let Some(permissions) = user.get("permissions").and_then(Value::as_i64) {
        session.permissions = permissions;
    }
}

/// Seerr's optional CSRF protection: the token pair comes from cookies set on
/// any API response and must be echoed back as cookies plus a header.
#[derive(Default)]
struct CsrfTokens {
    cookies: Vec<(String, String)>,
    token: Option<String>,
}

impl CsrfTokens {
    fn apply(
        &self,
        mut builder: reqwest::RequestBuilder,
        session: Option<&SeerrSession>,
    ) -> reqwest::RequestBuilder {
        if let Some(token) = &self.token {
            builder = builder
                .header("X-XSRF-TOKEN", token)
                .header("X-CSRF-Token", token);
        }
        let cookie = cookie_header(&self.cookies, session);
        if !cookie.is_empty() {
            builder = builder.header(header::COOKIE, cookie);
        }
        builder
    }
}

async fn fetch_csrf(seerr_url: &str) -> CsrfTokens {
    // auth/me answers 403 without a session but still issues the CSRF cookies.
    let Ok(response) = SEERR_CLIENT
        .get(format!("{seerr_url}/api/v1/auth/me"))
        .send()
        .await
    else {
        return CsrfTokens::default();
    };
    let cookies: Vec<(String, String)> = set_cookies(response.headers())
        .into_iter()
        .filter(|(name, _)| CSRF_COOKIES.contains(&name.as_str()))
        .collect();
    let token = cookies
        .iter()
        .find(|(name, _)| name == "XSRF-TOKEN")
        .map(|(_, value)| decode_cookie_value(value));
    CsrfTokens { cookies, token }
}

fn cookie_header(cookies: &[(String, String)], session: Option<&SeerrSession>) -> String {
    cookies
        .iter()
        .map(|(name, value)| format!("{name}={value}"))
        .chain(session.map(|s| format!("{}={}", s.cookie_name, s.cookie_value)))
        .collect::<Vec<_>>()
        .join("; ")
}

fn decode_cookie_value(value: &str) -> String {
    percent_encoding::percent_decode_str(value)
        .decode_utf8_lossy()
        .into_owned()
}

/// `(name, value)` pairs from `Set-Cookie`, values kept verbatim.
fn set_cookies(headers: &reqwest::header::HeaderMap) -> Vec<(String, String)> {
    headers
        .get_all(reqwest::header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .filter_map(|value| {
            let pair = value.split(';').next()?.trim();
            let (name, value) = pair.split_once('=')?;
            let name = name.trim();
            (!name.is_empty()).then(|| (name.to_string(), value.trim().to_string()))
        })
        .collect()
}

/// Stock Seerr names its session cookie `connect.sid`; rebranded builds may
/// rename it, so fall back to the first cookie that is not a CSRF cookie.
fn session_cookie(headers: &reqwest::header::HeaderMap) -> Option<(String, String)> {
    let cookies: Vec<_> = set_cookies(headers)
        .into_iter()
        .filter(|(_, value)| !value.is_empty())
        .collect();
    cookies
        .iter()
        .find(|(name, _)| name == "connect.sid")
        .or_else(|| {
            cookies
                .iter()
                .find(|(name, _)| !CSRF_COOKIES.contains(&name.as_str()))
        })
        .cloned()
}

#[cfg(test)]
mod tests;
