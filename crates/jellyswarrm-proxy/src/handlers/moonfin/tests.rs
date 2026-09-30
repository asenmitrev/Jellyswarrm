use std::sync::Arc;

use axum::Router;
use reqwest::StatusCode;
use serde_json::{json, Value};
use sqlx::sqlite::SqlitePoolOptions;
use wiremock::{
    matchers::{body_json, header, method, path, query_param},
    Mock, MockServer, ResponseTemplate,
};

use super::*;
use crate::{
    config::{AppConfig, MIGRATOR},
    handlers::quick_connect::QuickConnectStorage,
    media_storage_service::MediaStorageService,
    server_storage::ServerStorageService,
    session_storage::SessionStorage,
    user_authorization_service::UserAuthorizationService,
    virtual_library_service::VirtualLibraryService,
    DataContext, ProxyProcessors,
};

struct Fixture {
    state: AppState,
    user: User,
    seerr: MockServer,
    url: String,
    client: reqwest::Client,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Fixture {
    async fn new(seerr_enabled: bool) -> Self {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        MIGRATOR.run(&pool).await.unwrap();
        let seerr = MockServer::start().await;
        let servers = ServerStorageService::new(pool.clone());
        let media = MediaStorageService::new(pool.clone());
        let data = DataContext {
            user_authorization: Arc::new(UserAuthorizationService::new(pool.clone())),
            server_storage: Arc::new(servers.clone()),
            media_storage: Arc::new(media.clone()),
            virtual_library_service: Arc::new(VirtualLibraryService::new(pool, servers, media)),
            play_sessions: Arc::new(SessionStorage::new()),
            config: Arc::new(tokio::sync::RwLock::new(AppConfig {
                seerr_enabled,
                seerr_url: Some(format!("{}/", seerr.uri())),
                ..Default::default()
            })),
        };
        let state = AppState::new(
            reqwest::Client::new(),
            reqwest::Client::new(),
            data.clone(),
            ProxyProcessors::new(data),
            QuickConnectStorage::new(),
        );
        let user = state
            .user_authorization
            .create_user("alice", &"password".into())
            .await
            .unwrap();

        let routes = Router::new()
            .nest("/Moonfin", routes())
            .route("/{*path}", any(crate::proxy_handler));
        let app = Router::new()
            .nest("/proxy", routes)
            .with_state(state.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/proxy", listener.local_addr().unwrap());
        let task = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        Self {
            state,
            user,
            seerr,
            url,
            client: reqwest::Client::new(),
            task,
        }
    }

    fn request(&self, method: reqwest::Method, path: &str) -> reqwest::RequestBuilder {
        self.client
            .request(method, format!("{}{path}", self.url))
            .header("X-Emby-Token", &self.user.virtual_key)
    }

    async fn get_json(&self, path: &str) -> (StatusCode, Value) {
        let response = self
            .request(reqwest::Method::GET, path)
            .send()
            .await
            .unwrap();
        let status = response.status();
        (status, response.json().await.unwrap_or(Value::Null))
    }

    async fn store_session(&self, cookie: &str, validated_ago: chrono::TimeDelta) {
        let now = chrono::Utc::now();
        self.state
            .user_authorization
            .seerr_sessions()
            .save(&SeerrSession {
                user_id: self.user.id.clone(),
                cookie_name: "connect.sid".into(),
                cookie_value: cookie.into(),
                seerr_user_id: 3,
                display_name: Some("Alice".into()),
                avatar: None,
                permissions: 2,
                created_at: now,
                last_validated: now - validated_ago,
            })
            .await
            .unwrap();
    }

    async fn stored_session(&self) -> Option<SeerrSession> {
        self.state
            .user_authorization
            .seerr_sessions()
            .get(&self.user.id)
            .await
            .unwrap()
    }
}

#[tokio::test]
async fn ping_and_config_report_seerr_when_enabled() {
    let f = Fixture::new(true).await;

    // The exact header shape Moonfin's plugin probe sends.
    let response = f
        .client
        .get(format!("{}/Moonfin/Ping", f.url))
        .header(
            "Authorization",
            format!(
                "MediaBrowser Client=\"Moonfin\", Device=\"Pixel\", DeviceId=\"abc\", Version=\"1.0.0\", Token=\"{}\"",
                f.user.virtual_key
            ),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let ping: Value = response.json().await.unwrap();
    assert_eq!(ping["installed"], true);
    assert_eq!(ping["seerrEnabled"], true);
    assert_eq!(ping["seerrUrl"], f.seerr.uri());
    // Moonfin treats an explicit `false` here as "plugin unavailable".
    assert!(ping.get("settingsSyncEnabled").is_none());

    for path in ["/Moonfin/Seerr/Config", "/Moonfin/Jellyseerr/Config"] {
        let (status, config) = f.get_json(path).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            config,
            json!({
                "enabled": true,
                "url": f.seerr.uri(),
                "displayName": "Seerr",
                "variant": "seerr",
                "userEnabled": true,
            })
        );
    }
}

#[tokio::test]
async fn disabled_seerr_is_reported_and_login_is_unavailable() {
    let f = Fixture::new(false).await;

    let (_, ping) = f.get_json("/Moonfin/Ping").await;
    assert_eq!(ping["seerrEnabled"], false);
    assert_eq!(ping["seerrUrl"], Value::Null);

    let (_, status) = f.get_json("/Moonfin/Seerr/Status").await;
    assert_eq!(status["enabled"], false);

    let response = f
        .request(reqwest::Method::POST, "/Moonfin/Seerr/Login")
        .json(&json!({ "username": "alice", "password": "pw" }))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn moonfin_requires_an_authenticated_user() {
    let f = Fixture::new(true).await;
    let response = f
        .client
        .get(format!("{}/Moonfin/Ping", f.url))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn unsupported_moonfin_endpoints_are_not_forwarded() {
    let f = Fixture::new(true).await;
    for path in ["/Moonfin/Settings", "/Moonfin/Seerr/Unknown"] {
        let (status, _) = f.get_json(path).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{path}");
    }
}

#[tokio::test]
async fn login_stores_session_with_csrf_and_returns_seerr_user() {
    let f = Fixture::new(true).await;
    Mock::given(method("GET"))
        .and(path("/api/v1/auth/me"))
        .respond_with(
            ResponseTemplate::new(403)
                .append_header("Set-Cookie", "_csrf=secret; Path=/; HttpOnly")
                .append_header("Set-Cookie", "XSRF-TOKEN=tok%2Ben; Path=/"),
        )
        .mount(&f.seerr)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/v1/auth/jellyfin"))
        .and(header("X-XSRF-TOKEN", "tok+en"))
        .and(header("Cookie", "_csrf=secret; XSRF-TOKEN=tok%2Ben"))
        .and(body_json(json!({ "username": "alice", "password": "pw" })))
        .respond_with(
            ResponseTemplate::new(200)
                .append_header("Set-Cookie", "connect.sid=s%3Aabc; Path=/; HttpOnly")
                .set_body_json(json!({
                    "id": 5,
                    "displayName": "Alice A",
                    "avatar": "/avatar.png",
                    "permissions": 32,
                })),
        )
        .expect(1)
        .mount(&f.seerr)
        .await;

    let response = f
        .request(reqwest::Method::POST, "/Moonfin/Seerr/Login")
        .json(&json!({ "Username": "alice", "Password": "pw" }))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = response.json().await.unwrap();
    assert_eq!(
        body,
        json!({
            "success": true,
            "seerrUserId": 5,
            "jellyseerrUserId": 5,
            "displayName": "Alice A",
            "avatar": "/avatar.png",
            "permissions": 32,
        })
    );

    let session = f.stored_session().await.unwrap();
    assert_eq!(session.cookie_name, "connect.sid");
    assert_eq!(session.cookie_value, "s%3Aabc");
}

#[tokio::test]
async fn failed_login_does_not_store_a_session() {
    let f = Fixture::new(true).await;
    Mock::given(method("POST"))
        .and(path("/api/v1/auth/jellyfin"))
        .respond_with(ResponseTemplate::new(401))
        .mount(&f.seerr)
        .await;

    let response = f
        .request(reqwest::Method::POST, "/Moonfin/Seerr/Login")
        .json(&json!({ "username": "alice", "password": "wrong" }))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let body: Value = response.json().await.unwrap();
    assert_eq!(body["success"], false);
    assert!(f.stored_session().await.is_none());
}

#[tokio::test]
async fn api_proxy_forwards_path_query_and_cookie() {
    let f = Fixture::new(true).await;
    f.store_session("s%3Aabc", chrono::TimeDelta::zero()).await;
    Mock::given(method("GET"))
        .and(path("/api/v1/search"))
        .and(query_param("query", "the matrix"))
        .and(query_param("page", "1"))
        .and(header("Cookie", "connect.sid=s%3Aabc"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "results": [] })))
        .expect(1)
        .mount(&f.seerr)
        .await;

    let (status, body) = f
        .get_json("/Moonfin/Seerr/Api/search?query=the%20matrix&page=1")
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, json!({ "results": [] }));
}

#[tokio::test]
async fn api_proxy_forwards_post_body() {
    let f = Fixture::new(true).await;
    f.store_session("s%3Aabc", chrono::TimeDelta::zero()).await;
    Mock::given(method("POST"))
        .and(path("/api/v1/request"))
        .and(body_json(json!({ "mediaType": "movie", "mediaId": 603 })))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({ "id": 1 })))
        .expect(1)
        .mount(&f.seerr)
        .await;

    let response = f
        .request(reqwest::Method::POST, "/Moonfin/Seerr/Api/request")
        .json(&json!({ "mediaType": "movie", "mediaId": 603 }))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
}

#[tokio::test]
async fn api_proxy_without_session_is_unauthorized() {
    let f = Fixture::new(true).await;
    let (status, body) = f.get_json("/Moonfin/Seerr/Api/auth/me").await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["code"], "NO_SESSION");
}

#[tokio::test]
async fn permission_denial_keeps_a_live_session() {
    let f = Fixture::new(true).await;
    f.store_session("s%3Aabc", chrono::TimeDelta::zero()).await;
    Mock::given(method("DELETE"))
        .and(path("/api/v1/request/9"))
        .respond_with(ResponseTemplate::new(403))
        .mount(&f.seerr)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/v1/auth/me"))
        .and(header("Cookie", "connect.sid=s%3Aabc"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "id": 3 })))
        .mount(&f.seerr)
        .await;

    let response = f
        .request(reqwest::Method::DELETE, "/Moonfin/Seerr/Api/request/9")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert!(f.stored_session().await.is_some());
}

#[tokio::test]
async fn stale_dead_session_is_reported_and_cleared() {
    let f = Fixture::new(true).await;
    f.store_session("s%3Aold", chrono::TimeDelta::minutes(10))
        .await;
    Mock::given(method("GET"))
        .and(path("/api/v1/auth/me"))
        .respond_with(ResponseTemplate::new(403))
        .mount(&f.seerr)
        .await;

    let (_, status) = f.get_json("/Moonfin/Seerr/Status").await;
    assert_eq!(status["enabled"], true);
    assert_eq!(status["authenticated"], false);
    assert!(f.stored_session().await.is_none());
}

#[tokio::test]
async fn fresh_session_status_skips_seerr() {
    let f = Fixture::new(true).await;
    f.store_session("s%3Aabc", chrono::TimeDelta::zero()).await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(&f.seerr)
        .await;

    let (_, status) = f.get_json("/Moonfin/Seerr/Status").await;
    assert_eq!(status["authenticated"], true);
    assert_eq!(status["seerrUserId"], 3);
    assert_eq!(status["displayName"], "Alice");
}

#[tokio::test]
async fn logout_clears_session() {
    let f = Fixture::new(true).await;
    f.store_session("s%3Aabc", chrono::TimeDelta::zero()).await;
    Mock::given(method("POST"))
        .and(path("/api/v1/auth/logout"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&f.seerr)
        .await;

    let response = f
        .request(reqwest::Method::DELETE, "/Moonfin/Seerr/Logout")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert!(f.stored_session().await.is_none());
}

#[tokio::test]
async fn read_only_api_keys_cannot_mutate_seerr() {
    let f = Fixture::new(true).await;
    let key = f
        .state
        .user_authorization
        .create_api_key(&f.user.id, "Moonfin")
        .await
        .unwrap();
    let response = f
        .client
        .post(format!("{}/Moonfin/Seerr/Api/request", f.url))
        .header("X-Emby-Token", key.access_token)
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[test]
fn session_cookie_prefers_connect_sid_and_skips_csrf() {
    let mut headers = reqwest::header::HeaderMap::new();
    for value in [
        "XSRF-TOKEN=a; Path=/",
        "custom.sid=b; Path=/",
        "connect.sid=c; Path=/; HttpOnly",
    ] {
        headers.append(reqwest::header::SET_COOKIE, value.parse().unwrap());
    }
    assert_eq!(
        session_cookie(&headers),
        Some(("connect.sid".into(), "c".into()))
    );

    headers.remove(reqwest::header::SET_COOKIE);
    headers.append(reqwest::header::SET_COOKIE, "_csrf=x".parse().unwrap());
    headers.append(reqwest::header::SET_COOKIE, "sb.sid=y".parse().unwrap());
    assert_eq!(
        session_cookie(&headers),
        Some(("sb.sid".into(), "y".into()))
    );
}

#[test]
fn api_path_keeps_encoding_after_api_segment() {
    assert_eq!(api_path("/Api/search%20x"), Some("search%20x"));
    assert_eq!(api_path("/api/request/9"), Some("request/9"));
    assert_eq!(api_path("/Api/"), None);
}
