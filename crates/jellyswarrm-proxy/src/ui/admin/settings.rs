use askama::Template;
use axum::{
    extract::State,
    http::StatusCode,
    response::{Html, IntoResponse, Response},
    Form,
};
use serde::Deserialize;
use tracing::error;

use crate::{config::save_config, AppState};

#[derive(Template)]
#[template(path = "admin/settings.html")]
pub struct SettingsPageTemplate {
    pub ui_route: String,
}

#[derive(Template)]
#[template(path = "admin/settings_form.html")]
pub struct SettingsFormTemplate {
    pub server_id: String,
    pub public_address: String,
    pub server_name: String,
    pub include_server_name_in_media: bool,
    pub auto_create_users_on_login: bool,
    pub deduplicate_media: bool,
    pub seerr_enabled: bool,
    pub seerr_url: String,
    pub seerr_display_name: String,
    pub ui_route: String,
}

pub async fn settings_page(State(state): State<AppState>) -> impl IntoResponse {
    let template = SettingsPageTemplate {
        ui_route: state.get_ui_route().await,
    };
    match template.render() {
        Ok(html) => Html(html).into_response(),
        Err(e) => {
            error!("Failed to render settings page: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "Template error").into_response()
        }
    }
}

pub async fn settings_form(State(state): State<AppState>) -> impl IntoResponse {
    let cfg = state.config.read().await.clone();
    let form = SettingsFormTemplate {
        server_id: cfg.server_id,
        public_address: cfg.public_address,
        server_name: cfg.server_name,
        include_server_name_in_media: cfg.include_server_name_in_media,
        auto_create_users_on_login: cfg.auto_create_users_on_login,
        deduplicate_media: cfg.deduplicate_media,
        seerr_enabled: cfg.seerr_enabled,
        seerr_url: cfg.seerr_url.unwrap_or_default(),
        seerr_display_name: cfg.seerr_display_name.unwrap_or_default(),
        ui_route: state.get_ui_route().await,
    };
    match form.render() {
        Ok(html) => Html(html).into_response(),
        Err(e) => {
            error!("Failed to render settings form: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "Template error").into_response()
        }
    }
}

#[derive(Deserialize)]
pub struct SaveForm {
    pub public_address: String,
    pub server_name: String,
    // When the checkbox is unchecked the field is absent; default to false.
    #[serde(default)]
    pub include_server_name_in_media: bool,
    #[serde(default)]
    pub auto_create_users_on_login: bool,
    #[serde(default)]
    pub deduplicate_media: bool,
    #[serde(default)]
    pub seerr_enabled: bool,
    #[serde(default)]
    pub seerr_url: String,
    #[serde(default)]
    pub seerr_display_name: String,
}

fn settings_error(message: &str) -> Response {
    Html(format!(
        "<div id=\"settings-messages\" class=\"alert alert-error\">{message}</div>"
    ))
    .into_response()
}

/// Normalize the Seerr base URL; an empty value clears it.
fn parse_seerr_url(input: &str) -> Result<Option<String>, &'static str> {
    let trimmed = input.trim().trim_end_matches('/');
    if trimmed.is_empty() {
        return Ok(None);
    }
    match url::Url::parse(trimmed) {
        Ok(url) if matches!(url.scheme(), "http" | "https") && url.host().is_some() => {
            Ok(Some(trimmed.to_string()))
        }
        _ => Err("Seerr URL must be an http(s) URL"),
    }
}

pub async fn save_settings(State(state): State<AppState>, Form(form): Form<SaveForm>) -> Response {
    if form.public_address.trim().is_empty() || form.server_name.trim().is_empty() {
        return Html(
            "<div id=\"settings-messages\" class=\"alert alert-error\">All fields required</div>",
        )
        .into_response();
    }
    let seerr_url = match parse_seerr_url(&form.seerr_url) {
        Ok(url) => url,
        Err(message) => return settings_error(message),
    };
    if form.seerr_enabled && seerr_url.is_none() {
        return settings_error("Seerr URL is required to enable Seerr");
    }
    let seerr_display_name =
        Some(form.seerr_display_name.trim().to_string()).filter(|name| !name.is_empty());

    let save_result = {
        let mut cfg = state.config.write().await;
        let mut updated = cfg.clone();
        updated.public_address = form.public_address.trim().to_string();
        updated.server_name = form.server_name.trim().to_string();
        updated.include_server_name_in_media = form.include_server_name_in_media;
        updated.auto_create_users_on_login = form.auto_create_users_on_login;
        updated.deduplicate_media = form.deduplicate_media;
        updated.seerr_enabled = form.seerr_enabled;
        updated.seerr_url = seerr_url;
        updated.seerr_display_name = seerr_display_name;
        match save_config(&updated) {
            Ok(()) => {
                *cfg = updated;
                Ok(())
            }
            Err(error) => Err(error),
        }
    };
    if let Err(error) = save_result {
        error!("Failed to save settings: {error}");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Html("<div id=\"settings-messages\" class=\"alert alert-error\">Could not save settings. The previous configuration is still active.</div>"),
        )
            .into_response();
    }

    settings_form(State(state)).await.into_response()
}

pub async fn reload_config(State(state): State<AppState>) -> impl IntoResponse {
    let current_key = state.config.read().await.session_key.clone();
    let new_cfg = match crate::config::load_config_with_session_key(Some(&current_key)) {
        Ok(cfg) => cfg,
        Err(error) => {
            error!("Failed to reload config: {error}");
            return (
                StatusCode::BAD_REQUEST,
                Html("<div class=\"alert alert-error\">Invalid configuration</div>"),
            )
                .into_response();
        }
    };
    {
        let mut cfg = state.config.write().await;
        if cfg.session_key != new_cfg.session_key {
            return (StatusCode::CONFLICT, Html("<div class=\"alert alert-error\">session_key cannot be changed while running</div>")).into_response();
        }
        *cfg = new_cfg;
    }
    Html("<div class=\"alert\">Configuration reloaded</div>").into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn settings_form_does_not_render_library_merging_control() {
        let html = SettingsFormTemplate {
            server_id: "server".to_string(),
            public_address: "http://localhost:8096".to_string(),
            server_name: "Jellyswarrm".to_string(),
            include_server_name_in_media: false,
            auto_create_users_on_login: true,
            deduplicate_media: true,
            seerr_enabled: false,
            seerr_url: String::new(),
            seerr_display_name: String::new(),
            ui_route: "admin".to_string(),
        }
        .render()
        .unwrap();

        assert!(!html.contains("name=\"merge_libraries\""));
    }

    #[test]
    fn settings_form_renders_media_deduplication_control() {
        let html = SettingsFormTemplate {
            server_id: "server".to_string(),
            public_address: "http://localhost:8096".to_string(),
            server_name: "Jellyswarrm".to_string(),
            include_server_name_in_media: false,
            auto_create_users_on_login: true,
            deduplicate_media: true,
            seerr_enabled: false,
            seerr_url: String::new(),
            seerr_display_name: String::new(),
            ui_route: "admin".to_string(),
        }
        .render()
        .unwrap();

        assert!(html.contains("name=\"deduplicate_media\""));
        assert!(html.contains("name=\"deduplicate_media\" value=\"true\" checked"));
    }

    #[test]
    fn seerr_url_is_normalized_and_validated() {
        assert_eq!(parse_seerr_url("  "), Ok(None));
        assert_eq!(
            parse_seerr_url("http://seerr:5055/"),
            Ok(Some("http://seerr:5055".to_string()))
        );
        assert!(parse_seerr_url("seerr:5055").is_err());
        assert!(parse_seerr_url("ftp://seerr").is_err());
    }
}
