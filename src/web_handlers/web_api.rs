use std::collections::HashMap;

use actix_web::{web, HttpRequest, HttpResponse};
use log::error;

use crate::api::{sub_process, SubResponse, SubconverterQuery};
use crate::web_handlers::getprofile::get_profile_handler;
impl SubResponse {
    /// Convert SubResponse to HttpResponse
    pub fn to_http_response(self) -> HttpResponse {
        // Create response with appropriate status code
        let mut http_response = match self.status_code {
            200 => HttpResponse::Ok(),
            400 => HttpResponse::BadRequest(),
            500 => HttpResponse::InternalServerError(),
            _ => HttpResponse::build(
                actix_web::http::StatusCode::from_u16(self.status_code)
                    .unwrap_or(actix_web::http::StatusCode::INTERNAL_SERVER_ERROR),
            ),
        };

        // Add headers
        for (name, value) in self.headers {
            http_response.append_header((name, value));
        }

        // Set content type
        http_response.content_type(self.content_type);

        // Return response with content
        http_response.body(self.content)
    }
}

pub async fn sub_handler(req: HttpRequest, query: web::Query<SubconverterQuery>) -> HttpResponse {
    let req_url = req.uri().to_string();

    let mut request_headers = HashMap::new();
    for (key, value) in req.headers() {
        request_headers.insert(key.to_string(), value.to_str().unwrap_or("").to_string());
    }

    let mut modified_query = query.into_inner();
    modified_query.request_headers = Some(request_headers);

    match sub_process(Some(req_url), modified_query).await {
        Ok(response) => response.to_http_response(),
        Err(e) => {
            error!("Subconverter process error: {}", e);
            HttpResponse::InternalServerError().body(format!("Internal server error: {}", e))
        }
    }
}

/// Handler for simple conversion (no rules)
pub async fn simple_handler(
    req: HttpRequest,
    path: web::Path<(String,)>,
    query: web::Query<SubconverterQuery>,
) -> HttpResponse {
    let target_type = &path.0;
    let req_url = req.uri().to_string();

    // Set appropriate target based on path
    match target_type.as_str() {
        "clash" | "clashr" | "surge" | "quan" | "quanx" | "loon" | "ss" | "ssr" | "ssd"
        | "v2ray" | "trojan" | "mixed" | "singbox" => {
            // Create a modified query with the target set
            let mut modified_query = query.into_inner();
            modified_query.target = Some(target_type.clone());

            // Reuse the sub_handler logic
            match sub_process(Some(req_url), modified_query).await {
                Ok(response) => response.to_http_response(),
                Err(e) => {
                    error!("Subconverter process error: {}", e);
                    HttpResponse::InternalServerError()
                        .body(format!("Internal server error: {}", e))
                }
            }
        }
        _ => HttpResponse::BadRequest().body(format!("Unsupported target type: {}", target_type)),
    }
}

/// Handler for Clash from Surge configuration
pub async fn surge_to_clash_handler(
    req: HttpRequest,
    query: web::Query<SubconverterQuery>,
) -> HttpResponse {
    let req_url = req.uri().to_string();

    // Create a modified query with the target set to Clash
    let mut modified_query = query.into_inner();
    modified_query.target = Some("clash".to_string());

    // Set nodelist to true for this special case
    modified_query.list = Some(true);

    // Reuse the sub_process logic
    match sub_process(Some(req_url), modified_query).await {
        Ok(response) => response.to_http_response(),
        Err(e) => {
            error!("Subconverter process error: {}", e);
            HttpResponse::InternalServerError().body(format!("Internal server error: {}", e))
        }
    }
}

/// Register the API endpoints with Actix Web
pub fn config(cfg: &mut web::ServiceConfig) {
    cfg.route("/sub", web::get().to(sub_handler))
        .route("/getprofile", web::get().to(get_profile_handler))
        .route("/surge2clash", web::get().to(surge_to_clash_handler))
        .route("/{target_type}", web::get().to(simple_handler));
}
