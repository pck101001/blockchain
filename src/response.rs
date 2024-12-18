use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;
use thiserror::Error;
#[derive(Serialize, Debug)]
pub struct MyResponse {
    pub status: bool,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}

#[derive(Error, Debug)]
pub enum MyError {
    #[error("An error occurred:{0}")]
    GenericError(String),
    #[error("Invalid Submission:{0}")]
    InvalidSubmission(String),
    #[error("Invalid Transaction:{0}")]
    InvalidTransaction(String),
}
impl IntoResponse for MyError {
    fn into_response(self) -> Response {
        let (status, error_message) = match self {
            MyError::GenericError(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg),
            MyError::InvalidSubmission(msg) => (StatusCode::BAD_REQUEST, msg),
            MyError::InvalidTransaction(msg) => (StatusCode::BAD_REQUEST, msg),
        };
        let body = Json(MyResponse {
            status: false,
            message: error_message,
            data: None,
        });
        (status, body).into_response()
    }
}
