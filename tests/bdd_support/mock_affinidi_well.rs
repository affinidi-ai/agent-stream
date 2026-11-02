use std::sync::Arc;

use axum::{Json, Router, http::StatusCode, response::IntoResponse, routing::get};
use serde_json::Value;
use tokio::sync::{Mutex, oneshot};

#[derive(Debug)]
struct State {
    metadata: Mutex<Value>,
    available: Mutex<bool>,
    request_count: Mutex<usize>,
}

#[derive(Debug)]
pub struct MockAffinidiWell {
    base_url: String,
    state: Arc<State>,
    shutdown: Option<oneshot::Sender<()>>,
}

impl MockAffinidiWell {
    pub async fn start(
        metadata: Value,
        available: bool,
    ) -> Self {
        let state = Arc::new(State {
            metadata: Mutex::new(metadata),
            available: Mutex::new(available),
            request_count: Mutex::new(0),
        });
        let app = Router::new()
            .route("/terms/v1/current.json", get(current_metadata))
            .with_state(state.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("mock Affinidi Well should bind");
        let address = listener
            .local_addr()
            .expect("mock Affinidi Well address should be readable");
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app)
                .with_graceful_shutdown(async {
                    let _ = shutdown_rx.await;
                })
                .await;
        });
        Self {
            base_url: format!("http://{address}"),
            state,
            shutdown: Some(shutdown_tx),
        }
    }

    pub fn metadata_url(&self) -> String {
        format!("{}/terms/v1/current.json", self.base_url)
    }

    pub async fn set_available(
        &self,
        available: bool,
    ) {
        *self
            .state
            .available
            .lock()
            .await = available;
    }

    pub async fn set_metadata(
        &self,
        metadata: Value,
    ) {
        *self
            .state
            .metadata
            .lock()
            .await = metadata;
    }

    pub async fn request_count(&self) -> usize {
        *self
            .state
            .request_count
            .lock()
            .await
    }
}

impl Drop for MockAffinidiWell {
    fn drop(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
    }
}

async fn current_metadata(axum::extract::State(state): axum::extract::State<Arc<State>>) -> impl IntoResponse {
    *state
        .request_count
        .lock()
        .await += 1;
    if !*state.available.lock().await {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    }
    Json(
        state
            .metadata
            .lock()
            .await
            .clone(),
    )
    .into_response()
}
