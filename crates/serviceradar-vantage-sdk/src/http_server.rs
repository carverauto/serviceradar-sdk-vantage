// SPDX-License-Identifier: Apache-2.0

//! Axum HTTP health (`/healthz`), readiness (`/readyz`), and Prometheus `/metrics` server.

use crate::error::VantageError;
use crate::metrics::WorkerMetrics;
use crate::protocol::WorkerCapabilities;
use axum::extract::State;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use parking_lot::RwLock;
use serde::Serialize;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;

#[derive(Debug, Clone)]
enum ReadinessPhase {
    Ready(Box<WorkerCapabilities>),
    NotReady(String),
    Draining(String),
}

#[derive(Debug, Clone)]
pub struct ReadinessState {
    worker_id: String,
    phase: Arc<RwLock<ReadinessPhase>>,
    metrics: Arc<WorkerMetrics>,
}

impl ReadinessState {
    pub fn not_ready(
        worker_id: impl Into<String>,
        reason: impl Into<String>,
        metrics: Arc<WorkerMetrics>,
    ) -> Self {
        Self {
            worker_id: worker_id.into(),
            phase: Arc::new(RwLock::new(ReadinessPhase::NotReady(reason.into()))),
            metrics,
        }
    }

    pub fn ready(
        worker_id: impl Into<String>,
        capabilities: WorkerCapabilities,
        metrics: Arc<WorkerMetrics>,
    ) -> Self {
        Self {
            worker_id: worker_id.into(),
            phase: Arc::new(RwLock::new(ReadinessPhase::Ready(Box::new(capabilities)))),
            metrics,
        }
    }

    pub fn mark_ready(&self, capabilities: WorkerCapabilities) {
        *self.phase.write() = ReadinessPhase::Ready(Box::new(capabilities));
    }

    pub fn mark_draining(&self, reason: impl Into<String>) {
        *self.phase.write() = ReadinessPhase::Draining(reason.into());
    }

    pub fn mark_not_ready(&self, reason: impl Into<String>) {
        *self.phase.write() = ReadinessPhase::NotReady(reason.into());
    }

    pub fn is_ready(&self) -> bool {
        matches!(&*self.phase.read(), ReadinessPhase::Ready(_))
    }
}

#[derive(Serialize)]
struct HealthzResponse<'a> {
    status: &'a str,
    service: &'a str,
    worker_id: &'a str,
}

#[derive(Serialize)]
struct ReadyzManifest<'a> {
    status: &'a str,
    worker_id: &'a str,
    #[serde(flatten)]
    capabilities: &'a WorkerCapabilities,
}

#[derive(Serialize)]
struct UnavailableReadyzResponse<'a> {
    status: &'a str,
    worker_id: &'a str,
    reason: &'a str,
}

pub fn build_http_router(state: ReadinessState) -> Router {
    Router::new()
        .route("/healthz", get(handle_healthz))
        .route("/readyz", get(handle_readyz))
        .route("/metrics", get(handle_metrics))
        .with_state(state)
}

pub async fn serve_http_probes(
    listen_addr: SocketAddr,
    state: ReadinessState,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) -> Result<SocketAddr, VantageError> {
    let listener = TcpListener::bind(listen_addr).await.map_err(|err| {
        VantageError::transport(format!(
            "failed binding HTTP probe listener on {listen_addr}: {err}"
        ))
    })?;
    let bound = listener.local_addr().map_err(|err| {
        VantageError::transport(format!("failed reading local listener address: {err}"))
    })?;
    let router = build_http_router(state);

    tokio::spawn(async move {
        let _ = axum::serve(listener, router)
            .with_graceful_shutdown(async move {
                while !*shutdown.borrow_and_update() {
                    if shutdown.changed().await.is_err() {
                        break;
                    }
                }
            })
            .await;
    });

    Ok(bound)
}

async fn handle_healthz(State(state): State<ReadinessState>) -> Response {
    (
        StatusCode::OK,
        Json(HealthzResponse {
            status: "ok",
            service: "serviceradar-vantage-worker",
            worker_id: &state.worker_id,
        }),
    )
        .into_response()
}

async fn handle_readyz(State(state): State<ReadinessState>) -> Response {
    let snapshot = state.phase.read().clone();
    match snapshot {
        ReadinessPhase::Ready(caps) => (
            StatusCode::OK,
            Json(ReadyzManifest {
                status: "ready",
                worker_id: &state.worker_id,
                capabilities: &caps,
            }),
        )
            .into_response(),
        ReadinessPhase::NotReady(reason) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(UnavailableReadyzResponse {
                status: "not_ready",
                worker_id: &state.worker_id,
                reason: &reason,
            }),
        )
            .into_response(),
        ReadinessPhase::Draining(reason) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(UnavailableReadyzResponse {
                status: "draining",
                worker_id: &state.worker_id,
                reason: &reason,
            }),
        )
            .into_response(),
    }
}

async fn handle_metrics(State(state): State<ReadinessState>) -> Response {
    match state.metrics.render_prometheus_text() {
        Ok(body) => {
            let mut resp = (StatusCode::OK, body).into_response();
            resp.headers_mut().insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static("text/plain; version=0.0.4; charset=utf-8"),
            );
            resp
        }
        Err(err) => (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response(),
    }
}
