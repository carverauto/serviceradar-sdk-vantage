// SPDX-License-Identifier: Apache-2.0

//! External worker runtime configuration (`WorkerConfig`).
//!
//! External workers NEVER read database (`DATABASE_URL`, CNPG, StarRocks) or static
//! object-storage (`AWS_SECRET_ACCESS_KEY`) credentials.

use crate::error::VantageError;
use crate::grants::WorkerAuthCredentials;
use crate::protocol::{SourceMode, VANTAGE_RESULTS_SUBJECT, WorkerCapabilities, WorkerKind};
use std::net::SocketAddr;
use std::path::PathBuf;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct WorkerConfig {
    pub worker_id: String,
    pub worker_kind: WorkerKind,
    pub capabilities: Vec<String>,
    pub supported_source_modes: Vec<SourceMode>,
    pub execution_backend: String,
    pub architecture: String,
    pub model_id: String,
    pub model_version: String,
    pub max_concurrency: u32,
    pub nats_url: Option<String>,
    pub nats_creds_file: Option<PathBuf>,
    pub nats_tls_ca_file: Option<PathBuf>,
    pub nats_tls_cert_file: Option<PathBuf>,
    pub nats_tls_key_file: Option<PathBuf>,
    pub jobs_stream_name: String,
    pub results_stream_name: String,
    pub live_subject_override: Option<String>,
    pub result_subject: String,
    pub control_plane_url: Option<String>,
    pub control_plane_auth: Option<WorkerAuthCredentials>,
    pub http_listen_addr: Option<SocketAddr>,
    pub heartbeat_interval_ms: u64,
    pub nvr_scheme: String,
    pub nvr_port: u16,
    pub nvr_host_suffix: Option<String>,
    pub nvr_tls_ca_file: Option<PathBuf>,
    pub nvr_tls_cert_file: Option<PathBuf>,
    pub nvr_tls_key_file: Option<PathBuf>,
    pub nvr_auth_token_file: Option<PathBuf>,
    pub nvr_explicit_base_url: Option<String>,
}

impl Default for WorkerConfig {
    fn default() -> Self {
        Self {
            worker_id: format!("vantage-worker-{}", Uuid::new_v4().simple()),
            worker_kind: WorkerKind::ExternalRust,
            capabilities: vec!["vantage.alpr.v1".to_string()],
            supported_source_modes: vec![SourceMode::RecordedBlock, SourceMode::LiveKeyframeTap],
            execution_backend: "custom".to_string(),
            architecture: detect_architecture().to_string(),
            model_id: "vantage-worker-default".to_string(),
            model_version: "1.0.0".to_string(),
            max_concurrency: 4,
            nats_url: None,
            nats_creds_file: None,
            nats_tls_ca_file: None,
            nats_tls_cert_file: None,
            nats_tls_key_file: None,
            jobs_stream_name: "CAMERA_MEDIA_JOBS".to_string(),
            results_stream_name: "CAMERA_MEDIA_RESULTS".to_string(),
            live_subject_override: None,
            result_subject: VANTAGE_RESULTS_SUBJECT.to_string(),
            control_plane_url: None,
            control_plane_auth: None,
            http_listen_addr: None,
            heartbeat_interval_ms: 10_000,
            nvr_scheme: "https".to_string(),
            nvr_port: 8444,
            nvr_host_suffix: None,
            nvr_tls_ca_file: None,
            nvr_tls_cert_file: None,
            nvr_tls_key_file: None,
            nvr_auth_token_file: None,
            nvr_explicit_base_url: None,
        }
    }
}

impl WorkerConfig {
    pub fn from_env() -> Result<Self, VantageError> {
        let mut cfg = Self::default();
        cfg.apply_env_overrides()?;
        Ok(cfg)
    }

    pub fn apply_env_overrides(&mut self) -> Result<(), VantageError> {
        self.apply_overrides_with(non_empty_env)
    }

    pub fn apply_overrides_with<F>(&mut self, get_var: F) -> Result<(), VantageError>
    where
        F: Fn(&str) -> Option<String>,
    {
        let get = |name: &str| {
            get_var(name)
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
        };

        if let Some(id) = get("VANTAGE_WORKER_ID") {
            self.worker_id = id;
        }
        if let Some(caps_raw) = get("VANTAGE_CAPABILITIES").or_else(|| get("VANTAGE_CAPABILITY")) {
            let caps: Vec<String> = caps_raw
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(ToString::to_string)
                .collect();
            if caps.is_empty() {
                return Err(VantageError::invalid_configuration(
                    "VANTAGE_CAPABILITIES must not be empty",
                ));
            }
            self.capabilities = caps;
        }
        if let Some(modes_raw) = get("VANTAGE_SUPPORTED_SOURCE_MODES") {
            let mut modes = Vec::new();
            for item in modes_raw
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
            {
                modes.push(SourceMode::parse(item)?);
            }
            if modes.is_empty() {
                return Err(VantageError::invalid_configuration(
                    "VANTAGE_SUPPORTED_SOURCE_MODES must not be empty",
                ));
            }
            self.supported_source_modes = modes;
        }
        if let Some(backend) = get("VANTAGE_EXECUTION_BACKEND") {
            self.execution_backend = backend;
        }
        if let Some(model_id) = get("VANTAGE_MODEL_ID") {
            self.model_id = model_id;
        }
        if let Some(model_ver) = get("VANTAGE_MODEL_VERSION") {
            self.model_version = model_ver;
        }
        if let Some(conc) = get("VANTAGE_MAX_CONCURRENCY") {
            self.max_concurrency = conc.parse::<u32>().map_err(|err| {
                VantageError::invalid_configuration(format!(
                    "invalid VANTAGE_MAX_CONCURRENCY '{conc}': {err}"
                ))
            })?;
        }

        if let Some(url) = get("VANTAGE_NATS_URL")
            .or_else(|| get("SERVICERADAR_E2E_NATS_URL"))
            .or_else(|| get("NATS_URL"))
        {
            self.nats_url = Some(url);
        }
        if let Some(p) = get("VANTAGE_NATS_CREDS_FILE").map(PathBuf::from) {
            self.nats_creds_file = Some(p);
        }
        if let Some(p) = get("VANTAGE_NATS_TLS_CA_FILE").map(PathBuf::from) {
            self.nats_tls_ca_file = Some(p);
        }
        if let Some(p) = get("VANTAGE_NATS_TLS_CERT_FILE").map(PathBuf::from) {
            self.nats_tls_cert_file = Some(p);
        }
        if let Some(p) = get("VANTAGE_NATS_TLS_KEY_FILE").map(PathBuf::from) {
            self.nats_tls_key_file = Some(p);
        }

        if let Some(s) = get("VANTAGE_JOBS_STREAM") {
            self.jobs_stream_name = s;
        }
        if let Some(s) = get("VANTAGE_RESULTS_STREAM") {
            self.results_stream_name = s;
        }
        if let Some(s) = get("VANTAGE_LIVE_SUBJECT") {
            self.live_subject_override = Some(s);
        }
        if let Some(s) = get("VANTAGE_RESULT_SUBJECT") {
            self.result_subject = s;
        }

        if let Some(url) =
            get("VANTAGE_CONTROL_PLANE_URL").or_else(|| get("SERVICERADAR_E2E_WEB_URL"))
        {
            self.control_plane_url = Some(url);
        }

        if let Some(token) = get("VANTAGE_CONTROL_PLANE_AUTH") {
            let deploy_ref = get("VANTAGE_DEPLOYMENT_REF")
                .unwrap_or_else(|| "00000000-0000-4000-8000-000000000000".to_string());
            let generation = get("VANTAGE_WORKER_GENERATION").unwrap_or_else(|| "1".to_string());
            self.control_plane_auth =
                Some(WorkerAuthCredentials::new(token, deploy_ref, generation));
        } else if let Some(existing) = self.control_plane_auth.take() {
            let deploy_ref = get("VANTAGE_DEPLOYMENT_REF")
                .unwrap_or_else(|| existing.deployment_ref().to_string());
            let generation = get("VANTAGE_WORKER_GENERATION")
                .unwrap_or_else(|| existing.generation().to_string());
            self.control_plane_auth = Some(WorkerAuthCredentials::new(
                existing.token().to_string(),
                deploy_ref,
                generation,
            ));
        }

        if let Some(addr_raw) = get("VANTAGE_HTTP_LISTEN_ADDR") {
            let addr: SocketAddr = addr_raw.parse().map_err(|err| {
                VantageError::invalid_configuration(format!(
                    "invalid VANTAGE_HTTP_LISTEN_ADDR '{addr_raw}': {err}"
                ))
            })?;
            self.http_listen_addr = Some(addr);
        }

        if let Some(scheme) = get("VANTAGE_NVR_SCHEME") {
            self.nvr_scheme = scheme;
        }
        if let Some(port) = get("VANTAGE_NVR_PORT") {
            self.nvr_port = port.parse::<u16>().map_err(|err| {
                VantageError::invalid_configuration(format!(
                    "invalid VANTAGE_NVR_PORT '{port}': {err}"
                ))
            })?;
        }
        if let Some(s) = get("VANTAGE_NVR_HOST_SUFFIX") {
            self.nvr_host_suffix = Some(s);
        }
        if let Some(p) = get("VANTAGE_NVR_TLS_CA_FILE").map(PathBuf::from) {
            self.nvr_tls_ca_file = Some(p);
        }
        if let Some(p) = get("VANTAGE_NVR_TLS_CERT_FILE").map(PathBuf::from) {
            self.nvr_tls_cert_file = Some(p);
        }
        if let Some(p) = get("VANTAGE_NVR_TLS_KEY_FILE").map(PathBuf::from) {
            self.nvr_tls_key_file = Some(p);
        }
        if let Some(p) = get("VANTAGE_NVR_AUTH_TOKEN_FILE").map(PathBuf::from) {
            self.nvr_auth_token_file = Some(p);
        }
        if let Some(url) = get("VANTAGE_NVR_BASE_URL") {
            self.nvr_explicit_base_url = Some(url);
        }

        self.validate()?;
        Ok(())
    }

    pub fn capabilities_manifest(&self) -> WorkerCapabilities {
        WorkerCapabilities {
            capabilities: self.capabilities.clone(),
            supported_source_modes: self.supported_source_modes.clone(),
            execution_backend: self.execution_backend.clone(),
            model_id: self.model_id.clone(),
            model_version: self.model_version.clone(),
            max_concurrency: self.max_concurrency,
        }
    }

    pub fn validate(&self) -> Result<(), VantageError> {
        if self.worker_id.trim().is_empty() {
            return Err(VantageError::invalid_configuration(
                "worker_id must be non-empty",
            ));
        }
        self.capabilities_manifest().validate()?;
        if !matches!(
            self.execution_backend.as_str(),
            "onnx" | "candle" | "vlm" | "custom"
        ) {
            return Err(VantageError::invalid_configuration(format!(
                "execution_backend '{}' must be one of onnx, candle, vlm, custom",
                self.execution_backend
            )));
        }
        if !matches!(self.architecture.as_str(), "arm64" | "amd64") {
            return Err(VantageError::invalid_configuration(format!(
                "architecture '{}' must be 'arm64' or 'amd64'",
                self.architecture
            )));
        }
        if self.result_subject.trim().is_empty() {
            return Err(VantageError::invalid_configuration(
                "result_subject must be non-empty",
            ));
        }
        Ok(())
    }
}

pub fn detect_architecture() -> &'static str {
    match std::env::consts::ARCH {
        "aarch64" => "arm64",
        "x86_64" => "amd64",
        _ => "amd64",
    }
}

fn non_empty_env(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}
