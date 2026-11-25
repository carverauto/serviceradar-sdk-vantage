// SPDX-License-Identifier: Apache-2.0

//! Canonical `vantage.worker.v1` wire envelopes, validation rules, and worker handler traits.

use crate::crop::{
    CropConfig, DEFAULT_CROP_PADDING_RATIO, DEFAULT_MAX_CROP_BYTES, DEFAULT_MAX_CROP_DIMENSION,
    DEFAULT_MIN_BBOX_WIDTH_PX, RoiPolygon, STORED_PREVIEW_MAX_BYTES,
};
use crate::error::VantageError;
use crate::frame::{ObjectCategory, RgbFrame, clamp_unit_bbox};
use crate::jpeg::validate_baseline_jfif;
use base64::Engine as _;
use serde::{Deserialize, Deserializer, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

pub const VANTAGE_JOB_SCHEMA_VERSION: &str = "vantage.job.v1";
pub const VANTAGE_RESULT_SCHEMA_VERSION: &str = "vantage.result.v1";
pub const VANTAGE_HEARTBEAT_SCHEMA_VERSION: &str = "vantage.heartbeat.v1";
pub const VANTAGE_FRAME_SCHEMA_VERSION: &str = "vantage.frame.v1";
pub const VANTAGE_WORKER_PROTOCOL_VERSION: &str = "vantage.worker.v1";

pub const VANTAGE_RESULTS_SUBJECT: &str = "media.results.vantage.v1";
pub const VANTAGE_VLM_JOBS_SUBJECT: &str = "media.jobs.vantage.vlm.v1";
pub const VANTAGE_VLM_BACKFILL_SUBJECT: &str = "media.jobs.vantage.vlm.backfill.v1";
pub const VANTAGE_HEARTBEAT_SUBJECT: &str = "media.workers.heartbeat.v1";

pub const MAX_VANTAGE_JOB_ENVELOPE_BYTES: usize = 4 * 1024;
pub const MAX_VANTAGE_RESULT_ENVELOPE_BYTES: usize = 960 * 1024;
pub const MAX_OBSERVATIONS_PER_RESULT: usize = 256;
pub const MAX_STORED_CROP_JPEG_BYTES: usize = STORED_PREVIEW_MAX_BYTES;
pub const DEFAULT_VANTAGE_JOB_BUDGET_MS: u64 = 30_000;
pub const MAX_VLM_MAX_TOKENS: u32 = 4096;

/// Normalizes a capability string such as `"vantage.alpr.v1"` into `"vantage_alpr_v1"`.
pub fn capability_slug(capability: &str) -> String {
    let mut slug = String::with_capacity(capability.len());
    let mut prev_underscore = false;
    for ch in capability.chars() {
        if ch.is_ascii_alphanumeric() {
            slug.push(ch.to_ascii_lowercase());
            prev_underscore = false;
        } else if !prev_underscore && !slug.is_empty() {
            slug.push('_');
            prev_underscore = true;
        }
    }
    while slug.ends_with('_') {
        slug.pop();
    }
    slug
}

/// Returns the JetStream subject for a capability (`media.jobs.vantage.<slug>.v1` or `.backfill.v1`).
pub fn job_subject_for_capability(capability: &str, backfill: bool) -> String {
    let slug = capability_slug(capability);
    if backfill {
        format!("media.jobs.vantage.{slug}.backfill.v1")
    } else {
        format!("media.jobs.vantage.{slug}.v1")
    }
}

/// Returns the core-NATS live keyframe tap subject (`media.live.vantage.<slug>.v1`).
pub fn live_subject_for_capability(capability: &str) -> String {
    let slug = capability_slug(capability);
    format!("media.live.vantage.{slug}.v1")
}

/// Derives a reverse-DNS default `pack_id` and `pipeline_id` from a capability when
/// a `live_keyframe_tap` frame does not carry explicit pipeline metadata.
pub fn default_live_pipeline_ids(capability: &str) -> (String, String) {
    let slug = capability_slug(capability).replace('_', "-");
    let pack_id = format!("io.serviceradar.{slug}");
    let pipeline_id = format!("{pack_id}.live");
    (pack_id, pipeline_id)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceMode {
    RecordedBlock,
    LiveKeyframeTap,
}

impl SourceMode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RecordedBlock => "recorded_block",
            Self::LiveKeyframeTap => "live_keyframe_tap",
        }
    }

    pub fn parse(raw: &str) -> Result<Self, VantageError> {
        match raw.trim() {
            "recorded_block" => Ok(Self::RecordedBlock),
            "live_keyframe_tap" => Ok(Self::LiveKeyframeTap),
            other => Err(VantageError::invalid_configuration(format!(
                "unsupported source_mode '{other}', expected 'recorded_block' or 'live_keyframe_tap'"
            ))),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TimeBasis {
    #[default]
    Received,
    CameraReported,
}

impl TimeBasis {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Received => "received",
            Self::CameraReported => "camera_reported",
        }
    }

    pub fn parse(raw: &str) -> Result<Self, VantageError> {
        match raw.trim() {
            "received" => Ok(Self::Received),
            "camera_reported" => Ok(Self::CameraReported),
            other => Err(VantageError::protocol(format!(
                "unsupported time_basis '{other}', expected 'received' or 'camera_reported'"
            ))),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InputMode {
    FullFrame,
    DetectionCrop,
    MultiFrameTrack,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkerKind {
    CameraVlm,
    ExternalRust,
    ExternalPython,
}

impl WorkerKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CameraVlm => "camera_vlm",
            Self::ExternalRust => "external_rust",
            Self::ExternalPython => "external_python",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkerHealth {
    Ready,
    Degraded,
    Draining,
    Unhealthy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LiveFramePayloadFormat {
    AnnexBIdr,
    Jpeg,
    Rgb8,
}

fn default_padding_ratio() -> f32 {
    DEFAULT_CROP_PADDING_RATIO
}

fn default_min_bbox_width_px() -> u32 {
    DEFAULT_MIN_BBOX_WIDTH_PX
}

fn default_max_dimension() -> u32 {
    DEFAULT_MAX_CROP_DIMENSION
}

fn default_max_bytes() -> usize {
    DEFAULT_MAX_CROP_BYTES
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CropPolicy {
    #[serde(default = "default_padding_ratio")]
    pub padding_ratio: f32,
    #[serde(default = "default_min_bbox_width_px")]
    pub min_bbox_width_px: u32,
    #[serde(default = "default_max_dimension")]
    pub max_dimension: u32,
    #[serde(default = "default_max_bytes")]
    pub max_bytes: usize,
}

impl Default for CropPolicy {
    fn default() -> Self {
        Self {
            padding_ratio: DEFAULT_CROP_PADDING_RATIO,
            min_bbox_width_px: DEFAULT_MIN_BBOX_WIDTH_PX,
            max_dimension: DEFAULT_MAX_CROP_DIMENSION,
            max_bytes: DEFAULT_MAX_CROP_BYTES,
        }
    }
}

impl CropPolicy {
    pub fn validate(&self) -> Result<(), VantageError> {
        self.to_crop_config().validate()
    }

    pub fn to_crop_config(&self) -> CropConfig {
        CropConfig {
            padding_ratio: self.padding_ratio,
            min_bbox_width_px: self.min_bbox_width_px,
            ..CropConfig::default()
        }
        .with_bounds(self.max_dimension, self.max_bytes)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SampledTarget {
    pub target_key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub track_id: Option<String>,
    pub fragment_sequence: u32,
    pub media_pts_ns: u64,
    pub timeline_ts_us: i64,
    #[serde(default)]
    pub time_basis: TimeBasis,
    #[serde(default)]
    pub category: String,
    #[serde(default)]
    pub confidence: f32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bbox: Option<[f32; 4]>,
}

impl SampledTarget {
    pub fn validate(&self) -> Result<(), VantageError> {
        if self.target_key.trim().is_empty() {
            return Err(VantageError::protocol(
                "sampled_target.target_key must be non-empty",
            ));
        }
        if !self.confidence.is_finite() || !(0.0..=1.0).contains(&self.confidence) {
            return Err(VantageError::protocol(format!(
                "sampled_target.confidence {} must be finite and in 0.0..=1.0",
                self.confidence
            )));
        }
        if let Some(bbox) = self.bbox {
            validate_unit_bbox(bbox, "sampled_target.bbox")?;
        }
        Ok(())
    }
}

fn default_vlm_max_tokens() -> u32 {
    256
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VlmJobConfig {
    #[serde(default)]
    pub prompt: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub system_prompt: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_profile: Option<String>,
    #[serde(default = "default_vlm_max_tokens")]
    pub max_tokens: u32,
    #[serde(default)]
    pub temperature: f32,
    #[serde(
        default,
        alias = "response_schema",
        skip_serializing_if = "Option::is_none"
    )]
    pub json_schema: Option<serde_json::Value>,
}

impl Default for VlmJobConfig {
    fn default() -> Self {
        Self {
            prompt: String::new(),
            system_prompt: None,
            model_profile: None,
            max_tokens: default_vlm_max_tokens(),
            temperature: 0.0,
            json_schema: None,
        }
    }
}

impl VlmJobConfig {
    pub fn is_empty(&self) -> bool {
        self.prompt.trim().is_empty()
            && self
                .system_prompt
                .as_deref()
                .is_none_or(|s| s.trim().is_empty())
            && self
                .model_profile
                .as_deref()
                .is_none_or(|s| s.trim().is_empty())
            && self.json_schema.is_none()
    }

    pub fn validate(&self) -> Result<(), VantageError> {
        if !self.is_empty() && self.prompt.trim().is_empty() {
            return Err(VantageError::protocol(
                "vlm_config.prompt must be non-empty",
            ));
        }
        if self.max_tokens == 0 || self.max_tokens > MAX_VLM_MAX_TOKENS {
            return Err(VantageError::protocol(format!(
                "vlm_config.max_tokens {} must be in 1..={MAX_VLM_MAX_TOKENS}",
                self.max_tokens
            )));
        }
        if !self.temperature.is_finite() || !(0.0..=2.0).contains(&self.temperature) {
            return Err(VantageError::protocol(format!(
                "vlm_config.temperature {} must be finite and in 0.0..=2.0",
                self.temperature
            )));
        }
        Ok(())
    }
}

fn default_vantage_job_budget_ms() -> u64 {
    DEFAULT_VANTAGE_JOB_BUDGET_MS
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VantageJobEnvelope {
    pub schema_version: String,
    pub job_id: Uuid,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pack_id: Option<String>,
    pub pipeline_id: String,
    pub pipeline_version: String,
    pub capability: String,
    pub source_mode: SourceMode,
    pub camera_source_id: Uuid,
    pub stream_profile_id: Uuid,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub catalog_entry_id: Option<Uuid>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub descriptor_sha256: Option<String>,
    pub input_mode: InputMode,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub roi_polygons: Vec<RoiPolygon>,
    #[serde(default)]
    pub crop_policy: CropPolicy,
    #[serde(default)]
    pub sampled_targets: Vec<SampledTarget>,
    pub signal_schema_id: String,
    pub signal_schema_version: String,
    pub display_contract_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vlm_config: Option<VlmJobConfig>,
    #[serde(default = "default_vantage_job_budget_ms")]
    pub budget_ms: u64,
    #[serde(default)]
    pub pipeline_config: serde_json::Value,
}

impl VantageJobEnvelope {
    pub fn resolved_pack_id(&self) -> String {
        if let Some(pack_id) = self.pack_id.as_deref().map(str::trim)
            && !pack_id.is_empty()
        {
            return pack_id.to_string();
        }
        derive_pack_id_from_pipeline(&self.pipeline_id)
    }

    pub fn validate(&self) -> Result<(), VantageError> {
        if self.schema_version != VANTAGE_JOB_SCHEMA_VERSION {
            return Err(VantageError::protocol(format!(
                "unsupported vantage job schema_version '{}', expected '{VANTAGE_JOB_SCHEMA_VERSION}'",
                self.schema_version
            )));
        }
        require_non_empty(&self.pipeline_id, "pipeline_id")?;
        require_non_empty(&self.pipeline_version, "pipeline_version")?;
        require_non_empty(&self.capability, "capability")?;
        require_non_empty(&self.signal_schema_id, "signal_schema_id")?;
        require_non_empty(&self.signal_schema_version, "signal_schema_version")?;
        require_non_empty(&self.display_contract_id, "display_contract_id")?;

        if self.source_mode == SourceMode::RecordedBlock {
            if self.catalog_entry_id.is_none() {
                return Err(VantageError::protocol(
                    "recorded_block vantage job requires catalog_entry_id",
                ));
            }
            let sha = self.descriptor_sha256.as_deref().ok_or_else(|| {
                VantageError::protocol("recorded_block vantage job requires descriptor_sha256")
            })?;
            validate_sha256_hex(sha, "descriptor_sha256")?;
        } else if let Some(sha) = self.descriptor_sha256.as_deref() {
            validate_sha256_hex(sha, "descriptor_sha256")?;
        }

        for roi in &self.roi_polygons {
            roi.validate()?;
        }
        self.crop_policy.validate()?;
        for target in &self.sampled_targets {
            target.validate()?;
            if self.input_mode != InputMode::FullFrame && target.bbox.is_none() {
                return Err(VantageError::protocol(format!(
                    "sampled_target '{}' requires bbox when input_mode != full_frame",
                    target.target_key
                )));
            }
        }
        if let Some(vlm) = &self.vlm_config {
            vlm.validate()?;
        }
        if self.budget_ms == 0 {
            return Err(VantageError::protocol(
                "vantage job budget_ms must be non-zero",
            ));
        }

        Ok(())
    }

    pub fn to_bounded_json_bytes(&self) -> Result<Vec<u8>, VantageError> {
        self.validate()?;
        let bytes = serde_json::to_vec(self)
            .map_err(|err| VantageError::protocol(format!("failed serializing job: {err}")))?;
        if bytes.len() > MAX_VANTAGE_JOB_ENVELOPE_BYTES {
            return Err(VantageError::protocol(format!(
                "VantageJobEnvelope serialized size {} exceeds {} bytes",
                bytes.len(),
                MAX_VANTAGE_JOB_ENVELOPE_BYTES
            )));
        }
        Ok(bytes)
    }
}

pub fn derive_pack_id_from_pipeline(pipeline_id: &str) -> String {
    let trimmed = pipeline_id.trim();
    match trimmed.rsplit_once('.') {
        Some((prefix, _)) if !prefix.is_empty() => prefix.to_string(),
        _ => trimmed.to_string(),
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VantageObservationInput {
    pub observation_key: String,
    #[serde(default)]
    pub fragment_sequence: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub frame_sequence: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub media_pts_ns: Option<u64>,
    pub timeline_ts_us: i64,
    pub time_basis: TimeBasis,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub track_id: Option<String>,
    pub category: String,
    pub label: String,
    pub confidence: f32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bbox: Option<[f32; 4]>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub crop_jpeg_b64: Option<String>,
    #[serde(default)]
    pub attributes: serde_json::Value,
    pub signal_schema_id: String,
    pub signal_schema_version: String,
    pub display_contract_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub search_text: Option<String>,
}

impl VantageObservationInput {
    pub fn compute_observation_key(
        pipeline_id: &str,
        camera_source_id: Option<Uuid>,
        catalog_entry_id: Option<Uuid>,
        fragment_sequence: Option<u32>,
        frame_sequence: Option<u64>,
        track_id: Option<&str>,
        category: &str,
    ) -> String {
        let scope = match (catalog_entry_id, camera_source_id) {
            (Some(entry_id), _) => entry_id.to_string(),
            (None, Some(cam_id)) => format!("live:{cam_id}"),
            (None, None) => "live".to_string(),
        };
        let seq = fragment_sequence
            .map(u64::from)
            .or(frame_sequence)
            .unwrap_or(0);
        let track = track_id.unwrap_or("scene");
        let canonical = format!("{pipeline_id}|{scope}|{seq}|{track}|{category}");
        hex::encode(Sha256::digest(canonical.as_bytes()))
    }

    pub fn validate(&self) -> Result<(), VantageError> {
        require_non_empty(&self.observation_key, "observation_key")?;
        require_non_empty(&self.category, "category")?;
        require_non_empty(&self.label, "label")?;
        require_non_empty(&self.signal_schema_id, "signal_schema_id")?;
        require_non_empty(&self.signal_schema_version, "signal_schema_version")?;
        require_non_empty(&self.display_contract_id, "display_contract_id")?;

        if !self.confidence.is_finite() || !(0.0..=1.0).contains(&self.confidence) {
            return Err(VantageError::protocol(format!(
                "observation confidence {} must be finite and in 0.0..=1.0",
                self.confidence
            )));
        }
        if let Some(bbox) = self.bbox {
            validate_unit_bbox(bbox, "observation.bbox")?;
        }
        if let Some(crop_b64) = &self.crop_jpeg_b64 {
            let decoded = base64::engine::general_purpose::STANDARD
                .decode(crop_b64)
                .map_err(|err| {
                    VantageError::crop(format!("invalid observation crop_jpeg_b64: {err}"))
                })?;
            validate_baseline_jfif(&decoded, Some(MAX_STORED_CROP_JPEG_BYTES))?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VantageResultEnvelope {
    pub schema_version: String,
    #[serde(default)]
    pub job_id: Option<Uuid>,
    pub pack_id: String,
    pub pipeline_id: String,
    pub pipeline_version: String,
    pub worker_kind: WorkerKind,
    pub worker_id: String,
    pub model_id: String,
    pub model_version: String,
    pub capability: String,
    pub source_mode: SourceMode,
    pub camera_source_id: Uuid,
    pub stream_profile_id: Uuid,
    #[serde(default)]
    pub catalog_entry_id: Option<Uuid>,
    #[serde(default)]
    pub descriptor_sha256: Option<String>,
    #[serde(default)]
    pub observations: Vec<VantageObservationInput>,
}

impl VantageResultEnvelope {
    pub fn validate(&self) -> Result<(), VantageError> {
        if self.schema_version != VANTAGE_RESULT_SCHEMA_VERSION {
            return Err(VantageError::protocol(format!(
                "unsupported vantage result schema_version '{}', expected '{VANTAGE_RESULT_SCHEMA_VERSION}'",
                self.schema_version
            )));
        }
        require_non_empty(&self.pack_id, "pack_id")?;
        require_non_empty(&self.pipeline_id, "pipeline_id")?;
        require_non_empty(&self.pipeline_version, "pipeline_version")?;
        require_non_empty(&self.worker_id, "worker_id")?;
        require_non_empty(&self.model_id, "model_id")?;
        require_non_empty(&self.model_version, "model_version")?;
        require_non_empty(&self.capability, "capability")?;

        if self.observations.len() > MAX_OBSERVATIONS_PER_RESULT {
            return Err(VantageError::protocol(format!(
                "observations count {} exceeds maximum {MAX_OBSERVATIONS_PER_RESULT}",
                self.observations.len()
            )));
        }

        match self.source_mode {
            SourceMode::RecordedBlock => {
                if self.job_id.is_none() {
                    return Err(VantageError::protocol(
                        "recorded_block result requires job_id",
                    ));
                }
                if self.catalog_entry_id.is_none() {
                    return Err(VantageError::protocol(
                        "recorded_block result requires catalog_entry_id",
                    ));
                }
                let sha = self.descriptor_sha256.as_deref().ok_or_else(|| {
                    VantageError::protocol("recorded_block result requires descriptor_sha256")
                })?;
                validate_sha256_hex(sha, "descriptor_sha256")?;
                for obs in &self.observations {
                    if obs.fragment_sequence.is_none() {
                        return Err(VantageError::protocol(
                            "recorded_block observation requires fragment_sequence",
                        ));
                    }
                    if obs.media_pts_ns.is_none() {
                        return Err(VantageError::protocol(
                            "recorded_block observation requires media_pts_ns",
                        ));
                    }
                }
            }
            SourceMode::LiveKeyframeTap => {
                if self.job_id.is_some() {
                    return Err(VantageError::protocol(
                        "live_keyframe_tap result must have job_id = null",
                    ));
                }
                if self.catalog_entry_id.is_some() {
                    return Err(VantageError::protocol(
                        "live_keyframe_tap result must have catalog_entry_id = null",
                    ));
                }
                if self.descriptor_sha256.is_some() {
                    return Err(VantageError::protocol(
                        "live_keyframe_tap result must have descriptor_sha256 = null",
                    ));
                }
                for obs in &self.observations {
                    if obs.fragment_sequence.is_some() {
                        return Err(VantageError::protocol(
                            "live_keyframe_tap observation must have fragment_sequence = null",
                        ));
                    }
                }
            }
        }

        for obs in &self.observations {
            obs.validate()?;
        }
        Ok(())
    }

    pub fn to_bounded_json_bytes(&self) -> Result<Vec<u8>, VantageError> {
        self.validate()?;
        let bytes = serde_json::to_vec(self)
            .map_err(|err| VantageError::protocol(format!("failed serializing result: {err}")))?;
        if bytes.len() > MAX_VANTAGE_RESULT_ENVELOPE_BYTES {
            return Err(VantageError::protocol(format!(
                "VantageResultEnvelope serialized size {} exceeds {} bytes",
                bytes.len(),
                MAX_VANTAGE_RESULT_ENVELOPE_BYTES
            )));
        }
        Ok(bytes)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VantageWorkerHeartbeat {
    pub schema_version: String,
    pub worker_id: String,
    pub worker_kind: WorkerKind,
    pub protocol_version: String,
    pub capabilities: Vec<String>,
    pub supported_source_modes: Vec<SourceMode>,
    pub execution_backend: String,
    pub architecture: String,
    pub model_id: String,
    pub model_version: String,
    pub max_concurrency: u32,
    pub active_jobs: u32,
    pub health: WorkerHealth,
    pub sent_at_us: i64,
}

impl VantageWorkerHeartbeat {
    pub fn validate(&self) -> Result<(), VantageError> {
        if self.schema_version != VANTAGE_HEARTBEAT_SCHEMA_VERSION {
            return Err(VantageError::protocol(format!(
                "unsupported heartbeat schema_version '{}', expected '{VANTAGE_HEARTBEAT_SCHEMA_VERSION}'",
                self.schema_version
            )));
        }
        if self.protocol_version != VANTAGE_WORKER_PROTOCOL_VERSION {
            return Err(VantageError::protocol(format!(
                "unsupported heartbeat protocol_version '{}', expected '{VANTAGE_WORKER_PROTOCOL_VERSION}'",
                self.protocol_version
            )));
        }
        require_non_empty(&self.worker_id, "worker_id")?;
        require_non_empty(&self.execution_backend, "execution_backend")?;
        require_non_empty(&self.architecture, "architecture")?;
        require_non_empty(&self.model_id, "model_id")?;
        require_non_empty(&self.model_version, "model_version")?;
        if self.capabilities.is_empty() {
            return Err(VantageError::protocol(
                "heartbeat capabilities must not be empty",
            ));
        }
        if self.supported_source_modes.is_empty() {
            return Err(VantageError::protocol(
                "heartbeat supported_source_modes must not be empty",
            ));
        }
        if self.max_concurrency == 0 {
            return Err(VantageError::protocol(
                "heartbeat max_concurrency must be non-zero",
            ));
        }
        if self.active_jobs > self.max_concurrency {
            return Err(VantageError::protocol(format!(
                "heartbeat active_jobs {} exceeds max_concurrency {}",
                self.active_jobs, self.max_concurrency
            )));
        }
        Ok(())
    }
}

/// Upstream Stage 1 detection supporting BOTH `{track_id, category, confidence, bbox}`
/// and `{class_id, label, confidence, bbox}` representations.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct VantageUpstreamDetection {
    pub class_id: u32,
    pub label: ObjectCategory,
    pub category: String,
    pub confidence: f32,
    pub bbox: [f32; 4],
    #[serde(skip_serializing_if = "Option::is_none")]
    pub track_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_key: Option<String>,
}

#[derive(Deserialize)]
struct RawUpstreamDetection {
    #[serde(default)]
    class_id: Option<u32>,
    #[serde(default)]
    label: Option<String>,
    #[serde(default)]
    category: Option<String>,
    #[serde(default)]
    confidence: Option<f32>,
    bbox: [f32; 4],
    #[serde(default)]
    track_id: Option<String>,
    #[serde(default)]
    target_key: Option<String>,
}

impl<'de> Deserialize<'de> for VantageUpstreamDetection {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = RawUpstreamDetection::deserialize(deserializer)?;
        let cat_str = raw
            .category
            .or(raw.label)
            .unwrap_or_else(|| "vehicle".to_string());
        let parsed_cat = match cat_str.trim().to_ascii_lowercase().as_str() {
            "person" => ObjectCategory::Person,
            "vehicle" | "car" | "truck" | "bus" | "motorcycle" => ObjectCategory::Vehicle,
            "bicycle" | "bike" => ObjectCategory::Bicycle,
            "animal" => ObjectCategory::Animal,
            "package" => ObjectCategory::Package,
            "motion" => ObjectCategory::Motion,
            _ => ObjectCategory::Vehicle,
        };
        let class_id = raw.class_id.unwrap_or_else(|| parsed_cat.class_id());
        let confidence = raw.confidence.unwrap_or(1.0);
        if !confidence.is_finite() || !(0.0..=1.0).contains(&confidence) {
            return Err(serde::de::Error::custom(format!(
                "detection confidence {confidence} out of 0.0..=1.0"
            )));
        }
        validate_unit_bbox(raw.bbox, "detection.bbox").map_err(serde::de::Error::custom)?;
        Ok(Self {
            class_id,
            label: parsed_cat,
            category: cat_str,
            confidence,
            bbox: clamp_unit_bbox(raw.bbox),
            track_id: raw.track_id,
            target_key: raw.target_key,
        })
    }
}

/// Serializable live-tap frame envelope (`media.live.vantage.<capability_slug>.v1`).
///
/// Supports both `frame_jpeg_b64` / `idr_annex_b_b64` shorthand and `payload_format` +
/// `payload_b64` (`annex_b_idr`, `jpeg`, `rgb8` with `width`/`height`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VantageLiveFrameEnvelope {
    pub schema_version: String,
    pub source_mode: SourceMode,
    pub camera_source_id: Uuid,
    pub stream_profile_id: Uuid,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub catalog_entry_id: Option<Uuid>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fragment_sequence: Option<u32>,
    pub frame_sequence: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub media_pts_ns: Option<u64>,
    pub timeline_ts_us: i64,
    pub time_basis: TimeBasis,
    #[serde(default, alias = "upstream_detections")]
    pub detections: Vec<VantageUpstreamDetection>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload_format: Option<LiveFramePayloadFormat>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload_b64: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub frame_jpeg_b64: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idr_annex_b_b64: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub width: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub height: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub read_token: Option<serde_json::Value>,
    #[serde(default)]
    pub pipeline_config: serde_json::Value,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LiveFrameCarrier {
    Jpeg(Vec<u8>),
    AnnexBIdr(Vec<u8>),
    Rgb8 {
        width: Option<u32>,
        height: Option<u32>,
        bytes: Vec<u8>,
    },
}

impl VantageLiveFrameEnvelope {
    pub fn validate(&self) -> Result<LiveFrameCarrier, VantageError> {
        if self.schema_version != VANTAGE_FRAME_SCHEMA_VERSION {
            return Err(VantageError::protocol(format!(
                "unsupported live frame schema_version '{}', expected '{VANTAGE_FRAME_SCHEMA_VERSION}'",
                self.schema_version
            )));
        }
        if self.source_mode != SourceMode::LiveKeyframeTap {
            return Err(VantageError::protocol(format!(
                "live_keyframe_tap envelope requires source_mode = live_keyframe_tap, got {:?}",
                self.source_mode
            )));
        }
        if self.read_token.is_some() {
            return Err(VantageError::protocol(
                "live_keyframe_tap frame must not carry read_token",
            ));
        }
        if self.catalog_entry_id.is_some() {
            return Err(VantageError::protocol(
                "live_keyframe_tap frame requires catalog_entry_id = null",
            ));
        }
        if self.fragment_sequence.is_some() {
            return Err(VantageError::protocol(
                "live_keyframe_tap frame requires fragment_sequence = null",
            ));
        }
        for det in &self.detections {
            validate_unit_bbox(det.bbox, "detection.bbox")?;
        }

        match (self.payload_format, self.payload_b64.as_deref()) {
            (Some(_), None) => {
                return Err(VantageError::protocol(
                    "payload_b64 is required when payload_format is set",
                ));
            }
            (None, Some(_)) => {
                return Err(VantageError::protocol(
                    "payload_format is required when payload_b64 is set",
                ));
            }
            (Some(fmt), Some(b64)) => {
                let raw = decode_b64_strict(b64, "payload_b64")?;
                return match fmt {
                    LiveFramePayloadFormat::Jpeg => {
                        validate_baseline_jfif(&raw, None)?;
                        Ok(LiveFrameCarrier::Jpeg(raw))
                    }
                    LiveFramePayloadFormat::AnnexBIdr => {
                        validate_annex_b_start_code(&raw, "payload_b64")?;
                        Ok(LiveFrameCarrier::AnnexBIdr(raw))
                    }
                    LiveFramePayloadFormat::Rgb8 => {
                        validate_rgb8_payload(self.width, self.height, &raw)?;
                        Ok(LiveFrameCarrier::Rgb8 {
                            width: self.width,
                            height: self.height,
                            bytes: raw,
                        })
                    }
                };
            }
            (None, None) => {}
        }

        if let Some(jpeg_b64) = self.frame_jpeg_b64.as_deref() {
            let raw = decode_b64_strict(jpeg_b64, "frame_jpeg_b64")?;
            validate_baseline_jfif(&raw, None)?;
            return Ok(LiveFrameCarrier::Jpeg(raw));
        }

        if let Some(idr_b64) = self.idr_annex_b_b64.as_deref() {
            let raw = decode_b64_strict(idr_b64, "idr_annex_b_b64")?;
            validate_annex_b_start_code(&raw, "idr_annex_b_b64")?;
            return Ok(LiveFrameCarrier::AnnexBIdr(raw));
        }

        Err(VantageError::protocol(
            "live_keyframe_tap frame missing payload carrier (expected frame_jpeg_b64, idr_annex_b_b64, or payload_format + payload_b64)",
        ))
    }
}

fn validate_rgb8_payload(
    width: Option<u32>,
    height: Option<u32>,
    bytes: &[u8],
) -> Result<(), VantageError> {
    if bytes.is_empty() || !bytes.len().is_multiple_of(3) {
        return Err(VantageError::invalid_frame(format!(
            "rgb8 payload byte length {} must be non-empty and a multiple of 3",
            bytes.len()
        )));
    }
    match (width, height) {
        (Some(w), Some(h)) => {
            if w == 0 || h == 0 {
                return Err(VantageError::invalid_frame(
                    "rgb8 width and height must be non-zero",
                ));
            }
            let expected = (w as usize)
                .checked_mul(h as usize)
                .and_then(|n| n.checked_mul(3))
                .ok_or_else(|| VantageError::invalid_frame("rgb8 dimension overflow"))?;
            if bytes.len() != expected {
                return Err(VantageError::invalid_frame(format!(
                    "rgb8 dimension mismatch: width={w} * height={h} * 3 = {expected} != actual {} bytes",
                    bytes.len()
                )));
            }
        }
        (Some(_), None) | (None, Some(_)) => {
            return Err(VantageError::invalid_frame(
                "rgb8 payload must provide both width and height or neither",
            ));
        }
        (None, None) => {}
    }
    Ok(())
}

fn validate_annex_b_start_code(bytes: &[u8], field: &str) -> Result<(), VantageError> {
    if !(bytes.starts_with(&[0, 0, 0, 1]) || bytes.starts_with(&[0, 0, 1])) {
        return Err(VantageError::invalid_frame(format!(
            "{field} for annex_b_idr must begin with an Annex-B start code"
        )));
    }
    Ok(())
}

fn decode_b64_strict(b64: &str, field: &str) -> Result<Vec<u8>, VantageError> {
    base64::engine::general_purpose::STANDARD
        .decode(b64.trim())
        .map_err(|err| VantageError::protocol(format!("invalid base64 in {field}: {err}")))
}

/// Unified in-memory frame context passed to [`VantageHandler::process_frame`] for both
/// `recorded_block` and `live_keyframe_tap` frames.
#[derive(Debug, Clone, PartialEq)]
pub struct VantageFrameContext {
    pub source_mode: SourceMode,
    pub camera_source_id: Uuid,
    pub stream_profile_id: Uuid,
    pub catalog_entry_id: Option<Uuid>,
    pub fragment_sequence: Option<u32>,
    pub frame_sequence: u64,
    pub media_pts_ns: Option<u64>,
    pub timeline_ts_us: i64,
    pub time_basis: TimeBasis,
    pub rgb_frame: RgbFrame,
    pub upstream_detections: Vec<VantageUpstreamDetection>,
    pub pipeline_config: serde_json::Value,
}

/// Observation returned by [`VantageHandler::process_frame`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ObservationOutput {
    pub observation_key: String,
    pub fragment_sequence: Option<u32>,
    pub frame_sequence: u64,
    pub media_pts_ns: Option<u64>,
    pub timeline_ts_us: i64,
    pub time_basis: TimeBasis,
    pub track_id: Option<String>,
    pub category: String,
    pub label: String,
    pub confidence: f32,
    pub bbox: Option<[f32; 4]>,
    pub crop_jpeg_b64: Option<String>,
    pub attributes: serde_json::Value,
    pub signal_schema_id: String,
    pub signal_schema_version: String,
    pub display_contract_id: String,
    pub search_text: String,
}

impl ObservationOutput {
    /// Converts this handler output into a validated wire [`VantageObservationInput`],
    /// enforcing mode-specific invariants (`recorded_block` vs `live_keyframe_tap`) and
    /// filling deterministic fallback metadata if omitted.
    pub fn into_wire_observation(
        self,
        ctx: &VantageFrameContext,
        pipeline_id: &str,
        index: usize,
    ) -> Result<VantageObservationInput, VantageError> {
        let fragment_sequence = match ctx.source_mode {
            SourceMode::RecordedBlock => {
                self.fragment_sequence.or(ctx.fragment_sequence).or(Some(0))
            }
            SourceMode::LiveKeyframeTap => None,
        };
        let media_pts_ns = self.media_pts_ns.or(ctx.media_pts_ns).or(Some(0));
        let track_id = self
            .track_id
            .filter(|s| !s.trim().is_empty())
            .or_else(|| {
                ctx.upstream_detections
                    .first()
                    .and_then(|d| d.track_id.clone())
                    .filter(|s| !s.trim().is_empty())
            })
            .or_else(|| Some(format!("frame-{}-det-{index}", self.frame_sequence)));

        let observation_key = if self.observation_key.trim().is_empty() {
            VantageObservationInput::compute_observation_key(
                pipeline_id,
                Some(ctx.camera_source_id),
                ctx.catalog_entry_id,
                fragment_sequence,
                Some(self.frame_sequence),
                track_id.as_deref(),
                &self.category,
            )
        } else {
            self.observation_key
        };

        let bbox = self.bbox.or_else(|| {
            ctx.upstream_detections
                .first()
                .map(|d| d.bbox)
                .or(Some([0.0, 0.0, 1.0, 1.0]))
        });

        let wire = VantageObservationInput {
            observation_key,
            fragment_sequence,
            frame_sequence: Some(self.frame_sequence),
            media_pts_ns,
            timeline_ts_us: self.timeline_ts_us,
            time_basis: self.time_basis,
            track_id,
            category: self.category,
            label: self.label,
            confidence: self.confidence,
            bbox,
            crop_jpeg_b64: self.crop_jpeg_b64,
            attributes: self.attributes,
            signal_schema_id: self.signal_schema_id,
            signal_schema_version: self.signal_schema_version,
            display_contract_id: self.display_contract_id,
            search_text: Some(self.search_text),
        };
        wire.validate()?;
        Ok(wire)
    }
}

/// Capability advertisement metadata published in `vantage.heartbeat.v1` and `/readyz`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkerCapabilities {
    pub capabilities: Vec<String>,
    pub supported_source_modes: Vec<SourceMode>,
    pub execution_backend: String,
    pub model_id: String,
    pub model_version: String,
    pub max_concurrency: u32,
}

impl WorkerCapabilities {
    pub fn validate(&self) -> Result<(), VantageError> {
        if self.capabilities.is_empty() || self.capabilities.iter().any(|c| c.trim().is_empty()) {
            return Err(VantageError::invalid_configuration(
                "worker capabilities must be non-empty",
            ));
        }
        if self.supported_source_modes.is_empty() {
            return Err(VantageError::invalid_configuration(
                "supported_source_modes must be non-empty",
            ));
        }
        if self.max_concurrency == 0 {
            return Err(VantageError::invalid_configuration(
                "max_concurrency must be >= 1",
            ));
        }
        require_non_empty(&self.execution_backend, "execution_backend")?;
        require_non_empty(&self.model_id, "model_id")?;
        require_non_empty(&self.model_version, "model_version")?;
        Ok(())
    }
}

/// Trait implemented by Rust external Vantage workers.
///
/// The identical `process_frame` callback executes for both `SourceMode::RecordedBlock`
/// and `SourceMode::LiveKeyframeTap`.
pub trait VantageHandler: Send + Sync {
    fn capability(&self) -> &str;

    fn process_frame(
        &self,
        ctx: &VantageFrameContext,
    ) -> Result<Vec<ObservationOutput>, VantageError>;
}

pub(crate) fn require_non_empty(value: &str, field: &str) -> Result<(), VantageError> {
    if value.trim().is_empty() {
        return Err(VantageError::protocol(format!(
            "vantage field '{field}' must be non-empty"
        )));
    }
    Ok(())
}

pub(crate) fn validate_sha256_hex(hex_str: &str, field: &str) -> Result<(), VantageError> {
    if hex_str.len() != 64
        || !hex_str
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(VantageError::protocol(format!(
            "vantage field '{field}' must be 64 lowercase hex characters"
        )));
    }
    Ok(())
}

pub(crate) fn validate_unit_bbox(bbox: [f32; 4], field: &str) -> Result<(), VantageError> {
    let [x1, y1, x2, y2] = bbox;
    if !x1.is_finite()
        || !y1.is_finite()
        || !x2.is_finite()
        || !y2.is_finite()
        || !(0.0..=1.0).contains(&x1)
        || !(0.0..=1.0).contains(&y1)
        || !(0.0..=1.0).contains(&x2)
        || !(0.0..=1.0).contains(&y2)
        || x2 <= x1
        || y2 <= y1
    {
        return Err(VantageError::protocol(format!(
            "{field} must satisfy 0.0 <= x1 < x2 <= 1.0 and 0.0 <= y1 < y2 <= 1.0, got {bbox:?}"
        )));
    }
    Ok(())
}
