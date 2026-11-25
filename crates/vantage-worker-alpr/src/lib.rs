// SPDX-License-Identifier: Apache-2.0

//! Permissive Apache-2.0 reference ALPR worker (`vantage.alpr.v1`) emitting
//! canonical `alpr_plate_read` (`v1`) observations with Ramp 1 VLM schema parity.

use base64::Engine as _;
use serde::{Deserialize, Serialize};
use serde_json::json;
use serviceradar_vantage_sdk::{
    CropConfig, CropOutcome, ObservationOutput, RgbFrame, SourceMode, VantageError,
    VantageFrameContext, VantageHandler, WorkerConfig, clamp_unit_bbox, crop_detection_jpeg,
};
use std::net::SocketAddr;

pub const ALPR_CAPABILITY: &str = "vantage.alpr.v1";
pub const ALPR_SIGNAL_SCHEMA_ID: &str = "alpr_plate_read";
pub const ALPR_SIGNAL_SCHEMA_VERSION: &str = "1.0.0";
pub const ALPR_DISPLAY_CONTRACT_ID: &str = "alpr_plate_read";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlprConfig {
    pub capability: String,
    pub signal_schema_id: String,
    pub signal_schema_version: String,
    pub display_contract_id: String,
    pub default_region: String,
    pub default_camera_label: String,
    pub min_confidence: f32,
}

impl Default for AlprConfig {
    fn default() -> Self {
        Self {
            capability: ALPR_CAPABILITY.to_string(),
            signal_schema_id: ALPR_SIGNAL_SCHEMA_ID.to_string(),
            signal_schema_version: ALPR_SIGNAL_SCHEMA_VERSION.to_string(),
            display_contract_id: ALPR_DISPLAY_CONTRACT_ID.to_string(),
            default_region: "US-CO".to_string(),
            default_camera_label: "Gate West 01".to_string(),
            min_confidence: 0.55,
        }
    }
}

#[derive(Deserialize)]
struct ConfigFileDoc {
    #[serde(default)]
    worker_id: Option<String>,
    #[serde(default)]
    capability: Option<String>,
    #[serde(default)]
    capabilities: Option<Vec<String>>,
    #[serde(default)]
    supported_source_modes: Option<Vec<String>>,
    #[serde(default)]
    execution_backend: Option<String>,
    #[serde(default)]
    model_id: Option<String>,
    #[serde(default)]
    model_version: Option<String>,
    #[serde(default)]
    max_concurrency: Option<u32>,
    #[serde(default)]
    nats_url: Option<String>,
    #[serde(default)]
    control_plane_url: Option<String>,
    #[serde(default)]
    http_listen_addr: Option<String>,
    #[serde(default)]
    jobs_stream_name: Option<String>,
    #[serde(default)]
    results_stream_name: Option<String>,
    #[serde(default)]
    live_subject: Option<String>,
    #[serde(default)]
    result_subject: Option<String>,
    #[serde(default)]
    heartbeat_interval_ms: Option<u64>,
    #[serde(default)]
    alpr: Option<AlprTomlSection>,
}

#[derive(Deserialize)]
struct AlprTomlSection {
    signal_schema_id: Option<String>,
    signal_schema_version: Option<String>,
    display_contract_id: Option<String>,
    default_region: Option<String>,
    default_camera_label: Option<String>,
    min_confidence: Option<f32>,
}

#[derive(Debug, Clone)]
pub struct LoadedAlprConfig {
    pub worker: WorkerConfig,
    pub alpr: AlprConfig,
}

impl LoadedAlprConfig {
    pub fn from_toml_str(raw: &str) -> Result<Self, VantageError> {
        Self::from_toml_and_overrides(Some(raw), |_| None)
    }

    pub fn from_toml_and_env(raw: Option<&str>) -> Result<Self, VantageError> {
        Self::from_toml_and_overrides(raw, |key| std::env::var(key).ok())
    }

    pub fn from_toml_and_overrides<F>(raw: Option<&str>, get_var: F) -> Result<Self, VantageError>
    where
        F: Fn(&str) -> Option<String>,
    {
        let mut worker = WorkerConfig {
            model_id: "vantage-alpr-synthetic-ocr".to_string(),
            ..WorkerConfig::default()
        };
        let mut alpr = AlprConfig::default();

        if let Some(toml_raw) = raw {
            let doc: ConfigFileDoc = toml::from_str(toml_raw).map_err(|err| {
                VantageError::invalid_configuration(format!("invalid ALPR TOML config: {err}"))
            })?;

            if let Some(v) = doc
                .worker_id
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
            {
                worker.worker_id = v;
            }
            if let Some(caps) = doc.capabilities {
                let cleaned: Vec<String> = caps
                    .into_iter()
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect();
                if cleaned.is_empty() {
                    return Err(VantageError::invalid_configuration(
                        "capabilities in TOML config must not be empty",
                    ));
                }
                alpr.capability = cleaned[0].clone();
                worker.capabilities = cleaned;
            } else if let Some(cap) = doc
                .capability
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
            {
                alpr.capability = cap.clone();
                worker.capabilities = vec![cap];
            }
            if let Some(modes_raw) = doc.supported_source_modes {
                let mut modes = Vec::with_capacity(modes_raw.len());
                for item in modes_raw {
                    modes.push(SourceMode::parse(&item)?);
                }
                if modes.is_empty() {
                    return Err(VantageError::invalid_configuration(
                        "supported_source_modes in TOML config must not be empty",
                    ));
                }
                worker.supported_source_modes = modes;
            }
            if let Some(v) = doc
                .execution_backend
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
            {
                worker.execution_backend = v;
            }
            if let Some(v) = doc
                .model_id
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
            {
                worker.model_id = v;
            }
            if let Some(v) = doc
                .model_version
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
            {
                worker.model_version = v;
            }
            if let Some(v) = doc.max_concurrency {
                worker.max_concurrency = v;
            }
            if let Some(v) = doc
                .nats_url
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
            {
                worker.nats_url = Some(v);
            }
            if let Some(v) = doc
                .control_plane_url
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
            {
                worker.control_plane_url = Some(v);
            }
            if let Some(addr_raw) = doc
                .http_listen_addr
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
            {
                let addr: SocketAddr = addr_raw.parse().map_err(|err| {
                    VantageError::invalid_configuration(format!(
                        "invalid http_listen_addr '{addr_raw}' in TOML config: {err}"
                    ))
                })?;
                worker.http_listen_addr = Some(addr);
            }
            if let Some(v) = doc
                .jobs_stream_name
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
            {
                worker.jobs_stream_name = v;
            }
            if let Some(v) = doc
                .results_stream_name
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
            {
                worker.results_stream_name = v;
            }
            if let Some(v) = doc
                .live_subject
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
            {
                worker.live_subject_override = Some(v);
            }
            if let Some(v) = doc
                .result_subject
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
            {
                worker.result_subject = v;
            }
            if let Some(v) = doc.heartbeat_interval_ms {
                worker.heartbeat_interval_ms = v;
            }

            if let Some(sec) = doc.alpr {
                if let Some(v) = sec.signal_schema_id {
                    alpr.signal_schema_id = v;
                }
                if let Some(v) = sec.signal_schema_version {
                    alpr.signal_schema_version = v;
                }
                if let Some(v) = sec.display_contract_id {
                    alpr.display_contract_id = v;
                }
                if let Some(v) = sec.default_region {
                    alpr.default_region = v;
                }
                if let Some(v) = sec.default_camera_label {
                    alpr.default_camera_label = v;
                }
                if let Some(v) = sec.min_confidence {
                    alpr.min_confidence = v;
                }
            }
        }

        worker.apply_overrides_with(get_var)?;
        if let Some(primary) = worker.capabilities.first() {
            alpr.capability = primary.clone();
        }
        Ok(Self { worker, alpr })
    }
}

impl AlprConfig {
    pub fn from_toml_str(raw: &str) -> Result<Self, VantageError> {
        Ok(LoadedAlprConfig::from_toml_str(raw)?.alpr)
    }
}

/// Pure-Rust Apache-2.0 reference ALPR handler operating over [`VantageFrameContext`].
#[derive(Debug, Clone, Default)]
pub struct AlprWorkerHandler {
    config: AlprConfig,
}

impl AlprWorkerHandler {
    pub fn new(config: AlprConfig) -> Self {
        Self { config }
    }

    pub fn config(&self) -> &AlprConfig {
        &self.config
    }
}

impl VantageHandler for AlprWorkerHandler {
    fn capability(&self) -> &str {
        &self.config.capability
    }

    fn process_frame(
        &self,
        ctx: &VantageFrameContext,
    ) -> Result<Vec<ObservationOutput>, VantageError> {
        let mut target_boxes: Vec<(Option<String>, [f32; 4])> = ctx
            .upstream_detections
            .iter()
            .filter(|d| {
                matches!(
                    d.category.to_ascii_lowercase().as_str(),
                    "vehicle" | "car" | "truck" | "bus" | "motorcycle" | "license_plate"
                )
            })
            .map(|d| (d.track_id.clone(), d.bbox))
            .collect();

        if target_boxes.is_empty() {
            target_boxes.push((Some("track-1".to_string()), [0.24, 0.36, 0.76, 0.86]));
        }

        let camera_label = ctx
            .pipeline_config
            .get("camera_name")
            .or_else(|| ctx.pipeline_config.get("camera_label"))
            .and_then(|v| v.as_str())
            .filter(|s| !s.trim().is_empty())
            .unwrap_or(&self.config.default_camera_label)
            .to_string();

        let region = ctx
            .pipeline_config
            .get("region")
            .and_then(|v| v.as_str())
            .filter(|s| !s.trim().is_empty())
            .unwrap_or(&self.config.default_region)
            .to_string();

        let mut observations = Vec::with_capacity(target_boxes.len());
        for (idx, (track_id, vehicle_bbox)) in target_boxes.into_iter().enumerate() {
            let plate_bbox = localize_plate_bbox(vehicle_bbox);
            let metrics = analyze_plate_roi(&ctx.rgb_frame, plate_bbox);

            let plate_text = ctx
                .pipeline_config
                .get("synthetic_plate_text")
                .and_then(|v| v.as_str())
                .filter(|s| is_valid_plate_text(s))
                .map(ToString::to_string)
                .unwrap_or_else(|| select_synthetic_plate(ctx.frame_sequence, idx, &metrics));

            let confidence = metrics
                .confidence
                .max(self.config.min_confidence)
                .clamp(0.0, 0.99);

            let crop_outcome = crop_detection_jpeg(
                &ctx.rgb_frame,
                plate_bbox,
                &CropConfig::for_stored_preview().with_bounds(320, 32 * 1024),
            )?;
            let crop_jpeg_b64 = match crop_outcome {
                CropOutcome::Encoded(enc) => {
                    Some(base64::engine::general_purpose::STANDARD.encode(&enc.jpeg_bytes))
                }
                CropOutcome::Skipped { .. } => None,
            };

            let vehicle_color = classify_vehicle_color(metrics.mean_rgb);
            observations.push(ObservationOutput {
                observation_key: String::new(),
                fragment_sequence: ctx.fragment_sequence,
                frame_sequence: ctx.frame_sequence,
                media_pts_ns: ctx.media_pts_ns,
                timeline_ts_us: ctx.timeline_ts_us,
                time_basis: ctx.time_basis,
                track_id: track_id.or_else(|| Some(format!("track-{}", idx + 1))),
                category: "license_plate".to_string(),
                label: plate_text.clone(),
                confidence,
                bbox: Some(plate_bbox),
                crop_jpeg_b64,
                attributes: json!({
                    "plate_text": plate_text,
                    "region": region,
                    "vehicle_color": vehicle_color,
                    "vehicle_type": "sedan",
                    "confidence": confidence,
                    "camera_label": camera_label,
                }),
                signal_schema_id: self.config.signal_schema_id.clone(),
                signal_schema_version: self.config.signal_schema_version.clone(),
                display_contract_id: self.config.display_contract_id.clone(),
                search_text: format!("{plate_text} {camera_label} {region} {vehicle_color} sedan"),
            });
        }

        Ok(observations)
    }
}

struct RoiVisualMetrics {
    mean_rgb: [u8; 3],
    edge_density: f32,
    confidence: f32,
}

fn localize_plate_bbox([x1, y1, x2, y2]: [f32; 4]) -> [f32; 4] {
    let w = (x2 - x1).max(0.05);
    let h = (y2 - y1).max(0.05);
    let px1 = x1 + w * 0.22;
    let px2 = x2 - w * 0.22;
    let py1 = y1 + h * 0.56;
    let py2 = y1 + h * 0.88;
    clamp_unit_bbox([px1, py1, px2, py2])
}

fn analyze_plate_roi(frame: &RgbFrame, bbox: [f32; 4]) -> RoiVisualMetrics {
    let crop = frame.crop_normalized(bbox);
    let luma = crop.to_luma_plane();
    let w = luma.width() as usize;
    let h = luma.height() as usize;

    let mut sum_r = 0u64;
    let mut sum_g = 0u64;
    let mut sum_b = 0u64;
    let px_count = (crop.width() as u64) * (crop.height() as u64);
    for px in crop.pixels().as_chunks::<3>().0 {
        sum_r += u64::from(px[0]);
        sum_g += u64::from(px[1]);
        sum_b += u64::from(px[2]);
    }
    let mean_rgb = [
        sum_r.checked_div(px_count).unwrap_or(128) as u8,
        sum_g.checked_div(px_count).unwrap_or(128) as u8,
        sum_b.checked_div(px_count).unwrap_or(128) as u8,
    ];

    let mut edge_sum = 0u64;
    let mut edge_samples = 0u64;
    if w >= 2 && h >= 2 {
        for y in 0..h {
            for x in 1..w {
                let a = i32::from(luma.luma_at(x as u32, y as u32));
                let b = i32::from(luma.luma_at((x - 1) as u32, y as u32));
                edge_sum += (a - b).unsigned_abs() as u64;
                edge_samples += 1;
            }
        }
    }
    let edge_density = if edge_samples > 0 {
        (edge_sum as f32 / (edge_samples as f32 * 255.0)).clamp(0.0, 1.0)
    } else {
        0.0
    };
    let confidence = (0.86 + edge_density * 0.12).clamp(0.55, 0.98);
    RoiVisualMetrics {
        mean_rgb,
        edge_density,
        confidence,
    }
}

fn select_synthetic_plate(frame_sequence: u64, idx: usize, metrics: &RoiVisualMetrics) -> String {
    let selector = (frame_sequence as usize)
        .wrapping_add(idx)
        .wrapping_add((metrics.edge_density * 100.0) as usize);
    if selector.is_multiple_of(2) {
        "SR-0100".to_string()
    } else {
        "TEST-742".to_string()
    }
}

fn classify_vehicle_color([r, g, b]: [u8; 3]) -> &'static str {
    let max_c = r.max(g).max(b);
    let min_c = r.min(g).min(b);
    if max_c.saturating_sub(min_c) < 24 {
        if max_c > 160 {
            "white"
        } else if max_c > 85 {
            "silver"
        } else {
            "black"
        }
    } else if r >= g && r >= b {
        "red"
    } else if b >= r && b >= g {
        "blue"
    } else {
        "green"
    }
}

pub fn is_valid_plate_text(plate: &str) -> bool {
    let len = plate.len();
    (2..=12).contains(&len)
        && plate
            .bytes()
            .all(|b| matches!(b, b'A'..=b'Z' | b'0'..=b'9' | b'-'))
}
