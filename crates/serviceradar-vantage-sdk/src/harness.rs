// SPDX-License-Identifier: Apache-2.0

//! Offline synthetic development harness (`run_local_harness`) requiring zero NATS,
//! zero database, and zero cluster connectivity.

use crate::cmaf::extract_mp4_sync_samples;
use crate::decode::{decode_h264_access_unit, decode_jpeg_to_rgb, decode_live_frame_envelope};
use crate::error::VantageError;
use crate::frame::RgbFrame;
use crate::protocol::{
    SourceMode, TimeBasis, VANTAGE_RESULT_SCHEMA_VERSION, VantageFrameContext, VantageHandler,
    VantageLiveFrameEnvelope, VantageObservationInput, VantageResultEnvelope,
    VantageUpstreamDetection, WorkerKind, default_live_pipeline_ids,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::Path;
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HarnessReport {
    pub source_mode: SourceMode,
    pub frames_processed: usize,
    pub result_envelope: VantageResultEnvelope,
    pub schema_validated: bool,
}

struct DecodedClipFrame {
    frame_sequence: u64,
    media_pts_ns: u64,
    timeline_ts_us: i64,
    time_basis: TimeBasis,
    camera_source_id: Uuid,
    stream_profile_id: Uuid,
    rgb_frame: RgbFrame,
    upstream_detections: Vec<VantageUpstreamDetection>,
    pipeline_config: serde_json::Value,
}

/// Runs a [`VantageHandler`] locally against a synthetic MP4, CMAF, JPEG, or JSON clip file.
pub fn run_local_harness<H: VantageHandler>(
    clip_path: impl AsRef<Path>,
    handler: &H,
    source_mode: SourceMode,
    schema_path: Option<&Path>,
) -> Result<HarnessReport, VantageError> {
    let clip_path = clip_path.as_ref();
    let meta = std::fs::metadata(clip_path).map_err(|err| {
        VantageError::harness(format!(
            "local harness clip '{}' is unavailable: {err}",
            clip_path.display()
        ))
    })?;
    if !meta.is_file() || meta.len() == 0 {
        return Err(VantageError::harness(format!(
            "local harness clip '{}' must be a non-empty regular file",
            clip_path.display()
        )));
    }

    let mut schema_validated = false;
    if let Some(sp) = schema_path {
        let schema_raw = std::fs::read_to_string(sp).map_err(|err| {
            VantageError::harness(format!(
                "failed reading signal schema '{}': {err}",
                sp.display()
            ))
        })?;
        let parsed: serde_json::Value = serde_json::from_str(&schema_raw).map_err(|err| {
            VantageError::harness(format!(
                "invalid signal schema JSON '{}': {err}",
                sp.display()
            ))
        })?;
        if !parsed.is_object() {
            return Err(VantageError::harness(format!(
                "signal schema '{}' must be a JSON object",
                sp.display()
            )));
        }
        schema_validated = true;
    }

    let clip_bytes = std::fs::read(clip_path).map_err(|err| {
        VantageError::harness(format!(
            "failed reading local harness clip '{}': {err}",
            clip_path.display()
        ))
    })?;
    if clip_bytes.is_empty() {
        return Err(VantageError::harness(format!(
            "local harness clip '{}' is empty",
            clip_path.display()
        )));
    }

    let descriptor_sha256 = hex::encode(Sha256::digest(&clip_bytes));
    let decoded_frames = decode_clip_frames(clip_path, &clip_bytes, source_mode)?;
    if decoded_frames.is_empty() {
        return Err(VantageError::harness(format!(
            "local harness clip '{}' produced zero decodable frames",
            clip_path.display()
        )));
    }

    let capability = handler.capability().trim();
    if capability.is_empty() {
        return Err(VantageError::invalid_configuration(
            "handler capability() must be non-empty",
        ));
    }
    let (pack_id, pipeline_id) = default_live_pipeline_ids(capability);

    let synthetic_job_id =
        Uuid::parse_str("11111111-1111-4111-8111-111111111199").expect("valid uuid");
    let synthetic_catalog_id =
        Uuid::parse_str("44444444-4444-4444-8444-444444444499").expect("valid uuid");

    let first_cam = decoded_frames[0].camera_source_id;
    let first_prof = decoded_frames[0].stream_profile_id;
    let frames_processed = decoded_frames.len();
    let mut wire_observations: Vec<VantageObservationInput> = Vec::new();

    for (idx, frame) in decoded_frames.into_iter().enumerate() {
        let (catalog_entry_id, fragment_sequence) = match source_mode {
            SourceMode::RecordedBlock => (Some(synthetic_catalog_id), Some((idx + 1) as u32)),
            SourceMode::LiveKeyframeTap => (None, None),
        };
        let ctx = VantageFrameContext {
            source_mode,
            camera_source_id: frame.camera_source_id,
            stream_profile_id: frame.stream_profile_id,
            catalog_entry_id,
            fragment_sequence,
            frame_sequence: frame.frame_sequence,
            media_pts_ns: Some(frame.media_pts_ns),
            timeline_ts_us: frame.timeline_ts_us,
            time_basis: frame.time_basis,
            rgb_frame: frame.rgb_frame,
            upstream_detections: frame.upstream_detections,
            pipeline_config: frame.pipeline_config,
        };

        let outputs = handler.process_frame(&ctx)?;
        for (obs_idx, out) in outputs.into_iter().enumerate() {
            wire_observations.push(out.into_wire_observation(&ctx, &pipeline_id, obs_idx)?);
        }
    }

    let result_envelope = match source_mode {
        SourceMode::RecordedBlock => VantageResultEnvelope {
            schema_version: VANTAGE_RESULT_SCHEMA_VERSION.to_string(),
            job_id: Some(synthetic_job_id),
            pack_id,
            pipeline_id,
            pipeline_version: "1.0.0".to_string(),
            worker_kind: WorkerKind::ExternalRust,
            worker_id: "vantage-local-harness".to_string(),
            model_id: "local-harness".to_string(),
            model_version: "1.0.0".to_string(),
            capability: capability.to_string(),
            source_mode: SourceMode::RecordedBlock,
            camera_source_id: first_cam,
            stream_profile_id: first_prof,
            catalog_entry_id: Some(synthetic_catalog_id),
            descriptor_sha256: Some(descriptor_sha256),
            observations: wire_observations,
        },
        SourceMode::LiveKeyframeTap => VantageResultEnvelope {
            schema_version: VANTAGE_RESULT_SCHEMA_VERSION.to_string(),
            job_id: None,
            pack_id,
            pipeline_id,
            pipeline_version: "1.0.0".to_string(),
            worker_kind: WorkerKind::ExternalRust,
            worker_id: "vantage-local-harness".to_string(),
            model_id: "local-harness".to_string(),
            model_version: "1.0.0".to_string(),
            capability: capability.to_string(),
            source_mode: SourceMode::LiveKeyframeTap,
            camera_source_id: first_cam,
            stream_profile_id: first_prof,
            catalog_entry_id: None,
            descriptor_sha256: None,
            observations: wire_observations,
        },
    };

    let _ = result_envelope.to_bounded_json_bytes()?;

    Ok(HarnessReport {
        source_mode,
        frames_processed,
        result_envelope,
        schema_validated,
    })
}

fn decode_clip_frames(
    clip_path: &Path,
    clip_bytes: &[u8],
    source_mode: SourceMode,
) -> Result<Vec<DecodedClipFrame>, VantageError> {
    let default_cam = match source_mode {
        SourceMode::RecordedBlock => {
            Uuid::parse_str("22222222-2222-4222-8222-222222222201").expect("valid uuid")
        }
        SourceMode::LiveKeyframeTap => {
            Uuid::parse_str("22222222-2222-4222-8222-222222222204").expect("valid uuid")
        }
    };
    let default_prof = Uuid::parse_str("33333333-3333-4333-8333-333333333301").expect("valid uuid");

    let ext = clip_path
        .extension()
        .and_then(|e| e.to_str())
        .map(str::to_ascii_lowercase)
        .unwrap_or_default();

    if ext == "json" || clip_bytes.first().copied() == Some(b'{') {
        let env: VantageLiveFrameEnvelope = serde_json::from_slice(clip_bytes)
            .map_err(|err| VantageError::harness(format!("invalid JSON frame fixture: {err}")))?;
        let rgb = decode_live_frame_envelope(&env)?;
        return Ok(vec![DecodedClipFrame {
            frame_sequence: env.frame_sequence,
            media_pts_ns: env.media_pts_ns.unwrap_or(1_000_000_000),
            timeline_ts_us: env.timeline_ts_us,
            time_basis: env.time_basis,
            camera_source_id: env.camera_source_id,
            stream_profile_id: env.stream_profile_id,
            rgb_frame: rgb,
            upstream_detections: env.detections,
            pipeline_config: env.pipeline_config,
        }]);
    }

    if clip_bytes.len() >= 3 && clip_bytes[0] == 0xFF && clip_bytes[1] == 0xD8 {
        let rgb = decode_jpeg_to_rgb(clip_bytes)?;
        return Ok(vec![DecodedClipFrame {
            frame_sequence: 1,
            media_pts_ns: 1_000_000_000,
            timeline_ts_us: 1_700_000_000_000_000,
            time_basis: TimeBasis::Received,
            camera_source_id: default_cam,
            stream_profile_id: default_prof,
            rgb_frame: rgb,
            upstream_detections: Vec::new(),
            pipeline_config: serde_json::json!({"camera_name": "Gate West 01"}),
        }]);
    }

    let (init, samples) = extract_mp4_sync_samples(clip_bytes)?;
    let mut frames = Vec::with_capacity(samples.len());
    for (idx, sample) in samples.into_iter().enumerate() {
        let param_slices: Vec<&[u8]> = init
            .parameter_sets
            .iter()
            .chain(sample.in_band_parameter_sets.iter())
            .map(Vec::as_slice)
            .collect();
        let idr_slices: Vec<&[u8]> = sample.idr_nal_units.iter().map(Vec::as_slice).collect();
        let rgb = decode_h264_access_unit(&param_slices, &idr_slices)?;
        frames.push(DecodedClipFrame {
            frame_sequence: (idx + 1) as u64,
            media_pts_ns: sample.media_pts_ns,
            timeline_ts_us: 1_700_000_000_000_000 + (idx as i64) * 1_000_000,
            time_basis: TimeBasis::Received,
            camera_source_id: default_cam,
            stream_profile_id: default_prof,
            rgb_frame: rgb,
            upstream_detections: Vec::new(),
            pipeline_config: serde_json::json!({"camera_name": "Gate West 01"}),
        });
    }
    Ok(frames)
}
