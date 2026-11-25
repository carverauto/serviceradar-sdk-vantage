// SPDX-License-Identifier: Apache-2.0

use base64::Engine as _;
use rusty_h264_common::YuvFrame;
use rusty_h264_encoder::{Encoder, EncoderConfig};
use serde_json::json;
use serviceradar_vantage_sdk::cmaf::{build_cmaf_fragment_m4s, build_cmaf_init_mp4};
use serviceradar_vantage_sdk::{
    SourceMode, VantageResultEnvelope, VantageWorker, WorkerConfig, run_local_harness,
    split_annex_b_nals, validate_baseline_jfif,
};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use vantage_worker_alpr::{AlprConfig, AlprWorkerHandler, LoadedAlprConfig, is_valid_plate_text};

fn vectors_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crates dir")
        .parent()
        .expect("repo root")
        .join("conformance")
        .join("vectors")
}

fn build_synthetic_clip_bytes(width: u32, height: u32) -> Vec<u8> {
    let mut cfg = EncoderConfig::baseline(width as usize, height as usize);
    cfg.qp = 16;
    cfg.bitrate = 0;
    cfg.gop_size = 1;
    cfg.lookahead = 0;
    cfg.scenecut = 0;
    cfg.mbtree = false;
    cfg.bframes = 0;
    let frame = YuvFrame {
        width: width as usize,
        height: height as usize,
        y: vec![180u8; (width as usize) * (height as usize)],
        u: vec![128u8; (width as usize / 2) * (height as usize / 2)],
        v: vec![128u8; (width as usize / 2) * (height as usize / 2)],
    };
    let mut enc = Encoder::new(cfg).expect("encoder");
    let annex_b = enc.try_encode(&frame).expect("idr");
    let nals = split_annex_b_nals(&annex_b);
    let sps = nals.iter().copied().find(|n| (n[0] & 0x1f) == 7).unwrap();
    let pps = nals.iter().copied().find(|n| (n[0] & 0x1f) == 8).unwrap();
    let idr = nals.iter().copied().find(|n| (n[0] & 0x1f) == 5).unwrap();

    let mut bytes = build_cmaf_init_mp4(width, height, 90_000, &[sps], &[pps]);
    bytes.extend_from_slice(&build_cmaf_fragment_m4s(
        1,
        0,
        1_000_000_000,
        90_000,
        &[idr],
    ));
    bytes
}

#[test]
fn alpr_worker_ramp1_to_ramp2_schema_parity_recorded_and_live() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let clip_path = tmp.path().join("gate_west_01_alpr.mp4");
    std::fs::write(&clip_path, build_synthetic_clip_bytes(320, 240)).expect("write clip");

    let cfg_raw = std::fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("config.example.toml"),
    )
    .expect("config.example.toml");
    let cfg = AlprConfig::from_toml_str(&cfg_raw).expect("parse config.example.toml");
    assert_eq!(cfg.signal_schema_id, "alpr_plate_read");
    let handler = AlprWorkerHandler::new(cfg);
    let schema_path = vectors_dir().join("alpr_plate_read_schema.json");
    let report = run_local_harness(
        &clip_path,
        &handler,
        SourceMode::RecordedBlock,
        Some(&schema_path),
    )
    .expect("recorded_block harness");
    assert!(report.schema_validated);
    assert_eq!(report.frames_processed, 1);

    let env = &report.result_envelope;
    assert_eq!(env.capability, "vantage.alpr.v1");
    assert_eq!(env.observations.len(), 1);
    let obs = &env.observations[0];
    assert_eq!(obs.signal_schema_id, "alpr_plate_read");
    assert_eq!(obs.signal_schema_version, "1.0.0");
    assert_eq!(obs.display_contract_id, "alpr_plate_read");
    assert_eq!(obs.category, "license_plate");
    let plate = obs.attributes["plate_text"].as_str().expect("plate_text");
    assert!(is_valid_plate_text(plate));
    assert!(plate == "SR-0100" || plate == "TEST-742");
    if let Some(crop_b64) = &obs.crop_jpeg_b64 {
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(crop_b64)
            .expect("b64");
        validate_baseline_jfif(&decoded, Some(32 * 1024)).expect("valid 32 KiB Baseline JFIF");
    }

    // Compare schema_id parity with conformance/vectors/vantage_result_v1.json (Ramp 1 VLM result)
    let ramp1_raw = std::fs::read_to_string(vectors_dir().join("vantage_result_v1.json"))
        .expect("vantage_result_v1.json");
    let ramp1_vec: serde_json::Value = serde_json::from_str(&ramp1_raw).expect("json");
    let ramp1_res: VantageResultEnvelope =
        serde_json::from_value(ramp1_vec["positive"].clone()).expect("ramp1 result");
    assert_eq!(
        ramp1_res.observations[0].signal_schema_id,
        obs.signal_schema_id
    );
    assert_eq!(
        ramp1_res.observations[0].display_contract_id,
        obs.display_contract_id
    );

    // Also verify live_keyframe_tap mode on the same handler
    let live_report = run_local_harness(&clip_path, &handler, SourceMode::LiveKeyframeTap, None)
        .expect("live_keyframe_tap harness");
    assert!(live_report.result_envelope.job_id.is_none());
    assert!(live_report.result_envelope.catalog_entry_id.is_none());
    assert!(
        live_report.result_envelope.observations[0]
            .fragment_sequence
            .is_none()
    );
}

#[tokio::test]
async fn alpr_worker_processes_live_frame_with_synthetic_plate_override() {
    let cfg_raw = std::fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("config.example.toml"),
    )
    .expect("config.example.toml");
    let cfg = AlprConfig::from_toml_str(&cfg_raw).expect("parse config.example.toml");
    assert_eq!(cfg.signal_schema_id, "alpr_plate_read");
    let handler = AlprWorkerHandler::new(cfg);
    let worker = VantageWorker::new(WorkerConfig::default(), handler).expect("worker");

    let frame_raw = std::fs::read_to_string(vectors_dir().join("vantage_frame_v1.json"))
        .expect("vantage_frame_v1.json");
    let mut frame_val: serde_json::Value = serde_json::from_str(&frame_raw).expect("json");
    frame_val["positive"]["pipeline_config"] = json!({
        "camera_name": "Gate West 01",
        "region": "US-CA",
        "synthetic_plate_text": "TEST-742"
    });
    let payload = serde_json::to_vec(&frame_val["positive"]).expect("json");
    let res = worker
        .process_live_frame_bytes(&payload, "vantage.alpr.v1")
        .await
        .expect("live frame result");

    assert_eq!(res.observations[0].label, "TEST-742");
    assert_eq!(res.observations[0].attributes["plate_text"], "TEST-742");
    assert_eq!(res.observations[0].attributes["region"], "US-CA");
    assert_eq!(
        res.observations[0].attributes["camera_label"],
        "Gate West 01"
    );
}

#[test]
fn alpr_config_loads_top_level_worker_fields_and_env_overrides() {
    let cfg_raw = std::fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("config.example.toml"),
    )
    .expect("config.example.toml");

    let loaded = LoadedAlprConfig::from_toml_str(&cfg_raw).expect("load config.example.toml");
    assert_eq!(loaded.worker.worker_id, "vantage-worker-alpr-gate-west-01");
    assert_eq!(loaded.worker.capabilities, vec!["vantage.alpr.v1"]);
    assert_eq!(
        loaded.worker.supported_source_modes,
        vec![SourceMode::RecordedBlock, SourceMode::LiveKeyframeTap]
    );
    assert_eq!(loaded.worker.execution_backend, "custom");
    assert_eq!(loaded.worker.model_id, "vantage-alpr-synthetic-ocr");
    assert_eq!(loaded.worker.model_version, "1.0.0");
    assert_eq!(loaded.worker.max_concurrency, 4);
    assert_eq!(
        loaded.worker.nats_url.as_deref(),
        Some("nats://192.0.2.10:4222")
    );
    assert_eq!(
        loaded.worker.control_plane_url.as_deref(),
        Some("https://192.0.2.20:4000")
    );
    assert_eq!(
        loaded.worker.http_listen_addr,
        Some("127.0.0.1:9091".parse::<SocketAddr>().unwrap())
    );
    assert_eq!(loaded.alpr.capability, "vantage.alpr.v1");
    assert_eq!(loaded.alpr.signal_schema_id, "alpr_plate_read");
    assert_eq!(loaded.alpr.default_region, "US-CO");
    assert_eq!(loaded.alpr.default_camera_label, "Gate West 01");

    // Verify explicit VANTAGE_* env overrides take precedence over TOML while preserving unset fields
    let env_map: HashMap<&str, &str> = HashMap::from([
        ("VANTAGE_WORKER_ID", "override-worker-02"),
        ("VANTAGE_NATS_URL", "nats://192.0.2.99:4222"),
        ("VANTAGE_MAX_CONCURRENCY", "8"),
        (
            "VANTAGE_CAPABILITIES",
            "vantage.alpr.v1,vantage.alpr.custom.v1",
        ),
    ]);
    let overridden = LoadedAlprConfig::from_toml_and_overrides(Some(&cfg_raw), |k| {
        env_map.get(k).map(|v| (*v).to_string())
    })
    .expect("load with env overrides");

    assert_eq!(overridden.worker.worker_id, "override-worker-02");
    assert_eq!(
        overridden.worker.nats_url.as_deref(),
        Some("nats://192.0.2.99:4222")
    );
    assert_eq!(overridden.worker.max_concurrency, 8);
    assert_eq!(
        overridden.worker.capabilities,
        vec!["vantage.alpr.v1", "vantage.alpr.custom.v1"]
    );
    // Unset env vars still preserve TOML values
    assert_eq!(
        overridden.worker.control_plane_url.as_deref(),
        Some("https://192.0.2.20:4000")
    );
    assert_eq!(
        overridden.worker.http_listen_addr,
        Some("127.0.0.1:9091".parse::<SocketAddr>().unwrap())
    );
}
