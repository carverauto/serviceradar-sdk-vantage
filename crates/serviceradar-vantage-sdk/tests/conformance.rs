// SPDX-License-Identifier: Apache-2.0

use base64::Engine as _;
use rusty_h264_common::YuvFrame;
use rusty_h264_encoder::{Encoder, EncoderConfig};
use serde_json::json;
use serviceradar_vantage_sdk::cmaf::{build_cmaf_fragment_m4s, build_cmaf_init_mp4};
use serviceradar_vantage_sdk::grants::VerifiedKeyframeBlock;
use serviceradar_vantage_sdk::http_server::{ReadinessState, build_http_router};
use serviceradar_vantage_sdk::metrics::WorkerMetrics;
use serviceradar_vantage_sdk::{
    CropConfig, CropOutcome, FragmentSlicePlan, FragmentStore, GrantClient, GrantResolution,
    ObservationOutput, ReadGrantPlan, ReadGrantRequest, RgbFrame, SourceMode, VantageError,
    VantageErrorKind, VantageFrameContext, VantageHandler, VantageJobEnvelope,
    VantageLiveFrameEnvelope, VantageResultEnvelope, VantageUpstreamDetection, VantageWorker,
    VantageWorkerHeartbeat, WorkerAuthCredentials, WorkerConfig, capability_slug,
    crop_detection_jpeg, encode_baseline_jpeg, job_subject_for_capability,
    live_subject_for_capability, run_local_harness, split_annex_b_nals, validate_baseline_jfif,
};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use uuid::Uuid;

fn vectors_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crates dir")
        .parent()
        .expect("repo root")
        .join("conformance")
        .join("vectors")
}

fn load_vector(name: &str) -> serde_json::Value {
    let path = vectors_dir().join(name);
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("failed reading {}: {e}", path.display()));
    serde_json::from_str(&raw).unwrap_or_else(|e| panic!("failed parsing {}: {e}", path.display()))
}

fn encode_synthetic_idr(width: usize, height: usize) -> Vec<u8> {
    let mut cfg = EncoderConfig::baseline(width, height);
    cfg.qp = 18;
    cfg.bitrate = 0;
    cfg.gop_size = 1;
    cfg.lookahead = 0;
    cfg.scenecut = 0;
    cfg.mbtree = false;
    cfg.bframes = 0;
    let y = vec![128u8; width * height];
    let u = vec![110u8; (width / 2) * (height / 2)];
    let v = vec![145u8; (width / 2) * (height / 2)];
    let frame = YuvFrame {
        width,
        height,
        y,
        u,
        v,
    };
    let mut enc = Encoder::new(cfg).expect("encoder cfg");
    enc.try_encode(&frame).expect("encode IDR")
}

fn build_synthetic_cmaf(width: u32, height: u32) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let annex_b = encode_synthetic_idr(width as usize, height as usize);
    let nals = split_annex_b_nals(&annex_b);
    let sps = nals
        .iter()
        .copied()
        .find(|n| (n[0] & 0x1f) == 7)
        .expect("SPS");
    let pps = nals
        .iter()
        .copied()
        .find(|n| (n[0] & 0x1f) == 8)
        .expect("PPS");
    let idr = nals
        .iter()
        .copied()
        .find(|n| (n[0] & 0x1f) == 5)
        .expect("IDR");

    let init_bytes = build_cmaf_init_mp4(width, height, 90_000, &[sps], &[pps]);
    let frag_bytes = build_cmaf_fragment_m4s(1, 0, 1_000_000_000, 90_000, &[idr]);
    (annex_b, init_bytes, frag_bytes)
}

struct RecordingHandler {
    capability: String,
    invocations: Arc<AtomicUsize>,
    seen_modes: Arc<parking_lot::Mutex<Vec<SourceMode>>>,
}

impl RecordingHandler {
    fn new(capability: impl Into<String>) -> Self {
        Self {
            capability: capability.into(),
            invocations: Arc::new(AtomicUsize::new(0)),
            seen_modes: Arc::new(parking_lot::Mutex::new(Vec::new())),
        }
    }
}

impl VantageHandler for RecordingHandler {
    fn capability(&self) -> &str {
        &self.capability
    }

    fn process_frame(
        &self,
        ctx: &VantageFrameContext,
    ) -> Result<Vec<ObservationOutput>, VantageError> {
        self.invocations.fetch_add(1, Ordering::SeqCst);
        self.seen_modes.lock().push(ctx.source_mode);

        let crop = crop_detection_jpeg(
            &ctx.rgb_frame,
            [0.15, 0.25, 0.85, 0.85],
            &CropConfig::for_stored_preview().with_bounds(320, 32 * 1024),
        )?;
        let crop_b64 = match crop {
            CropOutcome::Encoded(enc) => {
                Some(base64::engine::general_purpose::STANDARD.encode(&enc.jpeg_bytes))
            }
            CropOutcome::Skipped { .. } => None,
        };

        Ok(vec![ObservationOutput {
            observation_key: String::new(),
            fragment_sequence: ctx.fragment_sequence,
            frame_sequence: ctx.frame_sequence,
            media_pts_ns: ctx.media_pts_ns,
            timeline_ts_us: ctx.timeline_ts_us,
            time_basis: ctx.time_basis,
            track_id: Some("track-1".to_string()),
            category: "license_plate".to_string(),
            label: "SR-0100".to_string(),
            confidence: 0.94,
            bbox: Some([0.32, 0.58, 0.48, 0.66]),
            crop_jpeg_b64: crop_b64,
            attributes: json!({
                "plate_text": "SR-0100",
                "region": "US-CO",
                "confidence": 0.94
            }),
            signal_schema_id: "alpr_plate_read".to_string(),
            signal_schema_version: "1.0.0".to_string(),
            display_contract_id: "alpr_plate_read".to_string(),
            search_text: "SR-0100 Gate West 01 US-CO".to_string(),
        }])
    }
}

struct StubGrantClient {
    resolution: GrantResolution,
}

impl GrantClient for StubGrantClient {
    async fn acquire_read_grant(
        &self,
        _request: &ReadGrantRequest,
    ) -> Result<GrantResolution, VantageError> {
        Ok(self.resolution.clone())
    }
}

struct StubFragmentStore {
    init_bytes: Vec<u8>,
    expected_init_sha256: String,
    fragments: Vec<(FragmentSlicePlan, Vec<u8>)>,
}

impl FragmentStore for StubFragmentStore {
    async fn fetch_verified_block(
        &self,
        _plan: &ReadGrantPlan,
    ) -> Result<VerifiedKeyframeBlock, VantageError> {
        VerifiedKeyframeBlock::from_unverified(
            self.init_bytes.clone(),
            &self.expected_init_sha256,
            self.fragments.clone(),
        )
    }
}

fn resolve_negative_payload(
    vec_root: &serde_json::Value,
    neg: &serde_json::Value,
) -> serde_json::Value {
    if let Some(base_key) = neg.get("mutate_from").and_then(|v| v.as_str()) {
        let mut base = vec_root
            .get(base_key)
            .unwrap_or_else(|| panic!("missing mutate_from '{base_key}'"))
            .clone();
        if let Some(patch) = neg.get("patch").and_then(|v| v.as_object()) {
            for (dotted_key, val) in patch {
                apply_dotted_patch(&mut base, dotted_key, val.clone());
            }
        }
        base
    } else {
        neg.get("payload")
            .unwrap_or_else(|| {
                panic!(
                    "negative vector {} missing payload and mutate_from",
                    neg["name"]
                )
            })
            .clone()
    }
}

fn apply_dotted_patch(target: &mut serde_json::Value, dotted_path: &str, value: serde_json::Value) {
    let parts: Vec<&str> = dotted_path.split('.').collect();
    let mut cur = target;
    for part in &parts[..parts.len() - 1] {
        let map = cur.as_object_mut().unwrap_or_else(|| {
            panic!("patch path '{dotted_path}' segment '{part}' is not an object")
        });
        cur = map
            .entry((*part).to_string())
            .or_insert_with(|| serde_json::Value::Object(Default::default()));
    }
    let leaf = parts[parts.len() - 1];
    cur.as_object_mut()
        .unwrap_or_else(|| panic!("patch path '{dotted_path}' parent is not an object"))
        .insert(leaf.to_string(), value);
}

fn assert_negative_error<T>(res: Result<T, VantageError>, neg: &serde_json::Value, kind: &str) {
    let name = neg["name"].as_str().unwrap_or("<unnamed>");
    let err = match res {
        Ok(_) => panic!("negative {kind} '{name}' unexpectedly succeeded"),
        Err(err) => err,
    };
    if let Some(expected) = neg.get("expected_error").and_then(|v| v.as_str()) {
        let msg = err.to_string();
        assert!(
            msg.contains(expected),
            "negative {kind} '{name}' error '{msg}' did not contain expected_error '{expected}'"
        );
    }
}

#[test]
fn conformance_wire_vectors_roundtrip_and_negative_rejections() {
    assert_eq!(capability_slug("vantage.alpr.v1"), "vantage_alpr_v1");
    assert_eq!(
        job_subject_for_capability("vantage.alpr.v1", false),
        "media.jobs.vantage.vantage_alpr_v1.v1"
    );
    assert_eq!(
        job_subject_for_capability("vantage.alpr.v1", true),
        "media.jobs.vantage.vantage_alpr_v1.backfill.v1"
    );
    assert_eq!(
        live_subject_for_capability("vantage.bay_guidance.v1"),
        "media.live.vantage.vantage_bay_guidance_v1.v1"
    );

    // 1. vantage_job_v1
    let job_vec = load_vector("vantage_job_v1.json");
    let job: VantageJobEnvelope =
        serde_json::from_value(job_vec["positive"].clone()).expect("valid job");
    job.to_bounded_json_bytes().expect("bounded job bytes");
    for neg in job_vec["negative"].as_array().expect("negative jobs") {
        let payload = resolve_negative_payload(&job_vec, neg);
        let parsed: Result<VantageJobEnvelope, _> = serde_json::from_value(payload);
        let res = parsed
            .map(|j| j.to_bounded_json_bytes())
            .unwrap_or_else(|e| Err(VantageError::protocol(e.to_string())));
        assert_negative_error(res, neg, "job");
    }

    // 2. vantage_result_v1
    let res_vec = load_vector("vantage_result_v1.json");
    let res_rec: VantageResultEnvelope =
        serde_json::from_value(res_vec["positive"].clone()).expect("valid recorded result");
    res_rec
        .to_bounded_json_bytes()
        .expect("bounded recorded result");
    let res_live: VantageResultEnvelope =
        serde_json::from_value(res_vec["positive_live"].clone()).expect("valid live result");
    res_live
        .to_bounded_json_bytes()
        .expect("bounded live result");
    for neg in res_vec["negative"].as_array().expect("negative results") {
        let payload = resolve_negative_payload(&res_vec, neg);
        let parsed: Result<VantageResultEnvelope, _> = serde_json::from_value(payload);
        let res = parsed
            .map(|r| r.to_bounded_json_bytes())
            .unwrap_or_else(|e| Err(VantageError::protocol(e.to_string())));
        assert_negative_error(res, neg, "result");
    }

    // 3. vantage_heartbeat_v1
    let hb_vec = load_vector("vantage_heartbeat_v1.json");
    let hb: VantageWorkerHeartbeat =
        serde_json::from_value(hb_vec["positive"].clone()).expect("valid heartbeat");
    hb.validate().expect("heartbeat validates");
    for neg in hb_vec["negative"].as_array().expect("negative heartbeats") {
        let payload = resolve_negative_payload(&hb_vec, neg);
        let parsed: Result<VantageWorkerHeartbeat, _> = serde_json::from_value(payload);
        let res = parsed
            .map(|h| h.validate())
            .unwrap_or_else(|e| Err(VantageError::protocol(e.to_string())));
        assert_negative_error(res, neg, "heartbeat");
    }

    // 4. vantage_frame_v1 (both frame_jpeg_b64 and payload_format + payload_b64)
    let frame_vec = load_vector("vantage_frame_v1.json");
    let f_pos: VantageLiveFrameEnvelope =
        serde_json::from_value(frame_vec["positive"].clone()).expect("positive frame");
    f_pos.validate().expect("positive frame validates");
    let f_pf: VantageLiveFrameEnvelope =
        serde_json::from_value(frame_vec["positive_payload_format"].clone())
            .expect("positive payload_format frame");
    f_pf.validate().expect("positive payload_format validates");
    for neg in frame_vec["negative"].as_array().expect("negative frames") {
        let payload = resolve_negative_payload(&frame_vec, neg);
        let parsed: Result<VantageLiveFrameEnvelope, _> = serde_json::from_value(payload);
        let res = parsed
            .map(|f| f.validate().map(|_| ()))
            .unwrap_or_else(|e| Err(VantageError::protocol(e.to_string())));
        assert_negative_error(res, neg, "frame");
    }

    // 5. read_grant_response
    let rg_vec = load_vector("read_grant_response.json");
    let rg_arch: ReadGrantPlan =
        serde_json::from_value(rg_vec["positive_archive"].clone()).expect("archive grant");
    rg_arch.validate().expect("archive grant validates");
    let rg_loc: ReadGrantPlan =
        serde_json::from_value(rg_vec["positive_local"].clone()).expect("local grant");
    rg_loc.validate().expect("local grant validates");
    for neg in rg_vec["negative"].as_array().expect("negative grants") {
        let payload = resolve_negative_payload(&rg_vec, neg);
        let parsed: Result<ReadGrantPlan, _> = serde_json::from_value(payload);
        let res = parsed
            .map(|g| {
                let req =
                    ReadGrantRequest::new(&g.job_id, &g.catalog_entry_id, &g.descriptor_sha256);
                g.validate_for_request(&req)
            })
            .unwrap_or_else(|e| Err(VantageError::protocol(e.to_string())));
        assert_negative_error(res, neg, "read_grant");
    }

    // 6. Signal schemas presence & dual VantageUpstreamDetection deserialization
    assert!(load_vector("alpr_plate_read_schema.json")["schema_id"] == "alpr_plate_read");
    assert!(load_vector("bay_guidance_schema.json")["schema_id"] == "bay_guidance");

    let det_cat: VantageUpstreamDetection = serde_json::from_value(json!({
        "track_id": "t-1",
        "category": "vehicle",
        "confidence": 0.91,
        "bbox": [0.2, 0.3, 0.7, 0.85]
    }))
    .expect("category detection shape");
    assert_eq!(det_cat.category, "vehicle");

    let det_cls: VantageUpstreamDetection = serde_json::from_value(json!({
        "class_id": 1,
        "label": "vehicle",
        "confidence": 0.87,
        "bbox": [0.2, 0.3, 0.7, 0.85]
    }))
    .expect("class_id+label detection shape");
    assert_eq!(det_cls.class_id, 1);
}

#[tokio::test]
async fn sha256_mismatch_aborts_before_decode_or_process_frame() {
    let (_annex_b, init_bytes, frag_bytes) = build_synthetic_cmaf(128, 96);
    let init_sha = hex::encode(Sha256::digest(&init_bytes));
    let mut bad_frag_bytes = frag_bytes.clone();
    bad_frag_bytes[0] ^= 0xFF;
    let expected_frag_sha = hex::encode(Sha256::digest(&frag_bytes));

    let job_vec = load_vector("vantage_job_v1.json");
    let mut job: VantageJobEnvelope =
        serde_json::from_value(job_vec["positive"].clone()).expect("job");
    job.capability = "vantage.alpr.v1".to_string();

    let rg_vec = load_vector("read_grant_response.json");
    let mut plan: ReadGrantPlan =
        serde_json::from_value(rg_vec["positive_local"].clone()).expect("plan");
    plan.job_id = job.job_id.to_string();
    plan.catalog_entry_id = job.catalog_entry_id.unwrap().to_string();
    plan.descriptor_sha256 = job.descriptor_sha256.clone().unwrap();
    plan.init_sha256 = init_sha.clone();
    plan.init.sha256 = init_sha.clone();
    plan.init.length = init_bytes.len() as u64;
    plan.fragments = vec![FragmentSlicePlan::new(
        1,
        0,
        frag_bytes.len() as u64,
        0,
        1_000_000_000,
        expected_frag_sha.clone(),
    )];

    let handler = RecordingHandler::new("vantage.alpr.v1");
    let invocations = handler.invocations.clone();
    let cfg = WorkerConfig::default();
    let worker = VantageWorker::new(cfg, handler).expect("worker");

    let err = worker
        .process_recorded_job(
            &job,
            &StubGrantClient {
                resolution: GrantResolution::Admitted(Box::new(plan.clone())),
            },
            &StubFragmentStore {
                init_bytes: init_bytes.clone(),
                expected_init_sha256: init_sha.clone(),
                fragments: vec![(plan.fragments[0].clone(), bad_frag_bytes)],
            },
        )
        .await
        .expect_err("corrupted fragment SHA-256 must fail");

    assert!(matches!(err.kind(), VantageErrorKind::Integrity(_)));
    assert_eq!(
        invocations.load(Ordering::SeqCst),
        0,
        "process_frame must NEVER be invoked when SHA-256 verification fails"
    );

    // Also test init.mp4 SHA-256 mismatch
    let mut bad_init = init_bytes;
    bad_init[4] ^= 0xAA;
    let err_init = worker
        .process_recorded_job(
            &job,
            &StubGrantClient {
                resolution: GrantResolution::Admitted(Box::new(plan.clone())),
            },
            &StubFragmentStore {
                init_bytes: bad_init,
                expected_init_sha256: init_sha,
                fragments: vec![(plan.fragments[0].clone(), frag_bytes)],
            },
        )
        .await
        .expect_err("corrupted init SHA-256 must fail");
    assert!(matches!(err_init.kind(), VantageErrorKind::Integrity(_)));
    assert_eq!(invocations.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn rgb8_payload_validates_dimensions_and_rejects_mismatch() {
    let handler = RecordingHandler::new("vantage.bay_guidance.v1");
    let worker = VantageWorker::new(WorkerConfig::default(), handler).expect("worker");

    let valid_rgb8 = vec![180u8; 4 * 2 * 3];
    let valid_payload = serde_json::to_vec(&json!({
        "schema_version": "vantage.frame.v1",
        "source_mode": "live_keyframe_tap",
        "camera_source_id": "22222222-2222-4222-8222-222222222204",
        "stream_profile_id": "33333333-3333-4333-8333-333333333304",
        "frame_sequence": 7,
        "timeline_ts_us": 1700000042000000i64,
        "time_basis": "received",
        "catalog_entry_id": null,
        "fragment_sequence": null,
        "payload_format": "rgb8",
        "width": 4,
        "height": 2,
        "payload_b64": base64::engine::general_purpose::STANDARD.encode(&valid_rgb8),
        "detections": []
    }))
    .expect("json");
    let res = worker
        .process_live_frame_bytes(&valid_payload, "vantage.bay_guidance.v1")
        .await
        .expect("valid rgb8 must succeed");
    assert_eq!(res.source_mode, SourceMode::LiveKeyframeTap);
    assert!(res.job_id.is_none());

    // Mismatched dimensions: width=4, height=2 expects 24 bytes, give 21 bytes
    let bad_rgb8 = vec![180u8; 21];
    let bad_payload = serde_json::to_vec(&json!({
        "schema_version": "vantage.frame.v1",
        "source_mode": "live_keyframe_tap",
        "camera_source_id": "22222222-2222-4222-8222-222222222204",
        "stream_profile_id": "33333333-3333-4333-8333-333333333304",
        "frame_sequence": 8,
        "timeline_ts_us": 1700000043000000i64,
        "time_basis": "received",
        "catalog_entry_id": null,
        "fragment_sequence": null,
        "payload_format": "rgb8",
        "width": 4,
        "height": 2,
        "payload_b64": base64::engine::general_purpose::STANDARD.encode(&bad_rgb8),
        "detections": []
    }))
    .expect("json");
    let err = worker
        .process_live_frame_bytes(&bad_payload, "vantage.bay_guidance.v1")
        .await
        .expect_err("rgb8 length mismatch must fail");
    assert!(matches!(err.kind(), VantageErrorKind::InvalidFrame(_)));
}

#[tokio::test]
async fn live_keyframe_tap_carriers_and_strict_nullity() {
    let handler = RecordingHandler::new("vantage.bay_guidance.v1");
    let worker = VantageWorker::new(WorkerConfig::default(), handler).expect("worker");

    // 1. Annex-B IDR live tap carrier
    let annex_b = encode_synthetic_idr(64, 64);
    let annex_payload = serde_json::to_vec(&json!({
        "schema_version": "vantage.frame.v1",
        "source_mode": "live_keyframe_tap",
        "camera_source_id": "22222222-2222-4222-8222-222222222204",
        "stream_profile_id": "33333333-3333-4333-8333-333333333304",
        "frame_sequence": 11,
        "timeline_ts_us": 1700000050000000i64,
        "time_basis": "received",
        "catalog_entry_id": null,
        "fragment_sequence": null,
        "payload_format": "annex_b_idr",
        "payload_b64": base64::engine::general_purpose::STANDARD.encode(&annex_b),
        "detections": [
            {
                "track_id": "bay-04-track-1",
                "category": "vehicle",
                "confidence": 0.92,
                "bbox": [0.2, 0.3, 0.7, 0.85]
            }
        ]
    }))
    .expect("json");
    let res = worker
        .process_live_frame_bytes(&annex_payload, "vantage.bay_guidance.v1")
        .await
        .expect("annex_b_idr live tap succeeds");
    assert_eq!(res.source_mode, SourceMode::LiveKeyframeTap);
    assert!(res.job_id.is_none());
    assert!(res.catalog_entry_id.is_none());
    assert!(res.descriptor_sha256.is_none());
    assert!(res.observations[0].fragment_sequence.is_none());

    // 2. JPEG live tap carrier (`frame_jpeg_b64`)
    let rgb = RgbFrame::solid(64, 64, [40, 120, 200]);
    let jpeg = encode_baseline_jpeg(&rgb, 80).expect("jpeg");
    validate_baseline_jfif(&jpeg, None).expect("valid jfif");
    let jpeg_payload = serde_json::to_vec(&json!({
        "schema_version": "vantage.frame.v1",
        "source_mode": "live_keyframe_tap",
        "camera_source_id": "22222222-2222-4222-8222-222222222204",
        "stream_profile_id": "33333333-3333-4333-8333-333333333304",
        "frame_sequence": 12,
        "timeline_ts_us": 1700000051000000i64,
        "time_basis": "received",
        "catalog_entry_id": null,
        "fragment_sequence": null,
        "frame_jpeg_b64": base64::engine::general_purpose::STANDARD.encode(&jpeg)
    }))
    .expect("json");
    let res2 = worker
        .process_live_frame_bytes(&jpeg_payload, "vantage.bay_guidance.v1")
        .await
        .expect("jpeg live tap succeeds");
    assert!(res2.job_id.is_none());

    // 3. Reject read_token and non-null catalog_entry_id
    let mut bad: serde_json::Value = serde_json::from_slice(&jpeg_payload).expect("json");
    bad["read_token"] = json!("tok-forbidden");
    let bad_bytes = serde_json::to_vec(&bad).expect("json");
    assert!(
        worker
            .process_live_frame_bytes(&bad_bytes, "vantage.bay_guidance.v1")
            .await
            .is_err()
    );
}

#[tokio::test]
async fn dual_source_mode_processes_recorded_and_live_interleaved() {
    let (_annex_b, init_bytes, frag_bytes) = build_synthetic_cmaf(160, 120);
    let init_sha = hex::encode(Sha256::digest(&init_bytes));
    let frag_sha = hex::encode(Sha256::digest(&frag_bytes));

    let job_vec = load_vector("vantage_job_v1.json");
    let mut job: VantageJobEnvelope =
        serde_json::from_value(job_vec["positive"].clone()).expect("job");
    job.capability = "vantage.alpr.v1".to_string();

    let rg_vec = load_vector("read_grant_response.json");
    let mut plan: ReadGrantPlan =
        serde_json::from_value(rg_vec["positive_local"].clone()).expect("plan");
    plan.job_id = job.job_id.to_string();
    plan.catalog_entry_id = job.catalog_entry_id.unwrap().to_string();
    plan.descriptor_sha256 = job.descriptor_sha256.clone().unwrap();
    plan.init_sha256 = init_sha.clone();
    plan.init.sha256 = init_sha.clone();
    plan.init.length = init_bytes.len() as u64;
    plan.fragments = vec![FragmentSlicePlan::new(
        1,
        0,
        frag_bytes.len() as u64,
        0,
        1_000_000_000,
        frag_sha,
    )];

    let handler = RecordingHandler::new("vantage.alpr.v1");
    let seen_modes = handler.seen_modes.clone();
    let worker = VantageWorker::new(WorkerConfig::default(), handler).expect("worker");

    // 1. Recorded block pass
    let rec_res = worker
        .process_recorded_job(
            &job,
            &StubGrantClient {
                resolution: GrantResolution::Admitted(Box::new(plan.clone())),
            },
            &StubFragmentStore {
                init_bytes: init_bytes.clone(),
                expected_init_sha256: init_sha,
                fragments: vec![(plan.fragments[0].clone(), frag_bytes.clone())],
            },
        )
        .await
        .expect("recorded_block")
        .expect("result envelope");
    assert_eq!(rec_res.source_mode, SourceMode::RecordedBlock);
    assert!(rec_res.job_id.is_some());
    assert!(rec_res.catalog_entry_id.is_some());
    assert_eq!(rec_res.observations[0].fragment_sequence, Some(1));
    if let Some(crop_b64) = &rec_res.observations[0].crop_jpeg_b64 {
        let raw = base64::engine::general_purpose::STANDARD
            .decode(crop_b64)
            .expect("b64");
        validate_baseline_jfif(&raw, Some(32 * 1024)).expect("stored crop <= 32 KiB Baseline JFIF");
    }

    // 2. Interleaved live_keyframe_tap pass on the exact same handler
    let frame_vec = load_vector("vantage_frame_v1.json");
    let live_bytes = serde_json::to_vec(&frame_vec["positive"]).expect("json");
    let live_res = worker
        .process_live_frame_bytes(&live_bytes, "vantage.alpr.v1")
        .await
        .expect("live_keyframe_tap");
    assert_eq!(live_res.source_mode, SourceMode::LiveKeyframeTap);
    assert!(live_res.job_id.is_none());
    assert!(live_res.catalog_entry_id.is_none());
    assert!(live_res.observations[0].fragment_sequence.is_none());

    // 3. 410 Gone recording returns Ok(None) for clean ACK
    let gone_res = worker
        .process_recorded_job(
            &job,
            &StubGrantClient {
                resolution: GrantResolution::Gone,
            },
            &StubFragmentStore {
                init_bytes: Vec::new(),
                expected_init_sha256: String::new(),
                fragments: Vec::new(),
            },
        )
        .await
        .expect("410 Gone resolves cleanly");
    assert!(gone_res.is_none());

    assert_eq!(
        *seen_modes.lock(),
        vec![SourceMode::RecordedBlock, SourceMode::LiveKeyframeTap]
    );

    // 4. Local synthetic harness works in both modes on a CMAF MP4 clip and fails on missing clip
    let tmp = tempfile::tempdir().expect("tempdir");
    let clip_path = tmp.path().join("synthetic_gate_west_01.mp4");
    let mut combined = init_bytes;
    combined.extend_from_slice(&frag_bytes);
    std::fs::write(&clip_path, &combined).expect("write clip");

    let harness_handler = RecordingHandler::new("vantage.alpr.v1");
    let r_rec = run_local_harness(
        &clip_path,
        &harness_handler,
        SourceMode::RecordedBlock,
        Some(&vectors_dir().join("alpr_plate_read_schema.json")),
    )
    .expect("harness recorded_block");
    assert_eq!(r_rec.frames_processed, 1);
    assert_eq!(r_rec.result_envelope.source_mode, SourceMode::RecordedBlock);

    let r_live = run_local_harness(
        &clip_path,
        &harness_handler,
        SourceMode::LiveKeyframeTap,
        None,
    )
    .expect("harness live_keyframe_tap");
    assert_eq!(r_live.frames_processed, 1);
    assert_eq!(
        r_live.result_envelope.source_mode,
        SourceMode::LiveKeyframeTap
    );
    assert!(r_live.result_envelope.job_id.is_none());

    let missing_err = run_local_harness(
        tmp.path().join("missing.mp4"),
        &harness_handler,
        SourceMode::RecordedBlock,
        None,
    );
    assert!(missing_err.is_err());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn http_probes_and_read_grants_410_gone_work_end_to_end() {
    // 1. Test /healthz, /readyz, /metrics router via TCP
    let metrics = Arc::new(WorkerMetrics::new());
    let caps = WorkerConfig::default().capabilities_manifest();
    let readiness = ReadinessState::ready("worker-probe-1", caps, metrics);
    let (_tx, rx) = tokio::sync::watch::channel(false);
    let addr =
        serviceradar_vantage_sdk::serve_http_probes("127.0.0.1:0".parse().unwrap(), readiness, rx)
            .await
            .expect("bind probe");
    let _ = build_http_router; // ensure public export compiles

    let health = ureq::get(&format!("http://{addr}/healthz"))
        .call()
        .expect("healthz")
        .status()
        .as_u16();
    assert_eq!(health, 200);
    let ready = ureq::get(&format!("http://{addr}/readyz"))
        .call()
        .expect("readyz")
        .status()
        .as_u16();
    assert_eq!(ready, 200);
    let metrics_status = ureq::get(&format!("http://{addr}/metrics"))
        .call()
        .expect("metrics")
        .status()
        .as_u16();
    assert_eq!(metrics_status, 200);

    // 2. Test HTTP read-grants client against a mock server returning 410 Gone
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock cp");
    let cp_addr = listener.local_addr().expect("addr");
    let server_handle = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept");
        let mut reader = BufReader::new(stream.try_clone().expect("clone"));
        let mut headers = BTreeMap::new();
        let mut line = String::new();
        let _ = reader.read_line(&mut line);
        loop {
            line.clear();
            let n = reader.read_line(&mut line).expect("read header");
            if n == 0 || line == "\r\n" || line == "\n" {
                break;
            }
            if let Some((k, v)) = line.split_once(':') {
                headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
            }
        }
        let len: usize = headers
            .get("content-length")
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        let mut body = vec![0u8; len];
        let _ = reader.read_exact(&mut body);
        assert!(headers.contains_key("x-serviceradar-control-plane-authorization"));
        assert!(headers.contains_key("x-serviceradar-deployment-ref"));
        assert!(headers.contains_key("x-serviceradar-media-worker-generation"));

        let resp_body = r#"{"status":"recording_gone"}"#;
        let resp = format!(
            "HTTP/1.1 410 Gone\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{}",
            resp_body.len(),
            resp_body
        );
        stream.write_all(resp.as_bytes()).expect("write 410");
    });

    let client = serviceradar_vantage_sdk::HttpControlPlaneGrantClient::new(
        format!("http://{cp_addr}"),
        WorkerAuthCredentials::new("tok-synth", "deploy-synth", "7"),
        Duration::from_secs(5),
    );
    let res = client
        .acquire_read_grant(&ReadGrantRequest::new(
            Uuid::new_v4().to_string(),
            Uuid::new_v4().to_string(),
            "a".repeat(64),
        ))
        .await
        .expect("410 should resolve cleanly");
    assert_eq!(res, GrantResolution::Gone);
    server_handle.join().expect("mock cp thread");
}

struct ChildGuard(std::process::Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn live_keyframe_tap_custom_result_subject_run_until_one() {
    use async_nats::jetstream;
    use futures::StreamExt;

    let probe_cmd = std::process::Command::new("nats-server")
        .arg("--version")
        .output();
    if probe_cmd.is_err() {
        eprintln!("skipping live nats-server test: nats-server not found on PATH");
        return;
    }

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind free port");
    let port = listener.local_addr().expect("port").port();
    drop(listener);

    let js_dir = tempfile::tempdir().expect("js tempdir");
    let child = std::process::Command::new("nats-server")
        .arg("-js")
        .arg("-a")
        .arg("127.0.0.1")
        .arg("-p")
        .arg(port.to_string())
        .arg("-sd")
        .arg(js_dir.path())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("spawn nats-server");
    let _guard = ChildGuard(child);

    let nats_url = format!("nats://127.0.0.1:{port}");
    let mut client_opt = None;
    for _ in 0..40 {
        if let Ok(c) = async_nats::connect(&nats_url).await {
            client_opt = Some(c);
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let client = client_opt.expect("connect to ephemeral nats-server");
    let js = jetstream::new(client.clone());
    js.create_stream(jetstream::stream::Config {
        name: "CAMERA_MEDIA_RESULTS".to_string(),
        subjects: vec!["media.results.vantage.v1".to_string()],
        ..Default::default()
    })
    .await
    .expect("create CAMERA_MEDIA_RESULTS stream");

    let live_subj = "media.live.vantage.vantage_probe_v1.v1";
    let custom_out_subj = "media.results.vantage.probe.out";
    let mut out_sub = client.subscribe(custom_out_subj).await.expect("subscribe");
    client.flush().await.expect("flush");

    let handler = RecordingHandler::new("vantage.probe.v1");
    let invocations = handler.invocations.clone();
    let cfg = WorkerConfig {
        worker_id: "probe-custom-out-1".to_string(),
        capabilities: vec!["vantage.probe.v1".to_string()],
        supported_source_modes: vec![SourceMode::LiveKeyframeTap],
        nats_url: Some(nats_url),
        live_subject_override: Some(live_subj.to_string()),
        result_subject: custom_out_subj.to_string(),
        ..WorkerConfig::default()
    };
    let worker = Arc::new(VantageWorker::new(cfg, handler).expect("worker"));
    let worker_task = tokio::spawn({
        let w = Arc::clone(&worker);
        async move { w.run_until_one().await }
    });

    // Wait for worker readiness, then allow subscription flush to settle
    for _ in 0..40 {
        if worker.readiness().is_ready() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(worker.readiness().is_ready(), "worker never became ready");
    tokio::time::sleep(Duration::from_millis(150)).await;
    let rgb = RgbFrame::solid(64, 64, [20, 140, 220]);
    let jpeg = encode_baseline_jpeg(&rgb, 80).expect("jpeg");
    let frame_payload = serde_json::to_vec(&json!({
        "schema_version": "vantage.frame.v1",
        "source_mode": "live_keyframe_tap",
        "camera_source_id": "22222222-2222-4222-8222-222222222204",
        "stream_profile_id": "33333333-3333-4333-8333-333333333304",
        "frame_sequence": 101,
        "timeline_ts_us": 1700000101000000i64,
        "time_basis": "received",
        "catalog_entry_id": null,
        "fragment_sequence": null,
        "frame_jpeg_b64": base64::engine::general_purpose::STANDARD.encode(&jpeg),
        "detections": [{
            "track_id": "track-1",
            "category": "vehicle",
            "confidence": 0.91,
            "bbox": [0.15, 0.25, 0.85, 0.85]
        }]
    }))
    .expect("frame json");
    client
        .publish(live_subj, frame_payload.into())
        .await
        .expect("publish live frame");
    client.flush().await.expect("flush publish");

    let run_res = tokio::time::timeout(Duration::from_secs(5), worker_task)
        .await
        .unwrap_or_else(|e| {
            let metrics = worker.metrics().render_prometheus_text().unwrap_or_default();
            panic!(
                "run_until_one must not hang on custom result_subject (invocations={}, ready={}): {e}\nmetrics:\n{metrics}",
                invocations.load(Ordering::SeqCst),
                worker.readiness().is_ready()
            )
        })
        .expect("worker task join");
    run_res.expect("run_until_one must succeed");
    assert_eq!(invocations.load(Ordering::SeqCst), 1);

    let msg = tokio::time::timeout(Duration::from_secs(2), out_sub.next())
        .await
        .expect("result message timeout")
        .expect("result message");
    let result_env: VantageResultEnvelope =
        serde_json::from_slice(&msg.payload).expect("valid VantageResultEnvelope");
    assert_eq!(result_env.schema_version, "vantage.result.v1");
    assert_eq!(result_env.source_mode, SourceMode::LiveKeyframeTap);
    assert_eq!(result_env.observations.len(), 1);
    assert_eq!(result_env.observations[0].label, "SR-0100");
}
