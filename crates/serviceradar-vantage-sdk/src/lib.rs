// SPDX-License-Identifier: Apache-2.0

//! Apache-2.0 Rust SDK for external ServiceRadar Vantage computer-vision workers (`vantage.worker.v1`).

#![forbid(unsafe_code)]

pub mod cmaf;
pub mod config;
pub mod crop;
pub mod decode;
pub mod error;
pub mod frame;
pub mod grants;
pub mod harness;
pub mod http_server;
pub mod jpeg;
pub mod metrics;
pub mod protocol;
pub mod worker;

pub use config::{WorkerConfig, detect_architecture};
pub use crop::{
    CropConfig, CropOutcome, CropSkipReason, EncodedCrop, RgbCropOutcome, RoiPolygon,
    crop_detection_in_rois_jpeg, crop_detection_jpeg, crop_detection_rgb, crop_roi_polygon_jpeg,
    crop_roi_polygon_rgb, crop_roi_polygons_jpeg,
};
pub use decode::{
    decode_annex_b_idr, decode_cmaf_keyframe, decode_h264_access_unit, decode_jpeg_to_rgb,
    decode_live_frame_envelope, split_annex_b_nals,
};
pub use error::{VantageError, VantageErrorKind};
pub use frame::{Detection, LumaPlane, ObjectCategory, RgbFrame, clamp_unit_bbox};
pub use grants::{
    BackingSource, BrokerGrantScope, CoalescedRange, FragmentSlicePlan, FragmentStore, GrantClient,
    GrantResolution, HttpControlPlaneGrantClient, HybridGrantStore, InitSlicePlan,
    NvrAnalysisReader, PresignedArchiveReader, RangeSlice, ReadGrantPlan, ReadGrantRequest,
    RedactedPresignedUrl, VerifiedFragmentBytes, VerifiedKeyframeBlock, WorkerAuthCredentials,
    coalesce_fragment_ranges, extract_and_verify_slices, verify_sha256_hex,
};
pub use harness::{HarnessReport, run_local_harness};
pub use http_server::{ReadinessState, build_http_router, serve_http_probes};
pub use jpeg::{
    EncodedThumbnail, ThumbnailConfig, downscale_rgb_fit, encode_baseline_jpeg,
    encode_jpeg_thumbnail, validate_baseline_jfif,
};
pub use metrics::WorkerMetrics;
pub use protocol::{
    CropPolicy, InputMode, LiveFrameCarrier, LiveFramePayloadFormat, MAX_OBSERVATIONS_PER_RESULT,
    MAX_STORED_CROP_JPEG_BYTES, MAX_VANTAGE_JOB_ENVELOPE_BYTES, MAX_VANTAGE_RESULT_ENVELOPE_BYTES,
    ObservationOutput, SampledTarget, SourceMode, TimeBasis, VANTAGE_FRAME_SCHEMA_VERSION,
    VANTAGE_HEARTBEAT_SCHEMA_VERSION, VANTAGE_HEARTBEAT_SUBJECT, VANTAGE_JOB_SCHEMA_VERSION,
    VANTAGE_RESULT_SCHEMA_VERSION, VANTAGE_RESULTS_SUBJECT, VANTAGE_VLM_BACKFILL_SUBJECT,
    VANTAGE_VLM_JOBS_SUBJECT, VANTAGE_WORKER_PROTOCOL_VERSION, VantageFrameContext, VantageHandler,
    VantageJobEnvelope, VantageLiveFrameEnvelope, VantageObservationInput, VantageResultEnvelope,
    VantageUpstreamDetection, VantageWorkerHeartbeat, VlmJobConfig, WorkerCapabilities,
    WorkerHealth, WorkerKind, capability_slug, default_live_pipeline_ids,
    job_subject_for_capability, live_subject_for_capability,
};
pub use worker::VantageWorker;
