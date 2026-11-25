// SPDX-License-Identifier: Apache-2.0

//! External Vantage worker runtime: JetStream pull (`CAMERA_MEDIA_JOBS`, live before `.backfill.v1`),
//! `live_keyframe_tap` NATS subscriber, periodic heartbeat (`media.workers.heartbeat.v1`),
//! SHA-256 verified read-grant execution, publish-before-ACK (`PublishAckFuture`), and Axum probes.

use crate::cmaf::{parse_init_segment, parse_media_fragment};
use crate::config::WorkerConfig;
use crate::decode::{decode_cmaf_keyframe, decode_live_frame_envelope};
use crate::error::{VantageError, VantageErrorKind};
use crate::frame::ObjectCategory;
use crate::grants::{
    FragmentStore, GrantClient, GrantResolution, HttpControlPlaneGrantClient, HybridGrantStore,
    NvrAnalysisReader, PresignedArchiveReader, ReadGrantRequest,
};
use crate::http_server::{ReadinessState, serve_http_probes};
use crate::metrics::WorkerMetrics;
use crate::protocol::{
    SourceMode, TimeBasis, VANTAGE_HEARTBEAT_SCHEMA_VERSION, VANTAGE_HEARTBEAT_SUBJECT,
    VANTAGE_RESULT_SCHEMA_VERSION, VANTAGE_RESULTS_SUBJECT, VANTAGE_WORKER_PROTOCOL_VERSION,
    VantageFrameContext, VantageHandler, VantageJobEnvelope, VantageLiveFrameEnvelope,
    VantageObservationInput, VantageResultEnvelope, VantageUpstreamDetection,
    VantageWorkerHeartbeat, WorkerHealth, default_live_pipeline_ids, job_subject_for_capability,
    live_subject_for_capability,
};
use async_nats::jetstream::AckKind;
use async_nats::jetstream::consumer::{AckPolicy, Consumer, pull};
use async_nats::{Client, ConnectOptions, HeaderMap, Subscriber, jetstream};
use futures::StreamExt;
use std::collections::HashMap;
use std::sync::{Arc, Once};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::{Semaphore, watch};
use tokio::time::MissedTickBehavior;
use tracing::{debug, info, warn};

/// Runtime orchestrator for Rust and Python external Vantage workers.
pub struct VantageWorker<H: VantageHandler> {
    config: WorkerConfig,
    handler: Arc<H>,
    metrics: Arc<WorkerMetrics>,
    readiness: ReadinessState,
}

impl<H: VantageHandler + 'static> VantageWorker<H> {
    pub fn new(mut config: WorkerConfig, handler: H) -> Result<Self, VantageError> {
        let cap = handler.capability().trim();
        if cap.is_empty() {
            return Err(VantageError::invalid_configuration(
                "VantageHandler::capability() must not be empty",
            ));
        }
        if std::env::var("VANTAGE_CAPABILITIES").is_err()
            && std::env::var("VANTAGE_CAPABILITY").is_err()
            && config.capabilities == ["vantage.alpr.v1"]
            && cap != "vantage.alpr.v1"
        {
            config.capabilities = vec![cap.to_string()];
        }
        config.validate()?;

        let metrics = Arc::new(WorkerMetrics::new());
        let readiness =
            ReadinessState::not_ready(&config.worker_id, "initializing", metrics.clone());
        Ok(Self {
            config,
            handler: Arc::new(handler),
            metrics,
            readiness,
        })
    }

    pub fn config(&self) -> &WorkerConfig {
        &self.config
    }

    pub fn metrics(&self) -> &Arc<WorkerMetrics> {
        &self.metrics
    }

    pub fn readiness(&self) -> &ReadinessState {
        &self.readiness
    }

    /// Runs the worker indefinitely until Ctrl-C / SIGTERM.
    pub async fn run(&self) -> Result<(), VantageError> {
        self.run_with_mode(RunMode::UntilShutdown).await
    }

    /// Runs the worker for `duration`, then gracefully shuts down.
    pub async fn run_for_seconds(&self, duration: Duration) -> Result<(), VantageError> {
        self.run_with_mode(RunMode::ForDuration(duration)).await
    }

    /// Runs until a single job or live frame is processed and published (or shutdown).
    pub async fn run_until_one(&self) -> Result<(), VantageError> {
        self.run_with_mode(RunMode::UntilOne).await
    }

    /// Processes a single `recorded_block` [`VantageJobEnvelope`] end-to-end:
    /// read-grant acquisition -> SHA-256 verification -> CMAF/H.264 decode -> `process_frame` ->
    /// bounded `VantageResultEnvelope` construction.
    ///
    /// Returns `Ok(None)` on `410 Gone` (`recording_gone`), signaling the caller to ACK immediately
    /// without retry.
    pub async fn process_recorded_job<G: GrantClient, S: FragmentStore>(
        &self,
        job: &VantageJobEnvelope,
        grant_client: &G,
        store: &S,
    ) -> Result<Option<VantageResultEnvelope>, VantageError> {
        job.validate()?;
        if job.source_mode != SourceMode::RecordedBlock {
            return Err(VantageError::protocol(format!(
                "process_recorded_job requires source_mode = recorded_block, got {:?}",
                job.source_mode
            )));
        }

        let catalog_entry_id = job
            .catalog_entry_id
            .ok_or_else(|| VantageError::protocol("recorded_block job missing catalog_entry_id"))?;
        let descriptor_sha256 = job.descriptor_sha256.as_deref().ok_or_else(|| {
            VantageError::protocol("recorded_block job missing descriptor_sha256")
        })?;

        let _active_guard = ActiveJobGuard::enter(self.metrics.clone());

        let req = ReadGrantRequest::new(
            job.job_id.to_string(),
            catalog_entry_id.to_string(),
            descriptor_sha256.to_string(),
        );
        let plan = match grant_client.acquire_read_grant(&req).await? {
            GrantResolution::Gone => {
                self.metrics.inc_job("gone");
                return Ok(None);
            }
            GrantResolution::Admitted(plan) => plan,
        };

        let verified = match store.fetch_verified_block(&plan).await {
            Ok(block) => block,
            Err(err) => {
                if matches!(err.kind(), VantageErrorKind::Integrity(_)) {
                    self.metrics.inc_sha256_failure();
                    self.metrics.inc_job("integrity_error");
                } else {
                    self.metrics.inc_job("fetch_error");
                }
                return Err(err);
            }
        };

        let init = parse_init_segment(verified.init_bytes())?;
        let mut target_map: HashMap<u32, Vec<VantageUpstreamDetection>> = HashMap::new();
        let mut ts_by_frag: HashMap<u32, (i64, TimeBasis)> = HashMap::new();
        for target in &job.sampled_targets {
            ts_by_frag
                .entry(target.fragment_sequence)
                .or_insert((target.timeline_ts_us, target.time_basis));
            if let Some(bbox) = target.bbox {
                let category = parse_object_category(&target.category);
                target_map
                    .entry(target.fragment_sequence)
                    .or_default()
                    .push(VantageUpstreamDetection {
                        class_id: category.class_id(),
                        label: category,
                        category: target.category.clone(),
                        confidence: target.confidence,
                        bbox,
                        track_id: target.track_id.clone(),
                        target_key: Some(target.target_key.clone()),
                    });
            }
        }

        let mut wire_observations: Vec<VantageObservationInput> = Vec::new();
        for frag in verified.fragments() {
            let parsed_frag = parse_media_fragment(&frag.bytes, &init)?;
            let rgb_frame = decode_cmaf_keyframe(&init, &parsed_frag)?;
            let media_pts_ns = parsed_frag.media_pts_ns(init.timescale);
            let (timeline_ts_us, time_basis) =
                ts_by_frag.get(&frag.sequence).copied().unwrap_or_else(|| {
                    (
                        i64::try_from(frag.start_ns / 1_000).unwrap_or(0),
                        TimeBasis::Received,
                    )
                });
            let upstream_detections = target_map.remove(&frag.sequence).unwrap_or_default();

            let ctx = VantageFrameContext {
                source_mode: SourceMode::RecordedBlock,
                camera_source_id: job.camera_source_id,
                stream_profile_id: job.stream_profile_id,
                catalog_entry_id: Some(catalog_entry_id),
                fragment_sequence: Some(frag.sequence),
                frame_sequence: u64::from(frag.sequence),
                media_pts_ns: Some(media_pts_ns),
                timeline_ts_us,
                time_basis,
                rgb_frame,
                upstream_detections,
                pipeline_config: job.pipeline_config.clone(),
            };

            let handler = Arc::clone(&self.handler);
            let ctx_for_task = ctx.clone();
            let outputs = tokio::task::spawn_blocking(move || handler.process_frame(&ctx_for_task))
                .await
                .map_err(|err| VantageError::handler(format!("handler task panicked: {err}")))??;

            for (obs_idx, out) in outputs.into_iter().enumerate() {
                wire_observations.push(out.into_wire_observation(
                    &ctx,
                    &job.pipeline_id,
                    obs_idx,
                )?);
            }
        }

        let envelope = VantageResultEnvelope {
            schema_version: VANTAGE_RESULT_SCHEMA_VERSION.to_string(),
            job_id: Some(job.job_id),
            pack_id: job.resolved_pack_id(),
            pipeline_id: job.pipeline_id.clone(),
            pipeline_version: job.pipeline_version.clone(),
            worker_kind: self.config.worker_kind,
            worker_id: self.config.worker_id.clone(),
            model_id: self.config.model_id.clone(),
            model_version: self.config.model_version.clone(),
            capability: job.capability.clone(),
            source_mode: SourceMode::RecordedBlock,
            camera_source_id: job.camera_source_id,
            stream_profile_id: job.stream_profile_id,
            catalog_entry_id: Some(catalog_entry_id),
            descriptor_sha256: Some(descriptor_sha256.to_string()),
            observations: wire_observations,
        };
        envelope.to_bounded_json_bytes()?;
        self.metrics
            .add_observations(envelope.observations.len() as u64);
        self.metrics.inc_job("ok");
        Ok(Some(envelope))
    }

    /// Validates, decodes, and processes a single `live_keyframe_tap` JSON frame payload.
    pub async fn process_live_frame_bytes(
        &self,
        payload: &[u8],
        capability: &str,
    ) -> Result<VantageResultEnvelope, VantageError> {
        let env: VantageLiveFrameEnvelope = serde_json::from_slice(payload).map_err(|err| {
            self.metrics.inc_live_frame("invalid_json");
            VantageError::protocol(format!("invalid vantage.frame.v1 JSON: {err}"))
        })?;

        let rgb_frame = match decode_live_frame_envelope(&env) {
            Ok(frame) => frame,
            Err(err) => {
                self.metrics.inc_live_frame("rejected");
                return Err(err);
            }
        };

        let ctx = VantageFrameContext {
            source_mode: SourceMode::LiveKeyframeTap,
            camera_source_id: env.camera_source_id,
            stream_profile_id: env.stream_profile_id,
            catalog_entry_id: None,
            fragment_sequence: None,
            frame_sequence: env.frame_sequence,
            media_pts_ns: env.media_pts_ns,
            timeline_ts_us: env.timeline_ts_us,
            time_basis: env.time_basis,
            rgb_frame,
            upstream_detections: env.detections,
            pipeline_config: env.pipeline_config.clone(),
        };

        let handler = Arc::clone(&self.handler);
        let ctx_for_task = ctx.clone();
        let outputs = tokio::task::spawn_blocking(move || handler.process_frame(&ctx_for_task))
            .await
            .map_err(|err| VantageError::handler(format!("handler task panicked: {err}")))??;

        let (default_pack, default_pipe) = default_live_pipeline_ids(capability);
        let pack_id = env
            .pipeline_config
            .get("pack_id")
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .unwrap_or(&default_pack)
            .to_string();
        let pipeline_id = env
            .pipeline_config
            .get("pipeline_id")
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .unwrap_or(&default_pipe)
            .to_string();
        let pipeline_version = env
            .pipeline_config
            .get("pipeline_version")
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .unwrap_or("1.0.0")
            .to_string();

        let mut wire_observations = Vec::with_capacity(outputs.len());
        for (obs_idx, out) in outputs.into_iter().enumerate() {
            wire_observations.push(out.into_wire_observation(&ctx, &pipeline_id, obs_idx)?);
        }

        let envelope = VantageResultEnvelope {
            schema_version: VANTAGE_RESULT_SCHEMA_VERSION.to_string(),
            job_id: None,
            pack_id,
            pipeline_id,
            pipeline_version,
            worker_kind: self.config.worker_kind,
            worker_id: self.config.worker_id.clone(),
            model_id: self.config.model_id.clone(),
            model_version: self.config.model_version.clone(),
            capability: capability.to_string(),
            source_mode: SourceMode::LiveKeyframeTap,
            camera_source_id: env.camera_source_id,
            stream_profile_id: env.stream_profile_id,
            catalog_entry_id: None,
            descriptor_sha256: None,
            observations: wire_observations,
        };

        envelope.to_bounded_json_bytes()?;
        self.metrics
            .add_observations(envelope.observations.len() as u64);
        self.metrics.inc_live_frame("ok");
        Ok(envelope)
    }

    pub fn build_heartbeat(
        &self,
        health: WorkerHealth,
    ) -> Result<VantageWorkerHeartbeat, VantageError> {
        let active_jobs = self
            .metrics
            .current_active_jobs()
            .min(self.config.max_concurrency);
        let hb = VantageWorkerHeartbeat {
            schema_version: VANTAGE_HEARTBEAT_SCHEMA_VERSION.to_string(),
            worker_id: self.config.worker_id.clone(),
            worker_kind: self.config.worker_kind,
            protocol_version: VANTAGE_WORKER_PROTOCOL_VERSION.to_string(),
            capabilities: self.config.capabilities.clone(),
            supported_source_modes: self.config.supported_source_modes.clone(),
            execution_backend: self.config.execution_backend.clone(),
            architecture: self.config.architecture.clone(),
            model_id: self.config.model_id.clone(),
            model_version: self.config.model_version.clone(),
            max_concurrency: self.config.max_concurrency,
            active_jobs,
            health,
            sent_at_us: unix_now_us(),
        };
        hb.validate()?;
        Ok(hb)
    }

    async fn run_with_mode(&self, mode: RunMode) -> Result<(), VantageError> {
        ensure_rustls_provider();
        let nats_url = self.config.nats_url.as_deref().ok_or_else(|| {
            VantageError::invalid_configuration(
                "VANTAGE_NATS_URL (or nats_url) must be configured to run VantageWorker",
            )
        })?;

        let (client, js) = connect_nats_and_jetstream(&self.config, nats_url).await?;
        let (shutdown_tx, mut shutdown_rx) = watch::channel(false);

        if let Some(addr) = self.config.http_listen_addr {
            let bound =
                serve_http_probes(addr, self.readiness.clone(), shutdown_rx.clone()).await?;
            info!(worker_id = %self.config.worker_id, %bound, "vantage HTTP probe server listening");
        }

        self.readiness
            .mark_ready(self.config.capabilities_manifest());

        // Publish initial heartbeat immediately and keep refreshing on interval.
        let hb_client = client.clone();
        let hb_metrics = self.metrics.clone();
        let hb_cfg = self.config.clone();
        let mut hb_shutdown = shutdown_rx.clone();
        let hb_task = tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(Duration::from_millis(hb_cfg.heartbeat_interval_ms.max(250)));
            interval.set_missed_tick_behavior(MissedTickBehavior::Skip);
            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        let active = hb_metrics.current_active_jobs().min(hb_cfg.max_concurrency);
                        let hb = VantageWorkerHeartbeat {
                            schema_version: VANTAGE_HEARTBEAT_SCHEMA_VERSION.to_string(),
                            worker_id: hb_cfg.worker_id.clone(),
                            worker_kind: hb_cfg.worker_kind,
                            protocol_version: VANTAGE_WORKER_PROTOCOL_VERSION.to_string(),
                            capabilities: hb_cfg.capabilities.clone(),
                            supported_source_modes: hb_cfg.supported_source_modes.clone(),
                            execution_backend: hb_cfg.execution_backend.clone(),
                            architecture: hb_cfg.architecture.clone(),
                            model_id: hb_cfg.model_id.clone(),
                            model_version: hb_cfg.model_version.clone(),
                            max_concurrency: hb_cfg.max_concurrency,
                            active_jobs: active,
                            health: WorkerHealth::Ready,
                            sent_at_us: unix_now_us(),
                        };
                        if let Ok(bytes) = serde_json::to_vec(&hb) {
                            let _ = hb_client.publish(VANTAGE_HEARTBEAT_SUBJECT, bytes.into()).await;
                        }
                    }
                    _ = hb_shutdown.changed() => {
                        if *hb_shutdown.borrow() {
                            break;
                        }
                    }
                }
            }
        });

        let mut live_subs: Vec<(String, Subscriber)> = Vec::new();
        if self
            .config
            .supported_source_modes
            .contains(&SourceMode::LiveKeyframeTap)
        {
            if let Some(override_subj) = &self.config.live_subject_override {
                let cap = self
                    .config
                    .capabilities
                    .first()
                    .cloned()
                    .unwrap_or_else(|| self.handler.capability().to_string());
                let sub = client
                    .subscribe(override_subj.clone())
                    .await
                    .map_err(|err| {
                        VantageError::nats(format!(
                            "failed subscribing to live subject '{override_subj}': {err}"
                        ))
                    })?;
                live_subs.push((cap, sub));
            } else {
                for cap in &self.config.capabilities {
                    let subj = live_subject_for_capability(cap);
                    let sub = client.subscribe(subj.clone()).await.map_err(|err| {
                        VantageError::nats(format!(
                            "failed subscribing to live subject '{subj}': {err}"
                        ))
                    })?;
                    live_subs.push((cap.clone(), sub));
                }
            }
            client
                .flush()
                .await
                .map_err(|err| VantageError::nats(format!("NATS flush failed: {err}")))?;
        }

        let mut pull_pairs: Vec<(String, Consumer<pull::Config>, Consumer<pull::Config>)> =
            Vec::new();
        if self
            .config
            .supported_source_modes
            .contains(&SourceMode::RecordedBlock)
        {
            match js.get_stream(&self.config.jobs_stream_name).await {
                Ok(stream) => {
                    for cap in &self.config.capabilities {
                        let slug = crate::protocol::capability_slug(cap);
                        let live_subj = job_subject_for_capability(cap, false);
                        let backfill_subj = job_subject_for_capability(cap, true);
                        let live_consumer = ensure_pull_consumer(
                            &stream,
                            &format!("vantage_{slug}_live"),
                            &live_subj,
                            self.config.max_concurrency as usize,
                        )
                        .await?;
                        let backfill_consumer = ensure_pull_consumer(
                            &stream,
                            &format!("vantage_{slug}_backfill"),
                            &backfill_subj,
                            self.config.max_concurrency as usize,
                        )
                        .await?;
                        pull_pairs.push((cap.clone(), live_consumer, backfill_consumer));
                    }
                }
                Err(err) => {
                    if live_subs.is_empty() {
                        return Err(VantageError::nats(format!(
                            "JetStream stream '{}' unavailable: {err}",
                            self.config.jobs_stream_name
                        )));
                    }
                    warn!(
                        stream = %self.config.jobs_stream_name,
                        error = %err,
                        "JetStream jobs stream unavailable; continuing with live_keyframe_tap subscriptions"
                    );
                }
            }
        }

        let grant_client = self.build_grant_client()?;
        let store = self.build_fragment_store();
        let semaphore = Arc::new(Semaphore::new(self.config.max_concurrency.max(1) as usize));

        // Spawn live-tap subscription tasks.
        let (done_tx, mut done_rx) = tokio::sync::mpsc::channel::<()>(16);
        let mut live_tasks = Vec::new();
        for (cap, mut sub) in live_subs {
            let worker = Arc::new(WorkerClone {
                config: self.config.clone(),
                handler: Arc::clone(&self.handler),
                metrics: Arc::clone(&self.metrics),
                readiness: self.readiness.clone(),
            });
            let js_clone = js.clone();
            let client_clone = client.clone();
            let mut sub_shutdown = shutdown_rx.clone();
            let done_tx_clone = done_tx.clone();
            live_tasks.push(tokio::spawn(async move {
                loop {
                    tokio::select! {
                        maybe_msg = sub.next() => {
                            let Some(msg) = maybe_msg else { break; };
                            match worker.process_live_frame_bytes(&msg.payload, &cap).await {
                                Ok(env) => {
                                    if env.observations.is_empty() {
                                        let _ = done_tx_clone.try_send(());
                                        continue;
                                    }
                                    if let Err(err) = publish_result_envelope(
                                        &js_clone,
                                        &client_clone,
                                        &worker.config.result_subject,
                                        &env,
                                        true,
                                    ).await {
                                        warn!(error = %err, "failed publishing live_keyframe_tap result");
                                    } else {
                                        let _ = done_tx_clone.try_send(());
                                    }
                                }
                                Err(err) => {
                                    warn!(error = %err, "rejected invalid live_keyframe_tap frame");
                                }
                            }
                        }
                        _ = sub_shutdown.changed() => {
                            if *sub_shutdown.borrow() {
                                break;
                            }
                        }
                    }
                }
            }));
        }

        // Spawn JetStream pull loop if recorded_block consumers are active.
        let pull_task = if !pull_pairs.is_empty() {
            let worker = Arc::new(WorkerClone {
                config: self.config.clone(),
                handler: Arc::clone(&self.handler),
                metrics: Arc::clone(&self.metrics),
                readiness: self.readiness.clone(),
            });
            let js_clone = js.clone();
            let client_clone = client.clone();
            let grant_clone = grant_client.clone();
            let store_clone = store.clone();
            let sem_clone = semaphore.clone();
            let mut pull_shutdown = shutdown_rx.clone();
            let done_tx_clone = done_tx.clone();

            Some(tokio::spawn(async move {
                loop {
                    if *pull_shutdown.borrow() {
                        break;
                    }
                    let mut pulled_any = false;
                    // Strictly prioritize live jobs before backfill jobs.
                    for (_, live_consumer, _) in &pull_pairs {
                        if sem_clone.available_permits() == 0 {
                            break;
                        }
                        if let Some(msg) = fetch_one_job(live_consumer).await {
                            pulled_any = true;
                            spawn_recorded_job(
                                msg,
                                Arc::clone(&worker),
                                js_clone.clone(),
                                client_clone.clone(),
                                grant_clone.clone(),
                                store_clone.clone(),
                                sem_clone.clone(),
                                done_tx_clone.clone(),
                            );
                        }
                    }
                    if !pulled_any {
                        for (_, _, backfill_consumer) in &pull_pairs {
                            if sem_clone.available_permits() == 0 {
                                break;
                            }
                            if let Some(msg) = fetch_one_job(backfill_consumer).await {
                                pulled_any = true;
                                spawn_recorded_job(
                                    msg,
                                    Arc::clone(&worker),
                                    js_clone.clone(),
                                    client_clone.clone(),
                                    grant_clone.clone(),
                                    store_clone.clone(),
                                    sem_clone.clone(),
                                    done_tx_clone.clone(),
                                );
                            }
                        }
                    }
                    if !pulled_any {
                        tokio::select! {
                            _ = tokio::time::sleep(Duration::from_millis(25)) => {}
                            _ = pull_shutdown.changed() => break,
                        }
                    }
                }
            }))
        } else {
            None
        };

        // Wait according to run mode.
        match mode {
            RunMode::UntilShutdown => {
                let _ = tokio::signal::ctrl_c().await;
            }
            RunMode::ForDuration(dur) => {
                tokio::select! {
                    _ = tokio::time::sleep(dur) => {}
                    _ = shutdown_rx.changed() => {}
                }
            }
            RunMode::UntilOne => {
                tokio::select! {
                    _ = done_rx.recv() => {}
                    _ = tokio::signal::ctrl_c() => {}
                }
            }
        }

        self.readiness.mark_draining("shutdown");
        let _ = shutdown_tx.send(true);
        let _ = client.flush().await;

        hb_task.abort();
        for task in live_tasks {
            let _ = tokio::time::timeout(Duration::from_millis(250), task).await;
        }
        if let Some(pt) = pull_task {
            let _ = tokio::time::timeout(Duration::from_millis(250), pt).await;
        }

        Ok(())
    }

    fn build_grant_client(&self) -> Result<Option<HttpControlPlaneGrantClient>, VantageError> {
        match (
            &self.config.control_plane_url,
            &self.config.control_plane_auth,
        ) {
            (Some(url), Some(auth)) => Ok(Some(HttpControlPlaneGrantClient::new(
                url.clone(),
                auth.clone(),
                Duration::from_secs(15),
            ))),
            _ => Ok(None),
        }
    }

    fn build_fragment_store(&self) -> HybridGrantStore {
        HybridGrantStore {
            archive_reader: PresignedArchiveReader::default(),
            local_reader: NvrAnalysisReader {
                scheme: self.config.nvr_scheme.clone(),
                port: self.config.nvr_port,
                timeout: Duration::from_secs(10),
                explicit_base_url: self.config.nvr_explicit_base_url.clone(),
                host_suffix: self.config.nvr_host_suffix.clone(),
                tls_ca_file: self.config.nvr_tls_ca_file.clone(),
                tls_cert_file: self.config.nvr_tls_cert_file.clone(),
                tls_key_file: self.config.nvr_tls_key_file.clone(),
                auth_token_file: self.config.nvr_auth_token_file.clone(),
            },
        }
    }
}

enum RunMode {
    UntilShutdown,
    ForDuration(Duration),
    UntilOne,
}

struct WorkerClone<H: VantageHandler> {
    config: WorkerConfig,
    handler: Arc<H>,
    metrics: Arc<WorkerMetrics>,
    readiness: ReadinessState,
}

impl<H: VantageHandler + 'static> WorkerClone<H> {
    async fn process_live_frame_bytes(
        &self,
        payload: &[u8],
        capability: &str,
    ) -> Result<VantageResultEnvelope, VantageError> {
        let tmp = VantageWorker {
            config: self.config.clone(),
            handler: Arc::clone(&self.handler),
            metrics: Arc::clone(&self.metrics),
            readiness: self.readiness.clone(),
        };
        tmp.process_live_frame_bytes(payload, capability).await
    }

    async fn process_recorded_job<G: GrantClient, S: FragmentStore>(
        &self,
        job: &VantageJobEnvelope,
        grant_client: &G,
        store: &S,
    ) -> Result<Option<VantageResultEnvelope>, VantageError> {
        let tmp = VantageWorker {
            config: self.config.clone(),
            handler: Arc::clone(&self.handler),
            metrics: Arc::clone(&self.metrics),
            readiness: self.readiness.clone(),
        };
        tmp.process_recorded_job(job, grant_client, store).await
    }
}

async fn fetch_one_job(consumer: &Consumer<pull::Config>) -> Option<jetstream::Message> {
    let Ok(mut batch) = consumer
        .fetch()
        .max_messages(1)
        .expires(Duration::from_millis(100))
        .messages()
        .await
    else {
        return None;
    };
    match batch.next().await {
        Some(Ok(msg)) => Some(msg),
        _ => None,
    }
}

#[allow(clippy::too_many_arguments)]
fn spawn_recorded_job<H: VantageHandler + 'static>(
    msg: jetstream::Message,
    worker: Arc<WorkerClone<H>>,
    js: jetstream::Context,
    client: Client,
    grant_client: Option<HttpControlPlaneGrantClient>,
    store: HybridGrantStore,
    semaphore: Arc<Semaphore>,
    done_tx: tokio::sync::mpsc::Sender<()>,
) {
    tokio::spawn(async move {
        let Ok(_permit) = semaphore.acquire_owned().await else {
            return;
        };
        let Some(grant_client) = grant_client else {
            warn!("recorded_block job received without control_plane_url/auth; NAKing");
            let _ = msg.ack_with(AckKind::Nak(None)).await;
            return;
        };
        let job: VantageJobEnvelope = match serde_json::from_slice(&msg.payload) {
            Ok(j) => j,
            Err(err) => {
                warn!(error = %err, "invalid vantage.job.v1 payload; ACKing poison pill");
                let _ = msg.ack().await;
                return;
            }
        };

        // Send periodic AckKind::Progress heartbeats while processing.
        let (prog_tx, mut prog_rx) = watch::channel(false);
        let prog_msg = msg.clone();
        let prog_task = tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(15));
            interval.tick().await;
            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        let _ = prog_msg.ack_with(AckKind::Progress).await;
                    }
                    _ = prog_rx.changed() => {
                        if *prog_rx.borrow() {
                            break;
                        }
                    }
                }
            }
        });

        let res = worker
            .process_recorded_job(&job, &grant_client, &store)
            .await;
        let _ = prog_tx.send(true);
        prog_task.abort();

        match res {
            Ok(None) => {
                // 410 Gone (recording_gone): ACK immediately without retry.
                let _ = msg.ack().await;
                let _ = done_tx.try_send(());
            }
            Ok(Some(env)) => {
                // Publish-before-ACK: await PublishAckFuture BEFORE calling msg.ack().
                match publish_result_envelope(
                    &js,
                    &client,
                    &worker.config.result_subject,
                    &env,
                    false,
                )
                .await
                {
                    Ok(()) => {
                        let _ = msg.ack().await;
                        let _ = done_tx.try_send(());
                    }
                    Err(err) => {
                        warn!(error = %err, job_id = %job.job_id, "publish failed; NAKing job");
                        let _ = msg
                            .ack_with(AckKind::Nak(Some(Duration::from_secs(2))))
                            .await;
                    }
                }
            }
            Err(err) => {
                warn!(error = %err, job_id = %job.job_id, "recorded_block job failed");
                if matches!(
                    err.kind(),
                    VantageErrorKind::Integrity(_) | VantageErrorKind::Protocol(_)
                ) {
                    let _ = msg.ack_with(AckKind::Term).await;
                } else {
                    let _ = msg
                        .ack_with(AckKind::Nak(Some(Duration::from_secs(2))))
                        .await;
                }
            }
        }
    });
}

async fn publish_result_envelope(
    js: &jetstream::Context,
    client: &Client,
    subject: &str,
    envelope: &VantageResultEnvelope,
    allow_core_fallback_on_custom_subject: bool,
) -> Result<(), VantageError> {
    let bytes = envelope.to_bounded_json_bytes()?;
    let msg_id = envelope
        .observations
        .first()
        .map(|o| o.observation_key.clone())
        .or_else(|| envelope.job_id.map(|id| id.to_string()))
        .unwrap_or_else(|| format!("live-{}", envelope.camera_source_id));

    let mut headers = HeaderMap::new();
    headers.insert("Nats-Msg-Id", msg_id.as_str());

    match js
        .publish_with_headers(subject.to_string(), headers.clone(), bytes.clone().into())
        .await
    {
        Ok(ack_fut) => {
            ack_fut.await.map_err(|err| {
                VantageError::nats(format!("JetStream PublishAck failed on '{subject}': {err}"))
            })?;
            Ok(())
        }
        Err(err) if allow_core_fallback_on_custom_subject && subject != VANTAGE_RESULTS_SUBJECT => {
            debug!(
                subject,
                error = %err,
                "custom result_subject has no JetStream stream; falling back to core NATS publish"
            );
            client
                .publish_with_headers(subject.to_string(), headers, bytes.into())
                .await
                .map_err(|pub_err| {
                    VantageError::nats(format!(
                        "core NATS publish failed on '{subject}': {pub_err}"
                    ))
                })?;
            client.flush().await.map_err(|flush_err| {
                VantageError::nats(format!("NATS flush failed: {flush_err}"))
            })?;
            Ok(())
        }
        Err(err) => Err(VantageError::nats(format!(
            "JetStream publish failed on '{subject}': {err}"
        ))),
    }
}

async fn connect_nats_and_jetstream(
    config: &WorkerConfig,
    nats_url: &str,
) -> Result<(Client, jetstream::Context), VantageError> {
    let mut options = ConnectOptions::new();

    if let Some(creds_file) = &config.nats_creds_file {
        options = options.credentials_file(creds_file).await.map_err(|err| {
            VantageError::nats(format!(
                "failed loading NATS creds file {}: {err}",
                creds_file.display()
            ))
        })?;
    }

    let has_tls = config.nats_tls_ca_file.is_some()
        || (config.nats_tls_cert_file.is_some() && config.nats_tls_key_file.is_some());
    if has_tls {
        options = options.require_tls(true);
    }
    if let Some(ca) = &config.nats_tls_ca_file {
        options = options.add_root_certificates(ca.to_path_buf());
    }
    if let (Some(cert), Some(key)) = (&config.nats_tls_cert_file, &config.nats_tls_key_file) {
        options = options.add_client_certificate(cert.to_path_buf(), key.to_path_buf());
    }

    let client = async_nats::connect_with_options(nats_url, options)
        .await
        .map_err(|err| VantageError::nats(format!("NATS connect to '{nats_url}' failed: {err}")))?;
    let js = jetstream::new(client.clone());
    Ok((client, js))
}

async fn ensure_pull_consumer(
    stream: &jetstream::stream::Stream,
    durable_name: &str,
    filter_subject: &str,
    concurrency: usize,
) -> Result<Consumer<pull::Config>, VantageError> {
    let cfg = pull::Config {
        durable_name: Some(durable_name.to_string()),
        filter_subject: filter_subject.to_string(),
        ack_policy: AckPolicy::Explicit,
        ack_wait: Duration::from_secs(60),
        max_deliver: 5,
        max_ack_pending: (concurrency.max(1) * 4) as i64,
        ..Default::default()
    };
    stream
        .get_or_create_consumer(durable_name, cfg)
        .await
        .map_err(|err| {
            VantageError::nats(format!(
                "failed creating JetStream pull consumer '{durable_name}': {err}"
            ))
        })
}

fn parse_object_category(raw: &str) -> ObjectCategory {
    match raw.trim().to_ascii_lowercase().as_str() {
        "person" => ObjectCategory::Person,
        "vehicle" | "car" | "truck" | "bus" | "motorcycle" => ObjectCategory::Vehicle,
        "bicycle" | "bike" => ObjectCategory::Bicycle,
        "animal" => ObjectCategory::Animal,
        "package" => ObjectCategory::Package,
        "motion" => ObjectCategory::Motion,
        _ => ObjectCategory::Vehicle,
    }
}

struct ActiveJobGuard {
    metrics: Arc<WorkerMetrics>,
}

impl ActiveJobGuard {
    fn enter(metrics: Arc<WorkerMetrics>) -> Self {
        metrics.inc_active_jobs();
        Self { metrics }
    }
}

impl Drop for ActiveJobGuard {
    fn drop(&mut self) {
        self.metrics.dec_active_jobs();
    }
}

fn ensure_rustls_provider() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

fn unix_now_us() -> i64 {
    let dur = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO);
    i64::try_from(dur.as_micros()).unwrap_or(i64::MAX)
}
