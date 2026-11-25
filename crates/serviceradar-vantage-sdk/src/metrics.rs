// SPDX-License-Identifier: Apache-2.0

//! Prometheus metrics exposition for external Vantage workers.

use crate::error::VantageError;
use prometheus::{Encoder, IntCounter, IntCounterVec, IntGauge, Opts, Registry, TextEncoder};

#[derive(Debug)]
pub struct WorkerMetrics {
    registry: Registry,
    jobs_total: IntCounterVec,
    live_frames_total: IntCounterVec,
    observations_total: IntCounter,
    sha256_failures_total: IntCounter,
    active_jobs: IntGauge,
}

impl Default for WorkerMetrics {
    fn default() -> Self {
        Self::new()
    }
}

impl WorkerMetrics {
    pub fn new() -> Self {
        let registry = Registry::new();

        let jobs_total = IntCounterVec::new(
            Opts::new(
                "vantage_worker_jobs_total",
                "Total recorded_block JetStream jobs processed by outcome",
            ),
            &["outcome"],
        )
        .expect("valid metric");
        let live_frames_total = IntCounterVec::new(
            Opts::new(
                "vantage_worker_live_frames_total",
                "Total live_keyframe_tap frames processed by outcome",
            ),
            &["outcome"],
        )
        .expect("valid metric");
        let observations_total = IntCounter::new(
            "vantage_worker_observations_total",
            "Total Vantage observations emitted",
        )
        .expect("valid metric");
        let sha256_failures_total = IntCounter::new(
            "vantage_worker_sha256_failures_total",
            "Total SHA-256 integrity verification failures before decode/callback",
        )
        .expect("valid metric");
        let active_jobs = IntGauge::new(
            "vantage_worker_active_jobs",
            "Currently executing Vantage jobs",
        )
        .expect("valid metric");

        registry.register(Box::new(jobs_total.clone())).ok();
        registry.register(Box::new(live_frames_total.clone())).ok();
        registry.register(Box::new(observations_total.clone())).ok();
        registry
            .register(Box::new(sha256_failures_total.clone()))
            .ok();
        registry.register(Box::new(active_jobs.clone())).ok();

        Self {
            registry,
            jobs_total,
            live_frames_total,
            observations_total,
            sha256_failures_total,
            active_jobs,
        }
    }

    pub fn inc_job(&self, outcome: &str) {
        self.jobs_total.with_label_values(&[outcome]).inc();
    }

    pub fn inc_live_frame(&self, outcome: &str) {
        self.live_frames_total.with_label_values(&[outcome]).inc();
    }

    pub fn add_observations(&self, count: u64) {
        self.observations_total.inc_by(count);
    }

    pub fn inc_sha256_failure(&self) {
        self.sha256_failures_total.inc();
    }

    pub fn set_active_jobs(&self, count: i64) {
        self.active_jobs.set(count);
    }

    pub fn inc_active_jobs(&self) {
        self.active_jobs.inc();
    }

    pub fn dec_active_jobs(&self) {
        self.active_jobs.dec();
    }

    pub fn current_active_jobs(&self) -> u32 {
        u32::try_from(self.active_jobs.get().max(0)).unwrap_or(0)
    }

    pub fn render_prometheus_text(&self) -> Result<String, VantageError> {
        let encoder = TextEncoder::new();
        let families = self.registry.gather();
        let mut buf = Vec::new();
        encoder
            .encode(&families, &mut buf)
            .map_err(|err| VantageError::transport(format!("prometheus encode failed: {err}")))?;
        String::from_utf8(buf)
            .map_err(|err| VantageError::transport(format!("prometheus utf8 failed: {err}")))
    }
}
