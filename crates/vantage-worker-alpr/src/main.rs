// SPDX-License-Identifier: Apache-2.0

use serviceradar_vantage_sdk::{
    SourceMode, VantageError, VantageWorker, WorkerConfig, run_local_harness,
};
use std::path::PathBuf;
use vantage_worker_alpr::{AlprConfig, AlprWorkerHandler};

#[tokio::main]
async fn main() -> Result<(), VantageError> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let mut args = std::env::args().skip(1);
    let mut harness_clip: Option<PathBuf> = None;
    let mut source_mode = SourceMode::RecordedBlock;
    let mut schema_path: Option<PathBuf> = None;
    let mut config_path: Option<PathBuf> = None;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--config" => {
                let p = args.next().ok_or_else(|| {
                    VantageError::invalid_configuration("--config requires a TOML path")
                })?;
                config_path = Some(PathBuf::from(p));
            }
            "--harness" => {
                let p = args.next().ok_or_else(|| {
                    VantageError::invalid_configuration("--harness requires a clip path")
                })?;
                harness_clip = Some(PathBuf::from(p));
            }
            "--source-mode" => {
                let raw = args.next().ok_or_else(|| {
                    VantageError::invalid_configuration("--source-mode requires a value")
                })?;
                source_mode = SourceMode::parse(&raw)?;
            }
            "--schema" => {
                let p = args.next().ok_or_else(|| {
                    VantageError::invalid_configuration("--schema requires a path")
                })?;
                schema_path = Some(PathBuf::from(p));
            }
            other => {
                return Err(VantageError::invalid_configuration(format!(
                    "unknown argument '{other}'"
                )));
            }
        }
    }

    let alpr_cfg = if let Some(path) = config_path {
        let raw = std::fs::read_to_string(&path).map_err(|err| {
            VantageError::invalid_configuration(format!(
                "failed reading config '{}': {err}",
                path.display()
            ))
        })?;
        AlprConfig::from_toml_str(&raw)?
    } else {
        AlprConfig::default()
    };
    let handler = AlprWorkerHandler::new(alpr_cfg);

    if let Some(clip) = harness_clip {
        let report = run_local_harness(clip, &handler, source_mode, schema_path.as_deref())?;
        let json = serde_json::to_string_pretty(&report.result_envelope).map_err(|err| {
            VantageError::protocol(format!("failed serializing harness output: {err}"))
        })?;
        println!("{json}");
        return Ok(());
    }

    let mut config = WorkerConfig::from_env()?;
    if std::env::var("VANTAGE_MODEL_ID").is_err() {
        config.model_id = "vantage-alpr-synthetic-ocr".to_string();
    }
    let worker = VantageWorker::new(config, handler)?;
    worker.run().await
}
