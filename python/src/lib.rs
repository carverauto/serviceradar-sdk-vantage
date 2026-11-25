// SPDX-License-Identifier: Apache-2.0

//! PyO3 (`0.30.1`) + `numpy` (`0.30.0`) bindings for `serviceradar-vantage-sdk`.

use ndarray::Array3;
use numpy::{IntoPyArray, PyArray3};
use parking_lot::Mutex;
use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyBool, PyDict, PyFloat, PyInt, PyList, PyString};
use serviceradar_vantage_sdk::{
    ObservationOutput, SourceMode, TimeBasis, VantageError, VantageFrameContext, VantageHandler,
    VantageWorker as RustVantageWorker, WorkerCapabilities as RustWorkerCapabilities, WorkerConfig,
    WorkerKind,
};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

#[pyclass(module = "serviceradar_vantage._serviceradar_vantage")]
pub struct FrameContext {
    source_mode: String,
    camera_source_id: String,
    stream_profile_id: String,
    catalog_entry_id: Option<String>,
    fragment_sequence: Option<u32>,
    frame_sequence: u64,
    media_pts_ns: Option<u64>,
    timeline_ts_us: i64,
    time_basis: String,
    upstream_detections_json: serde_json::Value,
    pipeline_config_json: serde_json::Value,
    raw_pixels: Mutex<Option<(usize, usize, Vec<u8>)>>,
    cached_py_array: Mutex<Option<Py<PyArray3<u8>>>>,
    buffer_ptr: AtomicUsize,
}

impl FrameContext {
    fn from_rust(ctx: &VantageFrameContext) -> Self {
        let h = ctx.rgb_frame.height() as usize;
        let w = ctx.rgb_frame.width() as usize;
        let pixels = ctx.rgb_frame.pixels().to_vec();
        let ptr = pixels.as_ptr() as usize;
        let detections_json = serde_json::to_value(&ctx.upstream_detections)
            .unwrap_or(serde_json::Value::Array(vec![]));
        Self {
            source_mode: ctx.source_mode.as_str().to_string(),
            camera_source_id: ctx.camera_source_id.to_string(),
            stream_profile_id: ctx.stream_profile_id.to_string(),
            catalog_entry_id: ctx.catalog_entry_id.map(|u| u.to_string()),
            fragment_sequence: ctx.fragment_sequence,
            frame_sequence: ctx.frame_sequence,
            media_pts_ns: ctx.media_pts_ns,
            timeline_ts_us: ctx.timeline_ts_us,
            time_basis: ctx.time_basis.as_str().to_string(),
            upstream_detections_json: detections_json,
            pipeline_config_json: ctx.pipeline_config.clone(),
            raw_pixels: Mutex::new(Some((h, w, pixels))),
            cached_py_array: Mutex::new(None),
            buffer_ptr: AtomicUsize::new(ptr),
        }
    }
}

#[pymethods]
impl FrameContext {
    #[getter]
    fn source_mode(&self) -> &str {
        &self.source_mode
    }

    #[getter]
    fn camera_source_id(&self) -> &str {
        &self.camera_source_id
    }

    #[getter]
    fn stream_profile_id(&self) -> &str {
        &self.stream_profile_id
    }

    #[getter]
    fn catalog_entry_id(&self) -> Option<&str> {
        self.catalog_entry_id.as_deref()
    }

    #[getter]
    fn fragment_sequence(&self) -> Option<u32> {
        self.fragment_sequence
    }

    #[getter]
    fn frame_sequence(&self) -> u64 {
        self.frame_sequence
    }

    #[getter]
    fn media_pts_ns(&self) -> Option<u64> {
        self.media_pts_ns
    }

    #[getter]
    fn timeline_ts_us(&self) -> i64 {
        self.timeline_ts_us
    }

    #[getter]
    fn time_basis(&self) -> &str {
        &self.time_basis
    }

    #[getter]
    fn upstream_detections(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        json_to_py(py, &self.upstream_detections_json)
    }

    #[getter]
    fn pipeline_config(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        json_to_py(py, &self.pipeline_config_json)
    }

    /// Zero-copy `(H, W, 3)` `uint8` C-contiguous NumPy array backed by the Rust `Vec<u8>` buffer.
    #[getter]
    fn rgb_frame(&self, py: Python<'_>) -> PyResult<Py<PyArray3<u8>>> {
        if let Some(cached) = self.cached_py_array.lock().as_ref() {
            return Ok(cached.clone_ref(py));
        }

        let Some((height, width, pixels)) = self.raw_pixels.lock().take() else {
            return Err(PyRuntimeError::new_err("rgb_frame buffer already consumed"));
        };
        let ptr = pixels.as_ptr() as usize;
        self.buffer_ptr.store(ptr, Ordering::Relaxed);

        let arr = Array3::from_shape_vec((height, width, 3), pixels)
            .map_err(|err| PyValueError::new_err(format!("rgb_frame shape error: {err}")))?;
        let py_arr: Py<PyArray3<u8>> = arr.into_pyarray(py).unbind();
        *self.cached_py_array.lock() = Some(py_arr.clone_ref(py));
        Ok(py_arr)
    }

    /// Returns the Rust heap buffer pointer address (`Vec::as_ptr()`) for zero-copy verification.
    fn _debug_buffer_ptr(&self) -> usize {
        self.buffer_ptr.load(Ordering::Relaxed)
    }
}

#[pyclass(module = "serviceradar_vantage._serviceradar_vantage")]
#[derive(Clone)]
pub struct Observation {
    #[pyo3(get, set)]
    pub observation_key: Option<String>,
    #[pyo3(get, set)]
    pub fragment_sequence: Option<u32>,
    #[pyo3(get, set)]
    pub frame_sequence: Option<u64>,
    #[pyo3(get, set)]
    pub media_pts_ns: Option<u64>,
    #[pyo3(get, set)]
    pub timeline_ts_us: Option<i64>,
    #[pyo3(get, set)]
    pub time_basis: Option<String>,
    #[pyo3(get, set)]
    pub track_id: Option<String>,
    #[pyo3(get, set)]
    pub category: String,
    #[pyo3(get, set)]
    pub label: String,
    #[pyo3(get, set)]
    pub confidence: f32,
    #[pyo3(get, set)]
    pub bbox: Option<[f32; 4]>,
    #[pyo3(get, set)]
    pub crop_jpeg_b64: Option<String>,
    attributes_json: serde_json::Value,
    #[pyo3(get, set)]
    pub signal_schema_id: String,
    #[pyo3(get, set)]
    pub signal_schema_version: String,
    #[pyo3(get, set)]
    pub display_contract_id: String,
    #[pyo3(get, set)]
    pub search_text: Option<String>,
}

#[pymethods]
impl Observation {
    #[new]
    #[pyo3(signature = (
        category,
        label,
        confidence,
        bbox=None,
        signal_schema_id="generic",
        signal_schema_version="1.0.0",
        display_contract_id=None,
        attributes=None,
        search_text=None,
        observation_key=None,
        fragment_sequence=None,
        frame_sequence=None,
        media_pts_ns=None,
        timeline_ts_us=None,
        time_basis=None,
        track_id=None,
        crop_jpeg_b64=None,
    ))]
    #[allow(clippy::too_many_arguments)]
    fn new(
        category: String,
        label: String,
        confidence: f32,
        bbox: Option<[f32; 4]>,
        signal_schema_id: &str,
        signal_schema_version: &str,
        display_contract_id: Option<String>,
        attributes: Option<Bound<'_, PyAny>>,
        search_text: Option<String>,
        observation_key: Option<String>,
        fragment_sequence: Option<u32>,
        frame_sequence: Option<u64>,
        media_pts_ns: Option<u64>,
        timeline_ts_us: Option<i64>,
        time_basis: Option<String>,
        track_id: Option<String>,
        crop_jpeg_b64: Option<String>,
    ) -> PyResult<Self> {
        let attrs_json = match attributes {
            Some(obj) => py_to_json(&obj)?,
            None => serde_json::json!({}),
        };
        let display_id = display_contract_id.unwrap_or_else(|| signal_schema_id.to_string());
        Ok(Self {
            observation_key,
            fragment_sequence,
            frame_sequence,
            media_pts_ns,
            timeline_ts_us,
            time_basis,
            track_id,
            category,
            label,
            confidence,
            bbox,
            crop_jpeg_b64,
            attributes_json: attrs_json,
            signal_schema_id: signal_schema_id.to_string(),
            signal_schema_version: signal_schema_version.to_string(),
            display_contract_id: display_id,
            search_text,
        })
    }

    #[getter]
    fn attributes(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        json_to_py(py, &self.attributes_json)
    }

    #[setter]
    fn set_attributes(&mut self, value: Bound<'_, PyAny>) -> PyResult<()> {
        self.attributes_json = py_to_json(&value)?;
        Ok(())
    }
}

impl Observation {
    fn into_rust(self, ctx: &VantageFrameContext) -> Result<ObservationOutput, VantageError> {
        let time_basis = match self.time_basis.as_deref() {
            Some(raw) => TimeBasis::parse(raw)?,
            None => ctx.time_basis,
        };
        let search_text = self
            .search_text
            .unwrap_or_else(|| format!("{} {}", self.label, self.category));
        Ok(ObservationOutput {
            observation_key: self.observation_key.unwrap_or_default(),
            fragment_sequence: self.fragment_sequence.or(ctx.fragment_sequence),
            frame_sequence: self.frame_sequence.unwrap_or(ctx.frame_sequence),
            media_pts_ns: self.media_pts_ns.or(ctx.media_pts_ns),
            timeline_ts_us: self.timeline_ts_us.unwrap_or(ctx.timeline_ts_us),
            time_basis,
            track_id: self.track_id,
            category: self.category,
            label: self.label,
            confidence: self.confidence,
            bbox: self.bbox,
            crop_jpeg_b64: self.crop_jpeg_b64,
            attributes: self.attributes_json,
            signal_schema_id: self.signal_schema_id,
            signal_schema_version: self.signal_schema_version,
            display_contract_id: self.display_contract_id,
            search_text,
        })
    }
}

#[pyclass(module = "serviceradar_vantage._serviceradar_vantage")]
#[derive(Clone)]
pub struct WorkerCapabilities {
    #[pyo3(get)]
    pub capabilities: Vec<String>,
    #[pyo3(get)]
    pub supported_source_modes: Vec<String>,
    #[pyo3(get)]
    pub execution_backend: String,
    #[pyo3(get)]
    pub model_id: String,
    #[pyo3(get)]
    pub model_version: String,
    #[pyo3(get)]
    pub max_concurrency: u32,
}

#[pymethods]
impl WorkerCapabilities {
    #[new]
    #[pyo3(signature = (
        capabilities,
        supported_source_modes=None,
        execution_backend="custom",
        model_id="vantage-worker-default",
        model_version="1.0.0",
        max_concurrency=4,
    ))]
    fn new(
        capabilities: Vec<String>,
        supported_source_modes: Option<Vec<String>>,
        execution_backend: &str,
        model_id: &str,
        model_version: &str,
        max_concurrency: u32,
    ) -> PyResult<Self> {
        let modes = supported_source_modes.unwrap_or_else(|| {
            vec![
                "recorded_block".to_string(),
                "live_keyframe_tap".to_string(),
            ]
        });
        let mut parsed_modes = Vec::with_capacity(modes.len());
        for m in &modes {
            parsed_modes.push(SourceMode::parse(m).map_err(vantage_err_to_py)?);
        }
        let rust_caps = RustWorkerCapabilities {
            capabilities: capabilities.clone(),
            supported_source_modes: parsed_modes,
            execution_backend: execution_backend.to_string(),
            model_id: model_id.to_string(),
            model_version: model_version.to_string(),
            max_concurrency,
        };
        rust_caps.validate().map_err(vantage_err_to_py)?;
        Ok(Self {
            capabilities,
            supported_source_modes: modes,
            execution_backend: execution_backend.to_string(),
            model_id: model_id.to_string(),
            model_version: model_version.to_string(),
            max_concurrency,
        })
    }
}

#[derive(FromPyObject)]
enum CapabilitiesInput {
    Object(Py<WorkerCapabilities>),
    List(Vec<String>),
}

struct PyCallableHandler {
    capability: String,
    callable: Py<PyAny>,
}

impl VantageHandler for PyCallableHandler {
    fn capability(&self) -> &str {
        &self.capability
    }

    fn process_frame(
        &self,
        ctx: &VantageFrameContext,
    ) -> Result<Vec<ObservationOutput>, VantageError> {
        Python::attach(|py| {
            let py_ctx = Py::new(py, FrameContext::from_rust(ctx)).map_err(|err| {
                VantageError::handler(format!("failed constructing FrameContext: {err}"))
            })?;
            let result = self.callable.bind(py).call1((py_ctx,)).map_err(|err| {
                VantageError::handler(format!("python process_frame raised: {err}"))
            })?;
            extract_observations(py, &result, ctx)
        })
    }
}

#[pyclass(module = "serviceradar_vantage._serviceradar_vantage")]
pub struct VantageWorker {
    worker: Arc<RustVantageWorker<PyCallableHandler>>,
}

#[pymethods]
impl VantageWorker {
    #[new]
    #[pyo3(signature = (
        handler=None,
        worker_id=None,
        capabilities=None,
        supported_source_modes=None,
        execution_backend=None,
        model_id=None,
        model_version=None,
        max_concurrency=None,
        nats_url=None,
        control_plane_url=None,
        control_plane_auth=None,
        deployment_ref=None,
        worker_generation=None,
        live_subject=None,
        result_subject=None,
        http_listen_addr=None,
    ))]
    #[allow(clippy::too_many_arguments)]
    fn new(
        py: Python<'_>,
        handler: Option<Py<PyAny>>,
        worker_id: Option<String>,
        capabilities: Option<CapabilitiesInput>,
        supported_source_modes: Option<Vec<String>>,
        execution_backend: Option<String>,
        model_id: Option<String>,
        model_version: Option<String>,
        max_concurrency: Option<u32>,
        nats_url: Option<String>,
        control_plane_url: Option<String>,
        control_plane_auth: Option<String>,
        deployment_ref: Option<String>,
        worker_generation: Option<String>,
        live_subject: Option<String>,
        result_subject: Option<String>,
        http_listen_addr: Option<String>,
    ) -> PyResult<Self> {
        let callable =
            handler.ok_or_else(|| PyValueError::new_err("handler callable is required"))?;
        if !callable.bind(py).is_callable() {
            return Err(PyValueError::new_err("handler must be callable"));
        }

        let mut cfg = WorkerConfig::from_env().unwrap_or_default();
        cfg.worker_kind = WorkerKind::ExternalPython;

        if let Some(id) = worker_id {
            cfg.worker_id = id;
        }
        match capabilities {
            Some(CapabilitiesInput::Object(cap_obj)) => {
                let cap_ref = cap_obj.borrow(py);
                cfg.capabilities = cap_ref.capabilities.clone();
                let mut modes = Vec::with_capacity(cap_ref.supported_source_modes.len());
                for raw in &cap_ref.supported_source_modes {
                    modes.push(SourceMode::parse(raw).map_err(vantage_err_to_py)?);
                }
                cfg.supported_source_modes = modes;
                cfg.execution_backend = cap_ref.execution_backend.clone();
                cfg.model_id = cap_ref.model_id.clone();
                cfg.model_version = cap_ref.model_version.clone();
                cfg.max_concurrency = cap_ref.max_concurrency;
            }
            Some(CapabilitiesInput::List(caps)) => {
                cfg.capabilities = caps;
            }
            None => {}
        }
        if let Some(modes_raw) = supported_source_modes {
            let mut modes = Vec::with_capacity(modes_raw.len());
            for raw in modes_raw {
                modes.push(SourceMode::parse(&raw).map_err(vantage_err_to_py)?);
            }
            cfg.supported_source_modes = modes;
        }
        if let Some(backend) = execution_backend {
            cfg.execution_backend = backend;
        }
        if let Some(id) = model_id {
            cfg.model_id = id;
        }
        if let Some(ver) = model_version {
            cfg.model_version = ver;
        }
        if let Some(conc) = max_concurrency {
            cfg.max_concurrency = conc;
        }
        if let Some(url) = nats_url {
            cfg.nats_url = Some(url);
        }
        if let Some(url) = control_plane_url {
            cfg.control_plane_url = Some(url);
        }
        if let Some(tok) = control_plane_auth {
            let deploy = deployment_ref
                .unwrap_or_else(|| "00000000-0000-4000-8000-000000000000".to_string());
            let generation = worker_generation.unwrap_or_else(|| "1".to_string());
            cfg.control_plane_auth = Some(serviceradar_vantage_sdk::WorkerAuthCredentials::new(
                tok, deploy, generation,
            ));
        }
        if let Some(subj) = live_subject {
            cfg.live_subject_override = Some(subj);
        }
        if let Some(subj) = result_subject {
            cfg.result_subject = subj;
        }
        if let Some(addr) = http_listen_addr {
            cfg.http_listen_addr =
                Some(addr.parse().map_err(|e| {
                    PyValueError::new_err(format!("invalid http_listen_addr: {e}"))
                })?);
        }

        let primary_cap = cfg
            .capabilities
            .first()
            .cloned()
            .unwrap_or_else(|| "vantage.alpr.v1".to_string());
        let py_handler = PyCallableHandler {
            capability: primary_cap,
            callable,
        };
        let worker = RustVantageWorker::new(cfg, py_handler).map_err(vantage_err_to_py)?;
        Ok(Self {
            worker: Arc::new(worker),
        })
    }

    #[getter]
    fn worker_id(&self) -> &str {
        &self.worker.config().worker_id
    }

    #[getter]
    fn capabilities(&self) -> Vec<String> {
        self.worker.config().capabilities.clone()
    }

    fn run(&self, py: Python<'_>) -> PyResult<()> {
        let worker = Arc::clone(&self.worker);
        py.detach(move || {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .map_err(|err| PyRuntimeError::new_err(format!("tokio runtime error: {err}")))?;
            rt.block_on(worker.run()).map_err(vantage_err_to_py)
        })
    }

    fn run_forever(&self, py: Python<'_>) -> PyResult<()> {
        self.run(py)
    }

    fn run_for_seconds(&self, py: Python<'_>, seconds: f64) -> PyResult<()> {
        if !seconds.is_finite() || seconds < 0.0 {
            return Err(PyValueError::new_err("seconds must be finite and >= 0"));
        }
        let worker = Arc::clone(&self.worker);
        let dur = Duration::from_secs_f64(seconds);
        py.detach(move || {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .map_err(|err| PyRuntimeError::new_err(format!("tokio runtime error: {err}")))?;
            rt.block_on(worker.run_for_seconds(dur))
                .map_err(vantage_err_to_py)
        })
    }

    fn run_until_one(&self, py: Python<'_>) -> PyResult<()> {
        let worker = Arc::clone(&self.worker);
        py.detach(move || {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .map_err(|err| PyRuntimeError::new_err(format!("tokio runtime error: {err}")))?;
            rt.block_on(worker.run_until_one())
                .map_err(vantage_err_to_py)
        })
    }
}

#[pyfunction]
#[pyo3(signature = (clip_path, handler, schema_path=None, source_mode="recorded_block"))]
fn run_local_harness(
    py: Python<'_>,
    clip_path: String,
    handler: Py<PyAny>,
    schema_path: Option<String>,
    source_mode: &str,
) -> PyResult<Py<PyAny>> {
    if !handler.bind(py).is_callable() {
        return Err(PyValueError::new_err("handler must be callable"));
    }
    let parsed_mode = SourceMode::parse(source_mode).map_err(vantage_err_to_py)?;
    let py_handler = PyCallableHandler {
        capability: "vantage.local.v1".to_string(),
        callable: handler,
    };
    let schema_pb = schema_path.map(PathBuf::from);
    let report = py
        .detach(move || {
            serviceradar_vantage_sdk::run_local_harness(
                clip_path,
                &py_handler,
                parsed_mode,
                schema_pb.as_deref(),
            )
        })
        .map_err(vantage_err_to_py)?;

    let report_json = serde_json::to_value(&report).map_err(|err| {
        PyRuntimeError::new_err(format!("failed serializing harness report: {err}"))
    })?;
    json_to_py(py, &report_json)
}

fn extract_observations(
    _py: Python<'_>,
    obj: &Bound<'_, PyAny>,
    ctx: &VantageFrameContext,
) -> Result<Vec<ObservationOutput>, VantageError> {
    if obj.is_none() {
        return Ok(Vec::new());
    }
    let list = obj.cast::<PyList>().map_err(|_| {
        VantageError::handler("python process_frame must return a list of Observation or dict")
    })?;
    let mut out = Vec::with_capacity(list.len());
    for item in list.iter() {
        if let Ok(obs) = item.cast::<Observation>() {
            out.push(obs.borrow().clone().into_rust(ctx)?);
            continue;
        }
        if let Ok(dict) = item.cast::<PyDict>() {
            out.push(dict_to_observation(dict, ctx)?);
            continue;
        }
        return Err(VantageError::handler(
            "each observation returned by process_frame must be sv.Observation or dict",
        ));
    }
    Ok(out)
}

fn dict_to_observation(
    dict: &Bound<'_, PyDict>,
    ctx: &VantageFrameContext,
) -> Result<ObservationOutput, VantageError> {
    let get_str = |key: &str| -> Result<Option<String>, VantageError> {
        match dict
            .get_item(key)
            .map_err(|e| VantageError::handler(e.to_string()))?
        {
            Some(v) if !v.is_none() => v
                .extract::<String>()
                .map(Some)
                .map_err(|e| VantageError::handler(format!("field '{key}' must be str: {e}"))),
            _ => Ok(None),
        }
    };
    let category = get_str("category")?
        .ok_or_else(|| VantageError::handler("observation dict missing 'category'"))?;
    let label = get_str("label")?
        .ok_or_else(|| VantageError::handler("observation dict missing 'label'"))?;
    let confidence = dict
        .get_item("confidence")
        .map_err(|e| VantageError::handler(e.to_string()))?
        .ok_or_else(|| VantageError::handler("observation dict missing 'confidence'"))?
        .extract::<f32>()
        .map_err(|e| VantageError::handler(format!("field 'confidence' must be float: {e}")))?;

    let bbox =
        match dict
            .get_item("bbox")
            .map_err(|e| VantageError::handler(e.to_string()))?
        {
            Some(v) if !v.is_none() => Some(v.extract::<[f32; 4]>().map_err(|e| {
                VantageError::handler(format!("field 'bbox' must be [f32; 4]: {e}"))
            })?),
            _ => None,
        };
    let fragment_sequence = match dict
        .get_item("fragment_sequence")
        .map_err(|e| VantageError::handler(e.to_string()))?
    {
        Some(v) if !v.is_none() => Some(v.extract::<u32>().map_err(|e| {
            VantageError::handler(format!("field 'fragment_sequence' must be int: {e}"))
        })?),
        _ => ctx.fragment_sequence,
    };
    let frame_sequence = match dict
        .get_item("frame_sequence")
        .map_err(|e| VantageError::handler(e.to_string()))?
    {
        Some(v) if !v.is_none() => v.extract::<u64>().map_err(|e| {
            VantageError::handler(format!("field 'frame_sequence' must be int: {e}"))
        })?,
        _ => ctx.frame_sequence,
    };
    let media_pts_ns = match dict
        .get_item("media_pts_ns")
        .map_err(|e| VantageError::handler(e.to_string()))?
    {
        Some(v) if !v.is_none() => Some(v.extract::<u64>().map_err(|e| {
            VantageError::handler(format!("field 'media_pts_ns' must be int: {e}"))
        })?),
        _ => ctx.media_pts_ns,
    };
    let timeline_ts_us = match dict
        .get_item("timeline_ts_us")
        .map_err(|e| VantageError::handler(e.to_string()))?
    {
        Some(v) if !v.is_none() => v.extract::<i64>().map_err(|e| {
            VantageError::handler(format!("field 'timeline_ts_us' must be int: {e}"))
        })?,
        _ => ctx.timeline_ts_us,
    };
    let time_basis = match get_str("time_basis")? {
        Some(raw) => TimeBasis::parse(&raw)?,
        None => ctx.time_basis,
    };
    let attributes = match dict
        .get_item("attributes")
        .map_err(|e| VantageError::handler(e.to_string()))?
    {
        Some(v) if !v.is_none() => {
            py_to_json(&v).map_err(|e| VantageError::handler(format!("invalid attributes: {e}")))?
        }
        _ => serde_json::json!({}),
    };
    let signal_schema_id = get_str("signal_schema_id")?.unwrap_or_else(|| "generic".to_string());
    let signal_schema_version =
        get_str("signal_schema_version")?.unwrap_or_else(|| "1.0.0".to_string());
    let display_contract_id =
        get_str("display_contract_id")?.unwrap_or_else(|| signal_schema_id.clone());
    let search_text = get_str("search_text")?.unwrap_or_else(|| format!("{label} {category}"));

    Ok(ObservationOutput {
        observation_key: get_str("observation_key")?.unwrap_or_default(),
        fragment_sequence,
        frame_sequence,
        media_pts_ns,
        timeline_ts_us,
        time_basis,
        track_id: get_str("track_id")?,
        category,
        label: label.clone(),
        confidence,
        bbox,
        crop_jpeg_b64: get_str("crop_jpeg_b64")?,
        attributes,
        signal_schema_id,
        signal_schema_version,
        display_contract_id,
        search_text,
    })
}

fn json_to_py(py: Python<'_>, val: &serde_json::Value) -> PyResult<Py<PyAny>> {
    match val {
        serde_json::Value::Null => Ok(py.None()),
        serde_json::Value::Bool(b) => Ok(PyBool::new(py, *b).to_owned().into_any().unbind()),
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Ok(i.into_pyobject(py)?.into_any().unbind())
            } else if let Some(u) = n.as_u64() {
                Ok(u.into_pyobject(py)?.into_any().unbind())
            } else if let Some(f) = n.as_f64() {
                Ok(f.into_pyobject(py)?.into_any().unbind())
            } else {
                Ok(py.None())
            }
        }
        serde_json::Value::String(s) => Ok(PyString::new(py, s).into_any().unbind()),
        serde_json::Value::Array(arr) => {
            let py_list = PyList::empty(py);
            for item in arr {
                py_list.append(json_to_py(py, item)?)?;
            }
            Ok(py_list.into_any().unbind())
        }
        serde_json::Value::Object(map) => {
            let py_dict = PyDict::new(py);
            for (k, v) in map {
                py_dict.set_item(k, json_to_py(py, v)?)?;
            }
            Ok(py_dict.into_any().unbind())
        }
    }
}

fn py_to_json(obj: &Bound<'_, PyAny>) -> PyResult<serde_json::Value> {
    if obj.is_none() {
        return Ok(serde_json::Value::Null);
    }
    if obj.is_instance_of::<PyBool>() {
        return Ok(serde_json::Value::Bool(obj.extract::<bool>()?));
    }
    if obj.is_instance_of::<PyInt>() {
        return Ok(serde_json::Value::Number(obj.extract::<i64>()?.into()));
    }
    if obj.is_instance_of::<PyFloat>() {
        let f = obj.extract::<f64>()?;
        let num = serde_json::Number::from_f64(f)
            .ok_or_else(|| PyValueError::new_err("non-finite float in JSON attributes"))?;
        return Ok(serde_json::Value::Number(num));
    }
    if obj.is_instance_of::<PyString>() {
        return Ok(serde_json::Value::String(obj.extract::<String>()?));
    }
    if let Ok(list) = obj.cast::<PyList>() {
        let mut out = Vec::with_capacity(list.len());
        for item in list.iter() {
            out.push(py_to_json(&item)?);
        }
        return Ok(serde_json::Value::Array(out));
    }
    if let Ok(dict) = obj.cast::<PyDict>() {
        let mut out = serde_json::Map::new();
        for (k, v) in dict.iter() {
            let key = k.extract::<String>()?;
            out.insert(key, py_to_json(&v)?);
        }
        return Ok(serde_json::Value::Object(out));
    }
    Err(PyValueError::new_err(format!(
        "unsupported value type for JSON conversion: {}",
        obj.get_type().name()?
    )))
}

fn vantage_err_to_py(err: VantageError) -> PyErr {
    PyRuntimeError::new_err(err.to_string())
}

#[pymodule]
fn _serviceradar_vantage(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<FrameContext>()?;
    m.add_class::<Observation>()?;
    m.add_class::<WorkerCapabilities>()?;
    m.add_class::<VantageWorker>()?;
    m.add_function(wrap_pyfunction!(run_local_harness, m)?)?;
    Ok(())
}
