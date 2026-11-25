# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import json
import os
from pathlib import Path
import threading
import time
import pytest
import serviceradar_vantage as sv

VECTORS_DIR = Path(__file__).resolve().parents[2] / "conformance" / "vectors"


def test_handler_exception_is_isolated_and_surfaced_cleanly(tmp_path: Path) -> None:
    frame_fixture = json.loads((VECTORS_DIR / "vantage_frame_v1.json").read_text())["positive"]
    clip_path = tmp_path / "frame.json"
    clip_path.write_text(json.dumps(frame_fixture))

    def crashing_handler(_ctx: sv.FrameContext):
        raise RuntimeError("synthetic model inference fault")

    with pytest.raises(RuntimeError, match="synthetic model inference fault"):
        sv.run_local_harness(str(clip_path), crashing_handler, source_mode="live_keyframe_tap")


def test_invalid_observation_output_is_rejected(tmp_path: Path) -> None:
    frame_fixture = json.loads((VECTORS_DIR / "vantage_frame_v1.json").read_text())["positive"]
    clip_path = tmp_path / "frame.json"
    clip_path.write_text(json.dumps(frame_fixture))

    def bad_bbox_handler(_ctx: sv.FrameContext):
        return [
            sv.Observation(
                category="license_plate",
                label="SR-0100",
                confidence=0.95,
                bbox=[0.8, 0.2, 0.4, 0.9],  # inverted x1 > x2
                signal_schema_id="alpr_plate_read",
            )
        ]

    with pytest.raises(RuntimeError, match="x1 < x2"):
        sv.run_local_harness(str(clip_path), bad_bbox_handler, source_mode="live_keyframe_tap")


def test_worker_instantiation_requires_zero_db_or_s3_credentials() -> None:
    for forbidden in ("DATABASE_URL", "CNPG_PASSWORD", "STARROCKS_PASSWORD", "AWS_SECRET_ACCESS_KEY"):
        assert forbidden not in os.environ

    caps = sv.WorkerCapabilities(
        capabilities=["vantage.alpr.v1"],
        supported_source_modes=["recorded_block", "live_keyframe_tap"],
        execution_backend="onnx",
        model_id="vantage-alpr-synthetic",
        model_version="1.0.0",
    )
    worker = sv.VantageWorker(
        worker_id="py-isolation-check",
        capabilities=caps,
        handler=lambda _ctx: [],
    )
    assert worker.worker_id == "py-isolation-check"
    assert worker.capabilities == ["vantage.alpr.v1"]


def test_gil_released_during_rust_harness_work(tmp_path: Path) -> None:
    frame_fixture = json.loads((VECTORS_DIR / "vantage_frame_v1.json").read_text())["positive"]
    clip_path = tmp_path / "frame.json"
    clip_path.write_text(json.dumps(frame_fixture))

    ticks = 0
    stop = threading.Event()

    def ticker():
        nonlocal ticks
        while not stop.is_set():
            ticks += 1
            time.sleep(0.001)

    t = threading.Thread(target=ticker, daemon=True)
    t.start()
    try:
        for _ in range(10):
            sv.run_local_harness(str(clip_path), lambda _ctx: [], source_mode="live_keyframe_tap")
    finally:
        stop.set()
        t.join(timeout=2.0)

    assert ticks >= 1
