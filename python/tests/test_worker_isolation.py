# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import threading
import time
import urllib.request
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


def test_worker_deployment_ref_and_generation_override_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("VANTAGE_CONTROL_PLANE_AUTH", "tok-env-synthetic")
    monkeypatch.setenv("VANTAGE_WORKER_GENERATION", "3")
    monkeypatch.setenv("VANTAGE_DEPLOYMENT_REF", "deploy-env")

    # Both deployment_ref and worker_generation kwargs override env when control_plane_auth came from env
    w_both = sv.VantageWorker(
        worker_id="py-auth-override-1",
        capabilities=["vantage.alpr.v1"],
        handler=lambda _ctx: [],
        deployment_ref="deploy-kwarg",
        worker_generation="9",
    )
    assert w_both.deployment_ref == "deploy-kwarg"
    assert w_both.worker_generation == "9"

    # Overriding only deployment_ref preserves env worker_generation
    w_partial = sv.VantageWorker(
        worker_id="py-auth-override-2",
        capabilities=["vantage.alpr.v1"],
        handler=lambda _ctx: [],
        deployment_ref="deploy-only",
    )
    assert w_partial.deployment_ref == "deploy-only"
    assert w_partial.worker_generation == "3"


def _free_tcp_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def test_python_worker_run_until_one_custom_result_subject() -> None:
    if shutil.which("nats-server") is None:
        pytest.skip("nats-server not found on PATH")

    try:
        import nats  # type: ignore[import-not-found]
        import asyncio
    except ImportError:
        nats = None
        asyncio = None

    nats_port = _free_tcp_port()
    mon_port = _free_tcp_port()
    with tempfile.TemporaryDirectory() as js_dir:
        proc = subprocess.Popen(
            [
                "nats-server",
                "-js",
                "-a",
                "127.0.0.1",
                "-p",
                str(nats_port),
                "-m",
                str(mon_port),
                "-sd",
                js_dir,
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            deadline = time.monotonic() + 5.0
            while time.monotonic() < deadline:
                try:
                    with urllib.request.urlopen(f"http://127.0.0.1:{mon_port}/jsz", timeout=0.2) as r:
                        if r.status == 200:
                            break
                except Exception:
                    time.sleep(0.05)

            frame_fixture = json.loads((VECTORS_DIR / "vantage_frame_v1.json").read_text())["positive"]
            frame_bytes = json.dumps(frame_fixture).encode("utf-8")
            live_subj = "media.live.vantage.vantage_py_probe_v1.v1"
            out_subj = "media.results.vantage.py.out"
            nats_url = f"nats://127.0.0.1:{nats_port}"

            seen_frames: list[int] = []
            worker_errs: list[BaseException] = []

            def py_handler(ctx: sv.FrameContext):
                seen_frames.append(ctx.frame_sequence)
                return [
                    sv.Observation(
                        category="license_plate",
                        label="SR-0100",
                        confidence=0.95,
                        bbox=[0.2, 0.3, 0.7, 0.85],
                        signal_schema_id="alpr_plate_read",
                        attributes={"plate_text": "SR-0100"},
                    )
                ]

            worker = sv.VantageWorker(
                worker_id="py-custom-subj-1",
                capabilities=["vantage.py_probe.v1"],
                supported_source_modes=["live_keyframe_tap"],
                nats_url=nats_url,
                live_subject=live_subj,
                result_subject=out_subj,
                handler=py_handler,
            )

            def run_worker() -> None:
                try:
                    worker.run_until_one()
                except BaseException as exc:  # pragma: no cover
                    worker_errs.append(exc)

            t = threading.Thread(target=run_worker, daemon=True)
            t.start()
            time.sleep(0.25)

            if nats is not None and asyncio is not None:
                async def drive_nats() -> dict:
                    nc = await nats.connect(nats_url)
                    js = nc.jetstream()
                    await js.add_stream(
                        name="CAMERA_MEDIA_RESULTS",
                        subjects=["media.results.vantage.v1"],
                    )
                    sub = await nc.subscribe(out_subj)
                    await nc.publish(live_subj, frame_bytes)
                    await nc.flush()
                    msg = await sub.next_msg(timeout=5.0)
                    await nc.close()
                    return json.loads(msg.data.decode("utf-8"))

                env = asyncio.run(drive_nats())
                assert env["schema_version"] == "vantage.result.v1"
                assert env["observations"][0]["label"] == "SR-0100"
            else:
                # Minimal NATS wire drive without external nats-py dependency
                with socket.create_connection(("127.0.0.1", nats_port), timeout=5.0) as s:
                    s.settimeout(5.0)
                    buf = b""
                    while b"\r\n" not in buf:
                        buf += s.recv(4096)
                    s.sendall(b"CONNECT {\"verbose\":false,\"pedantic\":false}\r\n")
                    s.sendall(b"SUB " + out_subj.encode() + b" 1\r\n")
                    s.sendall(
                        f"PUB {live_subj} {len(frame_bytes)}\r\n".encode()
                        + frame_bytes
                        + b"\r\nPING\r\n"
                    )
                    received = b""
                    deadline = time.monotonic() + 5.0
                    while time.monotonic() < deadline:
                        chunk = s.recv(8192)
                        if not chunk:
                            break
                        received += chunk
                        if b"vantage.result.v1" in received:
                            break
                    assert b"vantage.result.v1" in received, f"missing result envelope: {received!r}"
                    assert b"SR-0100" in received

            t.join(timeout=5.0)
            assert not t.is_alive(), "VantageWorker.run_until_one() hung on custom result_subject"
            assert not worker_errs, f"worker raised: {worker_errs}"
            assert seen_frames == [frame_fixture["frame_sequence"]]
        finally:
            proc.terminate()
            proc.wait(timeout=5)
