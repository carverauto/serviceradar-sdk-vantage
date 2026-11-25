# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import base64
import json
from pathlib import Path
import numpy as np
import pytest
import serviceradar_vantage as sv

VECTORS_DIR = Path(__file__).resolve().parents[2] / "conformance" / "vectors"


def test_zero_copy_rgb_frame_layout_and_pointer_identity(tmp_path: Path) -> None:
    w, h = 8, 6
    rgb_bytes = bytes((i * 7) % 256 for i in range(w * h * 3))
    frame_fixture = json.loads((VECTORS_DIR / "vantage_frame_v1.json").read_text())["positive"]
    frame_fixture.pop("frame_jpeg_b64", None)
    frame_fixture["payload_format"] = "rgb8"
    frame_fixture["width"] = w
    frame_fixture["height"] = h
    frame_fixture["payload_b64"] = base64.b64encode(rgb_bytes).decode("ascii")

    clip_path = tmp_path / "rgb8_frame.json"
    clip_path.write_text(json.dumps(frame_fixture))

    observed = {}

    def handler(ctx: sv.FrameContext):
        arr = ctx.rgb_frame
        assert isinstance(arr, np.ndarray)
        assert arr.dtype == np.uint8
        assert arr.shape == (h, w, 3)
        assert arr.flags["C_CONTIGUOUS"] is True
        assert arr.flags["OWNDATA"] is False, "NumPy array must borrow Rust buffer via PyCapsule"
        assert arr.base is not None

        # Zero-copy: NumPy buffer address equals Rust Vec::as_ptr() and is stable across property reads
        ptr = ctx._debug_buffer_ptr()
        assert arr.__array_interface__["data"][0] == ptr
        assert ctx.rgb_frame.__array_interface__["data"][0] == ptr
        assert arr.tobytes() == rgb_bytes

        observed["shape"] = arr.shape
        return [
            sv.Observation(
                category="vehicle",
                label="Bay 04 Approach",
                confidence=0.95,
                bbox=[0.2, 0.3, 0.7, 0.85],
                signal_schema_id="bay_guidance",
                attributes={"bay_id": "bay-04", "guidance_state": "approach", "distance_m": 2.4},
            )
        ]

    report = sv.run_local_harness(
        str(clip_path),
        handler,
        str(VECTORS_DIR / "bay_guidance_schema.json"),
        source_mode="live_keyframe_tap",
    )
    assert observed["shape"] == (h, w, 3)
    assert report["frames_processed"] == 1
    assert report["result_envelope"]["source_mode"] == "live_keyframe_tap"
    assert report["result_envelope"]["job_id"] is None
    assert report["result_envelope"]["catalog_entry_id"] is None


def test_run_local_harness_rejects_missing_or_empty_clip(tmp_path: Path) -> None:
    empty_file = tmp_path / "empty.mp4"
    empty_file.write_bytes(b"")

    with pytest.raises(Exception):
        sv.run_local_harness(str(tmp_path / "nonexistent.mp4"), lambda _ctx: [])

    with pytest.raises(Exception):
        sv.run_local_harness(str(empty_file), lambda _ctx: [])
