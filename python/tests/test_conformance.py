# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import json
from pathlib import Path
import serviceradar_vantage as sv

VECTORS_DIR = Path(__file__).resolve().parents[2] / "conformance" / "vectors"


def test_dict_and_observation_outputs_produce_valid_envelopes(tmp_path: Path) -> None:
    frame_fixture = json.loads((VECTORS_DIR / "vantage_frame_v1.json").read_text())["positive_payload_format"]
    clip_path = tmp_path / "payload_format_jpeg.json"
    clip_path.write_text(json.dumps(frame_fixture))

    def dict_handler(ctx: sv.FrameContext):
        assert ctx.source_mode == "live_keyframe_tap"
        assert ctx.catalog_entry_id is None
        assert ctx.fragment_sequence is None
        assert len(ctx.upstream_detections) == 1
        assert ctx.upstream_detections[0]["category"] == "vehicle"
        return [
            {
                "category": "license_plate",
                "label": "TEST-742",
                "confidence": 0.96,
                "bbox": [0.32, 0.58, 0.48, 0.66],
                "attributes": {"plate_text": "TEST-742", "region": "US-CA"},
                "signal_schema_id": "alpr_plate_read",
                "signal_schema_version": "1.0.0",
                "display_contract_id": "alpr_plate_read",
                "search_text": "TEST-742 Gate West 01 US-CA",
            }
        ]

    rep_live = sv.run_local_harness(
        str(clip_path),
        dict_handler,
        str(VECTORS_DIR / "alpr_plate_read_schema.json"),
        source_mode="live_keyframe_tap",
    )
    env_live = rep_live["result_envelope"]
    assert env_live["schema_version"] == "vantage.result.v1"
    assert env_live["source_mode"] == "live_keyframe_tap"
    assert env_live["job_id"] is None
    assert env_live["catalog_entry_id"] is None
    assert env_live["observations"][0]["fragment_sequence"] is None
    assert env_live["observations"][0]["label"] == "TEST-742"

    # Same clip run in recorded_block mode populates job_id, catalog_entry_id, and fragment_sequence
    def rec_handler(ctx: sv.FrameContext):
        assert ctx.source_mode == "recorded_block"
        assert ctx.catalog_entry_id is not None
        assert ctx.fragment_sequence == 1
        return [
            sv.Observation(
                category="license_plate",
                label="SR-0100",
                confidence=0.94,
                bbox=[0.32, 0.58, 0.48, 0.66],
                signal_schema_id="alpr_plate_read",
                attributes={"plate_text": "SR-0100", "region": "US-CO"},
            )
        ]

    rep_rec = sv.run_local_harness(
        str(clip_path),
        rec_handler,
        str(VECTORS_DIR / "alpr_plate_read_schema.json"),
        source_mode="recorded_block",
    )
    env_rec = rep_rec["result_envelope"]
    assert env_rec["source_mode"] == "recorded_block"
    assert env_rec["job_id"] is not None
    assert env_rec["catalog_entry_id"] is not None
    assert env_rec["observations"][0]["fragment_sequence"] == 1
    assert env_rec["observations"][0]["label"] == "SR-0100"
