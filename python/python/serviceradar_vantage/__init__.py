# SPDX-License-Identifier: Apache-2.0
"""ServiceRadar Vantage external computer-vision worker SDK (`vantage.worker.v1`)."""

from __future__ import annotations

from serviceradar_vantage._serviceradar_vantage import (
    FrameContext,
    Observation,
    VantageWorker,
    WorkerCapabilities,
    run_local_harness,
)

__all__ = [
    "FrameContext",
    "Observation",
    "VantageWorker",
    "WorkerCapabilities",
    "run_local_harness",
]

__version__ = "0.1.0"
