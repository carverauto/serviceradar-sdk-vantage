# ServiceRadar Vantage SDK (`serviceradar-sdk-vantage`)

Apache-2.0 Rust and Python (`PyO3` + `maturin`) SDK for building external
ServiceRadar Vantage computer-vision workers (`vantage.worker.v1`) and running
the permissive reference ALPR worker (`vantage-worker-alpr`).

## Architecture & Security Boundary

External Vantage workers operate strictly outside the ServiceRadar control-plane
trust zone:

- **Zero database or warehouse credentials**: Workers never receive CNPG,
  PostgreSQL, StarRocks, or long-lived object-storage credentials.
- **Scoped read grants**: For `recorded_block` jobs, workers call
  `POST /v1/media/workers/read-grants`, fetch only authorized byte ranges or
  local NVR `analysis_read` blocks, and verify SHA-256 digests on `init.mp4`
  and every fragment slice before decoding or invoking user callbacks.
- **JetStream-only observation ingress**: Workers publish validated
  `vantage.result.v1` envelopes (`<= 960 KiB`, `<= 256` observations, Baseline
  JFIF `crop_jpeg_b64 <= 32 KiB`) to `media.results.vantage.v1` and await the
  JetStream `PublishAckFuture` before ACKing the job.
- **Dual source modes via one handler**: Both `recorded_block` (CMAF/H.264) and
  `live_keyframe_tap` (`media.live.vantage.<capability_slug>.v1`) deliver a
  unified `VantageFrameContext` / `FrameContext` into `process_frame(ctx)`.
- **Zero-copy Python frames**: `ctx.rgb_frame` exposes decoded `(H, W, 3)`
  `uint8` C-contiguous NumPy arrays backed directly by the Rust buffer
  (`OWNDATA == False`), while Rust I/O, SHA-256 verification, and H.264/JPEG
  decoding execute with the Python GIL released.

## Workspace Layout

- `crates/serviceradar-vantage-sdk/` — Rust SDK (`serviceradar_vantage_sdk`)
- `crates/vantage-worker-alpr/` — Permissive Apache-2.0 reference ALPR worker (`vantage.alpr.v1`)
- `python/` — PyO3 + `maturin` Python package (`serviceradar-vantage`, import `serviceradar_vantage`)
- `conformance/vectors/` — Canonical `vantage.worker.v1` wire vectors synced with ServiceRadar core
- `docs/licensing-and-security-boundary.md` — Licensing & third-party copyleft/commercial engine boundary

## Quickstart

### Rust

```bash
CARGO_TARGET_DIR=/Volumes/Build/cargo-target/serviceradar-sdk-vantage cargo test --workspace
```

### Python (`uv` + `maturin`)

```bash
uv venv .venv
uv pip install --python .venv/bin/python maturin pytest numpy
VIRTUAL_ENV=$PWD/.venv .venv/bin/maturin develop --manifest-path python/Cargo.toml
.venv/bin/python -m pytest python/tests -v
```

### Ramp 1 -> Ramp 2 Upgradeability (`io.serviceradar.vantage-alpr`)

1. Start in Ramp 1 using ServiceRadar's built-in `camera_vlm` runner (`media.jobs.vantage.vlm.v1`).
2. Deploy `vantage-worker-alpr` (or a custom Rust/Python SDK worker) advertising `vantage.alpr.v1` on `media.workers.heartbeat.v1`.
3. `VantagePipelineDispatcher` automatically routes new jobs to `media.jobs.vantage.vantage_alpr_v1.v1` while workers emit identical `alpr_plate_read` (`vantage.result.v1`) observations, and transparently falls back to `camera_vlm` if external registrations expire.

See [`docs/licensing-and-security-boundary.md`](docs/licensing-and-security-boundary.md) for external third-party / AGPL / commercial engine isolation rules.
