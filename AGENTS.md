# AGENTS.md — `serviceradar-sdk-vantage`

## Repository Invariants

- **License**: Strictly Apache-2.0 and permissive transitive dependencies only (`Apache-2.0`, `MIT`, `BSD-2-Clause`, `BSD-3-Clause`, `ISC`, `Zlib`, `CDLA-Permissive-2.0`). NEVER add GPL, AGPL, LGPL, or proprietary crates or libraries (e.g., `openalpr` is strictly forbidden).
- **Allocator safety**: `rusty_h264-decoder` MUST keep `default-features = false, features = ["std", "asm"]` so its default `#[global_allocator]` is never compiled into worker binaries or the PyO3 extension.
- **No secrets or live data**: NEVER commit CNPG/StarRocks/S3 credentials, real customer hostnames, real IPs, or captured footage/plates. Use synthetic plates (`SR-0100`, `TEST-742`), camera labels (`Gate West 01`, `Bay 04 Approach`), RFC 5737 IPs (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`), and `example.com` / `example.org`.
- **Build volume**: On macOS shared workstations, set `CARGO_TARGET_DIR=/Volumes/Build/cargo-target/serviceradar-sdk-vantage` and place Python virtualenvs under `/Volumes/Build/scratch/`.
- **Wire conformance**: Keep `conformance/vectors/` synchronized with ServiceRadar `integration_tests/vantage_ml/fixtures/wire_vectors/`.
