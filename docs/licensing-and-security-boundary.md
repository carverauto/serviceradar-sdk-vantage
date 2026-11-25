# Licensing and Security Boundary

## 1. Permissive Licensing Guarantee

`serviceradar-sdk-vantage` and the reference `vantage-worker-alpr` worker are licensed
under the **Apache License, Version 2.0** and depend solely on permissive open-source
crates and Python packages (`Apache-2.0`, `MIT`, `BSD-2-Clause`, `BSD-3-Clause`,
`ISC`, `Zlib`, `CDLA-Permissive-2.0`).

- **No copyleft contamination**: Neither ServiceRadar OSS (`carverauto/serviceradar`)
  nor `serviceradar-sdk-vantage` links, embeds, or ships `AGPL`, `GPL`, `LGPL`, or
  proprietary libraries (such as AGPLv3 OpenALPR or commercial ALPR SDKs).
- **External process boundary**: Operators who wish to integrate a third-party,
  AGPLv3 (e.g., OpenALPR), or commercial inference engine MUST build and run that
  integration in their own separate external worker binary/container that consumes
  this Apache-2.0 SDK over the `vantage.worker.v1` NATS/HTTP wire boundary.
  ServiceRadar OSS and `serviceradar-sdk-vantage` never bundle or distribute those
  engines.

## 2. Security and Credential Isolation Boundary

External Vantage workers run outside the ServiceRadar database and object-storage
trust perimeter:

1. **Zero Database / Warehouse Access**: Workers never receive `DATABASE_URL`,
   CNPG credentials, StarRocks credentials, or database client drivers. All outputs
   enter ServiceRadar exclusively via NATS JetStream (`media.results.vantage.v1`)
   and are ingested and schema-validated by Core's `EventWriter`.
2. **Zero Static S3 Secrets**: Workers authenticate only to the control plane
   read-grant endpoint (`POST /v1/media/workers/read-grants`) using workload headers
   (`X-ServiceRadar-Control-Plane-Authorization`, `X-ServiceRadar-Deployment-Ref`,
   `X-ServiceRadar-Media-Worker-Generation`). Read grants return time-bounded
   (`<= 900s`), `:reader`-only (`GET`/`HEAD`) presigned URLs or local NVR
   `analysis_read` paths.
3. **Mandatory Cryptographic Verification**: Before decoding CMAF/H.264 bytes or
   invoking user `process_frame` callbacks, the SDK verifies SHA-256 digests on
   `init.mp4` and every sampled fragment slice against the frozen block descriptor.
4. **Live Keyframe Tap Isolation**: In `live_keyframe_tap` mode, frames arrive on
   core NATS (`media.live.vantage.<capability_slug>.v1`) with `catalog_entry_id: null`,
   `fragment_sequence: null`, and zero read tokens. Any frame carrying a `read_token`
   or non-null recording coordinates is rejected before callback invocation.
5. **Bounded Payload & Crop Caps**:
   - `vantage.job.v1` <= `4,096` bytes
   - `vantage.result.v1` <= `983,040` bytes (`960 KiB`) and `<= 256` observations
   - `crop_jpeg_b64` decoded <= `32,768` bytes (`32 KiB`) Baseline Sequential JFIF (`SOF0`)
