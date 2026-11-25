// SPDX-License-Identifier: Apache-2.0

//! Scoped read-grant client (`POST /v1/media/workers/read-grants`), bounded byte-range
//! coalescing, presigned archive + NVR `analysis_read` readers, and mandatory SHA-256
//! verification before decode or handler callback.

use crate::error::VantageError;
use crate::protocol::{require_non_empty, validate_sha256_hex};
use core::fmt::{self, Debug, Formatter};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};
use std::future::Future;
use std::io::Read;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;
use zeroize::Zeroizing;

pub const HEADER_CONTROL_PLANE_AUTH: &str = "X-ServiceRadar-Control-Plane-Authorization";
pub const HEADER_DEPLOYMENT_REF: &str = "X-ServiceRadar-Deployment-Ref";
pub const HEADER_MEDIA_WORKER_GENERATION: &str = "X-ServiceRadar-Media-Worker-Generation";

pub const MAX_GRANT_RESPONSE_BYTES: usize = 512 * 1024;
pub const MAX_COALESCED_RANGE_BYTES: u64 = 4 * 1024 * 1024;
pub const MAX_COALESCE_GAP_BYTES: u64 = 256 * 1024;
pub const MAX_INIT_SEGMENT_BYTES: u64 = 1024 * 1024;
pub const MAX_TTL_SECONDS: u64 = 900;

/// Short-lived pre-signed GET URL zeroed on drop and redacted on `Debug`/`Serialize`.
#[derive(Clone, PartialEq, Eq)]
pub struct RedactedPresignedUrl(Zeroizing<String>);

impl RedactedPresignedUrl {
    pub fn new(url: impl Into<String>) -> Self {
        Self(Zeroizing::new(url.into()))
    }

    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }

    pub fn redacted_target(&self) -> String {
        match self.0.split_once('?') {
            Some((base, _)) => format!("{base}?[REDACTED]"),
            None => "[REDACTED]".to_string(),
        }
    }
}

impl Debug for RedactedPresignedUrl {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str("\"[REDACTED]\"")
    }
}

impl Serialize for RedactedPresignedUrl {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str("[REDACTED]")
    }
}

impl<'de> Deserialize<'de> for RedactedPresignedUrl {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = String::deserialize(deserializer)?;
        Ok(Self::new(raw))
    }
}

/// Control-plane authentication headers for `POST /v1/media/workers/read-grants`.
#[derive(Clone, PartialEq, Eq)]
pub struct WorkerAuthCredentials {
    token: Zeroizing<String>,
    deployment_ref: String,
    generation: String,
}

impl WorkerAuthCredentials {
    pub fn new(
        token: impl Into<String>,
        deployment_ref: impl Into<String>,
        generation: impl Into<String>,
    ) -> Self {
        Self {
            token: Zeroizing::new(token.into()),
            deployment_ref: deployment_ref.into(),
            generation: generation.into(),
        }
    }

    pub fn token(&self) -> &str {
        self.token.as_str()
    }

    pub fn deployment_ref(&self) -> &str {
        &self.deployment_ref
    }

    pub fn generation(&self) -> &str {
        &self.generation
    }
}

impl Debug for WorkerAuthCredentials {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("WorkerAuthCredentials")
            .field("token", &"[REDACTED]")
            .field("deployment_ref", &self.deployment_ref)
            .field("generation", &self.generation)
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReadGrantRequest {
    pub schema_version: u32,
    pub job_id: String,
    pub catalog_entry_id: String,
    pub descriptor_sha256: String,
}

impl ReadGrantRequest {
    pub fn new(
        job_id: impl Into<String>,
        catalog_entry_id: impl Into<String>,
        descriptor_sha256: impl Into<String>,
    ) -> Self {
        Self {
            schema_version: 1,
            job_id: job_id.into(),
            catalog_entry_id: catalog_entry_id.into(),
            descriptor_sha256: descriptor_sha256.into(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackingSource {
    Archive,
    Local,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InitSlicePlan {
    #[serde(default = "default_init_name")]
    pub object_name: String,
    #[serde(default)]
    pub offset: u64,
    #[serde(default)]
    pub first: u64,
    #[serde(default)]
    pub last: u64,
    pub length: u64,
    pub sha256: String,
    #[serde(default)]
    pub key: Option<String>,
    #[serde(default)]
    pub etag: Option<String>,
    #[serde(default)]
    pub version_id: Option<String>,
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub presigned_url: Option<RedactedPresignedUrl>,
}

fn default_init_name() -> String {
    "init.mp4".to_string()
}

impl InitSlicePlan {
    pub fn new(length: u64, sha256: impl Into<String>) -> Self {
        Self {
            object_name: "init.mp4".to_string(),
            offset: 0,
            first: 0,
            last: length.saturating_sub(1),
            length,
            sha256: sha256.into(),
            key: None,
            etag: None,
            version_id: None,
            path: None,
            presigned_url: None,
        }
    }

    pub fn redacted_presigned_url(&self) -> Option<&RedactedPresignedUrl> {
        self.presigned_url
            .as_ref()
            .filter(|u| !u.as_str().trim().is_empty())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArchiveMediaObjectPlan {
    #[serde(default = "default_media_name")]
    pub object_name: String,
    pub key: String,
    pub length: u64,
    pub sha256: String,
    #[serde(default)]
    pub etag: Option<String>,
    #[serde(default)]
    pub version_id: Option<String>,
    #[serde(default)]
    pub presigned_url: Option<RedactedPresignedUrl>,
}

fn default_media_name() -> String {
    "media.m4s".to_string()
}

impl ArchiveMediaObjectPlan {
    pub fn redacted_presigned_url(&self) -> Option<&RedactedPresignedUrl> {
        self.presigned_url
            .as_ref()
            .filter(|u| !u.as_str().trim().is_empty())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FragmentSlicePlan {
    pub sequence: u32,
    pub offset: u64,
    #[serde(default)]
    pub first: u64,
    #[serde(default)]
    pub last: u64,
    pub length: u64,
    #[serde(default)]
    pub start_ns: u64,
    #[serde(default)]
    pub duration_ns: u64,
    pub sha256: String,
    #[serde(default)]
    pub path: Option<String>,
}

impl FragmentSlicePlan {
    pub fn new(
        sequence: u32,
        offset: u64,
        length: u64,
        start_ns: u64,
        duration_ns: u64,
        sha256: impl Into<String>,
    ) -> Self {
        Self {
            sequence,
            offset,
            first: offset,
            last: offset + length.saturating_sub(1),
            length,
            start_ns,
            duration_ns,
            sha256: sha256.into(),
            path: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RangeSlice {
    pub sequence: u32,
    pub offset: u64,
    pub relative_offset: u64,
    pub length: u64,
    #[serde(default)]
    pub start_ns: u64,
    #[serde(default)]
    pub duration_ns: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoalescedRange {
    pub first: u64,
    pub last: u64,
    pub length: u64,
    pub fragment_sequences: Vec<u32>,
    pub slices: Vec<RangeSlice>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArchiveGrantTarget {
    #[serde(default)]
    pub binding_id: Option<String>,
    #[serde(default)]
    pub provider: Option<String>,
    pub endpoint: String,
    pub region: String,
    pub bucket: String,
    #[serde(default)]
    pub namespace: Option<String>,
    #[serde(default)]
    pub destination_sha256: Option<String>,
    pub init_key: String,
    #[serde(default)]
    pub init_etag: Option<String>,
    #[serde(default)]
    pub init_presigned_url: Option<RedactedPresignedUrl>,
    pub media_key: String,
    #[serde(default)]
    pub media_etag: Option<String>,
    #[serde(default)]
    pub media_presigned_url: Option<RedactedPresignedUrl>,
}

impl ArchiveGrantTarget {
    pub fn redacted_init_presigned_url(&self) -> Option<&RedactedPresignedUrl> {
        self.init_presigned_url
            .as_ref()
            .filter(|u| !u.as_str().trim().is_empty())
    }

    pub fn redacted_media_presigned_url(&self) -> Option<&RedactedPresignedUrl> {
        self.media_presigned_url
            .as_ref()
            .filter(|u| !u.as_str().trim().is_empty())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BrokerGrantScope {
    #[serde(default)]
    pub grant_id: Option<String>,
    #[serde(default)]
    pub grant_type: Option<String>,
    pub role: String,
    #[serde(default)]
    pub purpose: Option<String>,
    #[serde(default)]
    pub secret_ref: Option<String>,
    #[serde(default)]
    pub allowed_schemes: Vec<String>,
    #[serde(default)]
    pub allowed_hosts: Vec<String>,
    #[serde(default)]
    pub allowed_ports: Vec<u16>,
    #[serde(default)]
    pub allowed_paths: Vec<String>,
    pub allowed_methods: Vec<String>,
}

impl BrokerGrantScope {
    pub fn validate_reader_only(&self) -> Result<(), VantageError> {
        if self.role != "reader" {
            return Err(VantageError::integrity(format!(
                "archive broker grant role must be 'reader', got '{}'",
                self.role
            )));
        }
        if self.allowed_methods.is_empty() {
            return Err(VantageError::integrity(
                "archive broker grant allowed_methods must not be empty",
            ));
        }
        let all_reader = self
            .allowed_methods
            .iter()
            .all(|m| m.eq_ignore_ascii_case("GET") || m.eq_ignore_ascii_case("HEAD"));
        if !all_reader {
            return Err(VantageError::integrity(format!(
                "archive broker grant allowed_methods {:?} exceeds reader-only GET/HEAD scope",
                self.allowed_methods
            )));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalGrantTarget {
    #[serde(default)]
    pub nvr_member: Option<String>,
    pub storage_id: String,
    pub block_key: String,
    #[serde(default = "default_analysis_pool")]
    pub pool: String,
    #[serde(default = "default_analysis_pool")]
    pub purpose: String,
    #[serde(default)]
    pub init_path: Option<String>,
    #[serde(default)]
    pub endpoint: Option<String>,
}

fn default_analysis_pool() -> String {
    "analysis_read".to_string()
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ReadGrantPlan {
    #[serde(default = "default_schema_v1")]
    pub schema_version: u32,
    pub source: BackingSource,
    pub job_id: String,
    pub catalog_entry_id: String,
    pub camera_source_id: String,
    pub stream_profile_id: String,
    pub storage_id: String,
    pub block_key: String,
    pub descriptor_sha256: String,
    pub init_sha256: String,
    #[serde(default = "default_ttl_secs")]
    pub ttl_seconds: u64,
    pub init: InitSlicePlan,
    #[serde(default)]
    pub media: Option<ArchiveMediaObjectPlan>,
    pub fragments: Vec<FragmentSlicePlan>,
    #[serde(default)]
    pub coalesced_ranges: Vec<CoalescedRange>,
    #[serde(default)]
    pub archive: Option<ArchiveGrantTarget>,
    #[serde(default)]
    pub grant: Option<BrokerGrantScope>,
    #[serde(default)]
    pub local: Option<LocalGrantTarget>,
    #[serde(default)]
    pub nvr_member: Option<String>,
    #[serde(default)]
    pub read_pool: Option<String>,
}

#[derive(Deserialize)]
struct RawReadGrantPlan {
    #[serde(default = "default_schema_v1")]
    schema_version: u32,
    #[serde(default)]
    source: Option<BackingSource>,
    #[serde(default)]
    backing: Option<BackingSource>,
    job_id: String,
    catalog_entry_id: String,
    camera_source_id: String,
    stream_profile_id: String,
    storage_id: String,
    block_key: String,
    descriptor_sha256: String,
    init_sha256: String,
    #[serde(default = "default_ttl_secs")]
    ttl_seconds: u64,
    init: InitSlicePlan,
    #[serde(default)]
    media: Option<ArchiveMediaObjectPlan>,
    fragments: Vec<FragmentSlicePlan>,
    #[serde(default)]
    coalesced_ranges: Vec<CoalescedRange>,
    #[serde(default)]
    archive: Option<ArchiveGrantTarget>,
    #[serde(default)]
    grant: Option<BrokerGrantScope>,
    #[serde(default)]
    local: Option<LocalGrantTarget>,
    #[serde(default)]
    nvr_member: Option<String>,
    #[serde(default)]
    read_pool: Option<String>,
}

impl<'de> Deserialize<'de> for ReadGrantPlan {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::de::Deserializer<'de>,
    {
        let raw = RawReadGrantPlan::deserialize(deserializer)?;
        let source = match (raw.source, raw.backing) {
            (Some(src), Some(bck)) if src != bck => {
                return Err(serde::de::Error::custom(
                    "read grant source disagrees with backing",
                ));
            }
            (Some(src), _) | (None, Some(src)) => src,
            (None, None) => return Err(serde::de::Error::missing_field("source")),
        };
        Ok(Self {
            schema_version: raw.schema_version,
            source,
            job_id: raw.job_id,
            catalog_entry_id: raw.catalog_entry_id,
            camera_source_id: raw.camera_source_id,
            stream_profile_id: raw.stream_profile_id,
            storage_id: raw.storage_id,
            block_key: raw.block_key,
            descriptor_sha256: raw.descriptor_sha256,
            init_sha256: raw.init_sha256,
            ttl_seconds: raw.ttl_seconds,
            init: raw.init,
            media: raw.media,
            fragments: raw.fragments,
            coalesced_ranges: raw.coalesced_ranges,
            archive: raw.archive,
            grant: raw.grant,
            local: raw.local,
            nvr_member: raw.nvr_member,
            read_pool: raw.read_pool,
        })
    }
}

fn default_schema_v1() -> u32 {
    1
}

fn default_ttl_secs() -> u64 {
    300
}

impl ReadGrantPlan {
    pub fn validate(&self) -> Result<(), VantageError> {
        if self.schema_version != 1 {
            return Err(VantageError::integrity(format!(
                "unsupported read grant schema_version {}",
                self.schema_version
            )));
        }
        if self.ttl_seconds == 0 || self.ttl_seconds > MAX_TTL_SECONDS {
            return Err(VantageError::integrity(format!(
                "read grant ttl_seconds {} must be in 1..={MAX_TTL_SECONDS}",
                self.ttl_seconds
            )));
        }
        require_non_empty(&self.job_id, "job_id")?;
        require_non_empty(&self.catalog_entry_id, "catalog_entry_id")?;
        validate_sha256_hex(&self.descriptor_sha256, "descriptor_sha256")?;
        validate_sha256_hex(&self.init_sha256, "init_sha256")?;
        if self.init_sha256 != self.init.sha256 {
            return Err(VantageError::integrity(
                "read grant top-level init_sha256 disagrees with init.sha256",
            ));
        }
        if self.fragments.is_empty() {
            return Err(VantageError::integrity(
                "read grant contains zero sampled fragments",
            ));
        }
        match self.source {
            BackingSource::Archive => {
                let grant = self.grant.as_ref().ok_or_else(|| {
                    VantageError::integrity(
                        "archive read grant missing CredentialBrokerGrant scope",
                    )
                })?;
                grant.validate_reader_only()?;
                if self.archive.is_none() {
                    return Err(VantageError::integrity(
                        "archive read grant missing archive target",
                    ));
                }
                self.resolve_presigned_urls()?;
            }
            BackingSource::Local => {
                if let Some(pool) = self
                    .local
                    .as_ref()
                    .map(|l| l.pool.as_str())
                    .or(self.read_pool.as_deref())
                    && pool != "analysis_read"
                {
                    return Err(VantageError::integrity(format!(
                        "local read grant must target 'analysis_read' pool, got '{pool}'"
                    )));
                }
            }
        }
        Ok(())
    }

    pub fn validate_for_request(&self, req: &ReadGrantRequest) -> Result<(), VantageError> {
        self.validate()?;
        if self.job_id != req.job_id {
            return Err(VantageError::integrity(format!(
                "read grant job_id '{}' does not match requested '{}'",
                self.job_id, req.job_id
            )));
        }
        if self.catalog_entry_id != req.catalog_entry_id {
            return Err(VantageError::integrity(format!(
                "read grant catalog_entry_id '{}' does not match requested '{}'",
                self.catalog_entry_id, req.catalog_entry_id
            )));
        }
        if self.descriptor_sha256 != req.descriptor_sha256 {
            return Err(VantageError::integrity(
                "read grant descriptor_sha256 does not match frozen job descriptor_sha256",
            ));
        }
        Ok(())
    }

    pub fn resolve_presigned_urls(
        &self,
    ) -> Result<Option<(RedactedPresignedUrl, RedactedPresignedUrl)>, VantageError> {
        let init_direct = self.init.redacted_presigned_url();
        let init_archive = self
            .archive
            .as_ref()
            .and_then(ArchiveGrantTarget::redacted_init_presigned_url);
        let init_url = match (init_direct, init_archive) {
            (Some(a), Some(b)) if a != b => {
                return Err(VantageError::integrity(
                    "archive read grant init.presigned_url disagrees with archive.init_presigned_url",
                ));
            }
            (Some(u), _) | (None, Some(u)) => Some(u.clone()),
            (None, None) => None,
        };

        let media_direct = self
            .media
            .as_ref()
            .and_then(ArchiveMediaObjectPlan::redacted_presigned_url);
        let media_archive = self
            .archive
            .as_ref()
            .and_then(ArchiveGrantTarget::redacted_media_presigned_url);
        let media_url = match (media_direct, media_archive) {
            (Some(a), Some(b)) if a != b => {
                return Err(VantageError::integrity(
                    "archive read grant media.presigned_url disagrees with archive.media_presigned_url",
                ));
            }
            (Some(u), _) | (None, Some(u)) => Some(u.clone()),
            (None, None) => None,
        };

        match (init_url, media_url) {
            (Some(i), Some(m)) => Ok(Some((i, m))),
            (None, None) => Ok(None),
            _ => Err(VantageError::integrity(
                "archive read grant must supply both init and media pre-signed URLs",
            )),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GrantResolution {
    Admitted(Box<ReadGrantPlan>),
    /// `410 Gone` (`recording_gone`): ACK message cleanly without retry.
    Gone,
}

pub trait GrantClient: Send + Sync {
    fn acquire_read_grant(
        &self,
        request: &ReadGrantRequest,
    ) -> impl Future<Output = Result<GrantResolution, VantageError>> + Send;
}

#[derive(Debug, Clone)]
pub struct HttpControlPlaneGrantClient {
    base_url: String,
    auth: WorkerAuthCredentials,
    timeout: Duration,
}

impl HttpControlPlaneGrantClient {
    pub fn new(
        base_url: impl Into<String>,
        auth: WorkerAuthCredentials,
        timeout: Duration,
    ) -> Self {
        Self {
            base_url: base_url.into(),
            auth,
            timeout,
        }
    }
}

impl GrantClient for HttpControlPlaneGrantClient {
    async fn acquire_read_grant(
        &self,
        request: &ReadGrantRequest,
    ) -> Result<GrantResolution, VantageError> {
        let url = format!(
            "{}/v1/media/workers/read-grants",
            self.base_url.trim_end_matches('/')
        );
        let auth = self.auth.clone();
        let req_clone = request.clone();
        let timeout = self.timeout;
        tokio::task::spawn_blocking(move || execute_grant_post(&url, &auth, &req_clone, timeout))
            .await
            .map_err(|err| VantageError::transport(format!("grant HTTP task panicked: {err}")))?
    }
}

fn execute_grant_post(
    url: &str,
    auth: &WorkerAuthCredentials,
    request: &ReadGrantRequest,
    timeout: Duration,
) -> Result<GrantResolution, VantageError> {
    let agent = ureq::config::Config::builder()
        .http_status_as_error(false)
        .timeout_global(Some(timeout))
        .build()
        .new_agent();

    let bearer = format!("Bearer {}", auth.token());
    let mut response = agent
        .post(url)
        .header("Content-Type", "application/json")
        .header("Accept", "application/json")
        .header(HEADER_CONTROL_PLANE_AUTH, &bearer)
        .header(HEADER_DEPLOYMENT_REF, auth.deployment_ref())
        .header(HEADER_MEDIA_WORKER_GENERATION, auth.generation())
        .send_json(request)
        .map_err(|err| {
            VantageError::transport(format!(
                "POST /v1/media/workers/read-grants transport failed: {err}"
            ))
        })?;

    let status = response.status().as_u16();
    let mut raw_body = Vec::new();
    response
        .body_mut()
        .as_reader()
        .take((MAX_GRANT_RESPONSE_BYTES + 1) as u64)
        .read_to_end(&mut raw_body)
        .map_err(|err| {
            VantageError::transport(format!("failed reading read-grants response body: {err}"))
        })?;

    if raw_body.len() > MAX_GRANT_RESPONSE_BYTES {
        return Err(VantageError::control_plane_rejected(
            status,
            "read-grants response exceeded 512 KiB bound",
        ));
    }

    if status == 410 {
        return Ok(GrantResolution::Gone);
    }

    if status != 200 {
        let reason = extract_status_reason(&raw_body);
        return Err(VantageError::control_plane_rejected(status, reason));
    }

    let plan: ReadGrantPlan = serde_json::from_slice(&raw_body).map_err(|err| {
        VantageError::control_plane_rejected(200, format!("invalid read-grants JSON: {err}"))
    })?;
    plan.validate_for_request(request)?;
    Ok(GrantResolution::Admitted(Box::new(plan)))
}

fn extract_status_reason(raw_body: &[u8]) -> String {
    if let Ok(val) = serde_json::from_slice::<serde_json::Value>(raw_body)
        && let Some(reason) = val
            .get("status")
            .or_else(|| val.get("error"))
            .and_then(|v| v.as_str())
    {
        return reason.to_string();
    }
    "read_grant_rejected".to_string()
}

/// Verified `media.m4s` fragment slice bytes after passing SHA-256 verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedFragmentBytes {
    pub sequence: u32,
    pub start_ns: u64,
    pub duration_ns: u64,
    pub sha256: String,
    pub bytes: Vec<u8>,
}

/// Verified `init.mp4` and fragment slices ready for CMAF parsing and keyframe decode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedKeyframeBlock {
    init_bytes: Vec<u8>,
    fragments: Vec<VerifiedFragmentBytes>,
}

impl VerifiedKeyframeBlock {
    /// Constructs a [`VerifiedKeyframeBlock`] ONLY if `init.mp4` and every sampled fragment
    /// match their expected SHA-256 hex digests.
    pub fn from_unverified(
        init_bytes: Vec<u8>,
        expected_init_sha256: &str,
        raw_fragments: Vec<(FragmentSlicePlan, Vec<u8>)>,
    ) -> Result<Self, VantageError> {
        verify_sha256_hex(&init_bytes, expected_init_sha256, "init.mp4")?;
        let mut verified = Vec::with_capacity(raw_fragments.len());
        for (meta, bytes) in raw_fragments {
            verify_sha256_hex(&bytes, &meta.sha256, &format!("fragment:{}", meta.sequence))?;
            verified.push(VerifiedFragmentBytes {
                sequence: meta.sequence,
                start_ns: meta.start_ns,
                duration_ns: meta.duration_ns,
                sha256: meta.sha256,
                bytes,
            });
        }
        verified.sort_by_key(|f| f.sequence);
        Ok(Self {
            init_bytes,
            fragments: verified,
        })
    }

    pub fn init_bytes(&self) -> &[u8] {
        &self.init_bytes
    }

    pub fn fragments(&self) -> &[VerifiedFragmentBytes] {
        &self.fragments
    }
}

/// Verifies `bytes` match a 64-character lowercase hex SHA-256 digest.
pub fn verify_sha256_hex(
    bytes: &[u8],
    expected_hex: &str,
    target: &str,
) -> Result<(), VantageError> {
    validate_sha256_hex(expected_hex, "sha256")?;
    let actual_hex = hex::encode(Sha256::digest(bytes));
    if actual_hex != expected_hex {
        return Err(VantageError::integrity(format!(
            "sha256_mismatch on {target}: expected {expected_hex}, got {actual_hex}"
        )));
    }
    Ok(())
}

/// Coalesces fragment byte ranges into chunks `<= 4 MiB` with `<= 256 KiB` gap tolerance.
pub fn coalesce_fragment_ranges(
    fragments: &[FragmentSlicePlan],
) -> Result<Vec<CoalescedRange>, VantageError> {
    if fragments.is_empty() {
        return Ok(Vec::new());
    }
    let mut sorted = fragments.to_vec();
    sorted.sort_by_key(|f| f.offset);

    let mut pending: Vec<(u64, u64, Vec<FragmentSlicePlan>)> = Vec::new();
    for frag in sorted {
        if frag.length == 0 || frag.length > MAX_COALESCED_RANGE_BYTES {
            return Err(VantageError::integrity(format!(
                "fragment length {} outside 1..={MAX_COALESCED_RANGE_BYTES}",
                frag.length
            )));
        }
        validate_sha256_hex(&frag.sha256, "fragment.sha256")?;
        let frag_last = frag
            .offset
            .checked_add(frag.length - 1)
            .ok_or_else(|| VantageError::integrity("fragment offset overflow"))?;

        match pending.last_mut() {
            Some((first, last, items)) if frag.offset > *last => {
                let gap = frag.offset - (*last + 1);
                let merged_len = frag_last - *first + 1;
                if gap <= MAX_COALESCE_GAP_BYTES && merged_len <= MAX_COALESCED_RANGE_BYTES {
                    *last = frag_last;
                    items.push(frag);
                } else {
                    pending.push((frag.offset, frag_last, vec![frag]));
                }
            }
            None | Some(_) => pending.push((frag.offset, frag_last, vec![frag])),
        }
    }

    Ok(pending
        .into_iter()
        .map(|(first, last, frags)| {
            let length = last - first + 1;
            let fragment_sequences = frags.iter().map(|f| f.sequence).collect();
            let slices = frags
                .into_iter()
                .map(|f| RangeSlice {
                    sequence: f.sequence,
                    offset: f.offset,
                    relative_offset: f.offset - first,
                    length: f.length,
                    start_ns: f.start_ns,
                    duration_ns: f.duration_ns,
                    sha256: f.sha256,
                })
                .collect();
            CoalescedRange {
                first,
                last,
                length,
                fragment_sequences,
                slices,
            }
        })
        .collect())
}

pub fn extract_and_verify_slices(
    chunk_bytes: &[u8],
    range: &CoalescedRange,
) -> Result<Vec<VerifiedFragmentBytes>, VantageError> {
    if range.length > MAX_COALESCED_RANGE_BYTES {
        return Err(VantageError::integrity(format!(
            "coalesced range {} exceeds {MAX_COALESCED_RANGE_BYTES}",
            range.length
        )));
    }
    let mut out = Vec::with_capacity(range.slices.len());
    for slice in &range.slices {
        let start = usize::try_from(slice.relative_offset)
            .map_err(|_| VantageError::integrity("slice offset overflows usize"))?;
        let len = usize::try_from(slice.length)
            .map_err(|_| VantageError::integrity("slice length overflows usize"))?;
        let end = start
            .checked_add(len)
            .ok_or_else(|| VantageError::integrity("slice range overflows usize"))?;
        if end > chunk_bytes.len() {
            return Err(VantageError::integrity(format!(
                "slice {} ({start}..{end}) out of bounds for chunk {} bytes",
                slice.sequence,
                chunk_bytes.len()
            )));
        }
        let frag_bytes = &chunk_bytes[start..end];
        verify_sha256_hex(
            frag_bytes,
            &slice.sha256,
            &format!("fragment:{}", slice.sequence),
        )?;
        out.push(VerifiedFragmentBytes {
            sequence: slice.sequence,
            start_ns: slice.start_ns,
            duration_ns: slice.duration_ns,
            sha256: slice.sha256.clone(),
            bytes: frag_bytes.to_vec(),
        });
    }
    Ok(out)
}

pub trait FragmentStore: Send + Sync {
    fn fetch_verified_block(
        &self,
        plan: &ReadGrantPlan,
    ) -> impl Future<Output = Result<VerifiedKeyframeBlock, VantageError>> + Send;
}

/// Presigned HTTP `Range` reader for `:archive` grants.
#[derive(Debug, Clone)]
pub struct PresignedArchiveReader {
    timeout: Duration,
}

impl Default for PresignedArchiveReader {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(15),
        }
    }
}

impl PresignedArchiveReader {
    pub fn new(timeout: Duration) -> Self {
        Self { timeout }
    }

    pub async fn fetch_archive_plan(
        &self,
        plan: &ReadGrantPlan,
    ) -> Result<VerifiedKeyframeBlock, VantageError> {
        let archive = plan
            .archive
            .as_ref()
            .ok_or_else(|| VantageError::integrity("archive plan missing archive target"))?;
        let scope = plan
            .grant
            .as_ref()
            .ok_or_else(|| VantageError::integrity("archive plan missing broker grant scope"))?;
        scope.validate_reader_only()?;

        let (init_url, media_url) = plan.resolve_presigned_urls()?.ok_or_else(|| {
            VantageError::transport(
                "archive read grant missing pre-signed init/media URLs (external workers require presigned URLs)",
            )
        })?;

        let coalesced = if plan.coalesced_ranges.is_empty() {
            coalesce_fragment_ranges(&plan.fragments)?
        } else {
            validate_coalesced_ranges(&plan.coalesced_ranges)?;
            plan.coalesced_ranges.clone()
        };

        let init_len = plan.init.length;
        if init_len == 0 || init_len > MAX_INIT_SEGMENT_BYTES {
            return Err(VantageError::integrity(format!(
                "init.mp4 length {init_len} outside 1..={MAX_INIT_SEGMENT_BYTES}"
            )));
        }

        let plan_clone = plan.clone();
        let archive_clone = archive.clone();
        let scope_clone = scope.clone();
        let timeout = self.timeout;
        tokio::task::spawn_blocking(move || {
            execute_presigned_ranged_reads(
                &plan_clone,
                &archive_clone,
                &scope_clone,
                &init_url,
                &media_url,
                &coalesced,
                timeout,
            )
        })
        .await
        .map_err(|err| VantageError::transport(format!("archive reader panicked: {err}")))?
    }
}

fn validate_coalesced_ranges(ranges: &[CoalescedRange]) -> Result<(), VantageError> {
    for range in ranges {
        if range.length == 0 || range.length > MAX_COALESCED_RANGE_BYTES {
            return Err(VantageError::integrity(format!(
                "coalesced range length {} outside 1..={MAX_COALESCED_RANGE_BYTES}",
                range.length
            )));
        }
        if range.last < range.first || (range.last - range.first + 1) != range.length {
            return Err(VantageError::integrity(
                "coalesced range bounds (first, last, length) are inconsistent",
            ));
        }
        for slice in &range.slices {
            validate_sha256_hex(&slice.sha256, "slice.sha256")?;
        }
    }
    Ok(())
}

fn split_host_port(host_port: &str, default_port: u16) -> Result<(String, u16), VantageError> {
    if let Some((host, port_str)) = host_port.rsplit_once(':')
        && !host.contains(':')
    {
        let port = port_str
            .parse::<u16>()
            .map_err(|_| VantageError::integrity(format!("invalid endpoint port '{port_str}'")))?;
        if port == 0 {
            return Err(VantageError::integrity("endpoint port cannot be 0"));
        }
        return Ok((host.to_string(), port));
    }
    Ok((host_port.to_string(), default_port))
}

fn execute_presigned_ranged_reads(
    plan: &ReadGrantPlan,
    archive: &ArchiveGrantTarget,
    scope: &BrokerGrantScope,
    init_presigned: &RedactedPresignedUrl,
    media_presigned: &RedactedPresignedUrl,
    coalesced: &[CoalescedRange],
    timeout: Duration,
) -> Result<VerifiedKeyframeBlock, VantageError> {
    verify_presigned_url_scope(init_presigned, archive, scope)?;
    verify_presigned_url_scope(media_presigned, archive, scope)?;

    let agent = ureq::config::Config::builder()
        .http_status_as_error(false)
        .max_redirects(0)
        .timeout_global(Some(timeout))
        .build()
        .new_agent();

    let init_etag = plan.init.etag.as_deref().or(archive.init_etag.as_deref());
    let init_bytes =
        fetch_presigned_range_slice(&agent, init_presigned, 0, plan.init.length - 1, init_etag)?;
    verify_sha256_hex(&init_bytes, &plan.init_sha256, "init.mp4")?;

    let media_etag = plan
        .media
        .as_ref()
        .and_then(|m| m.etag.as_deref())
        .or(archive.media_etag.as_deref());
    let mut verified_fragments = Vec::with_capacity(plan.fragments.len());
    for range in coalesced {
        let chunk_bytes = fetch_presigned_range_slice(
            &agent,
            media_presigned,
            range.first,
            range.last,
            media_etag,
        )?;
        let mut verified_slices = extract_and_verify_slices(&chunk_bytes, range)?;
        verified_fragments.append(&mut verified_slices);
    }
    verified_fragments.sort_by_key(|f| f.sequence);

    Ok(VerifiedKeyframeBlock {
        init_bytes,
        fragments: verified_fragments,
    })
}

fn verify_presigned_url_scope(
    presigned: &RedactedPresignedUrl,
    archive: &ArchiveGrantTarget,
    scope: &BrokerGrantScope,
) -> Result<(), VantageError> {
    let raw = presigned.as_str();
    let (scheme, after_scheme) = raw
        .split_once("://")
        .ok_or_else(|| VantageError::integrity("pre-signed URL missing scheme"))?;
    let tls = match scheme.to_ascii_lowercase().as_str() {
        "https" => true,
        "http" => false,
        other => {
            return Err(VantageError::integrity(format!(
                "unsupported pre-signed URL scheme '{other}'"
            )));
        }
    };
    let (authority_and_path, _query) = after_scheme
        .split_once('?')
        .ok_or_else(|| VantageError::integrity("pre-signed URL missing query string"))?;
    let (authority, rel_path) = authority_and_path
        .split_once('/')
        .ok_or_else(|| VantageError::integrity("pre-signed URL missing object path"))?;
    let (host, port) = split_host_port(authority, if tls { 443 } else { 80 })?;
    let ip_addr = host.parse::<IpAddr>().ok();
    if !tls && !ip_addr.is_some_and(|ip| ip.is_loopback()) {
        return Err(VantageError::integrity(format!(
            "plaintext HTTP pre-signed URL host '{host}' is forbidden outside loopback"
        )));
    }
    if !scope.allowed_schemes.is_empty()
        && !scope
            .allowed_schemes
            .iter()
            .any(|s| s.eq_ignore_ascii_case(scheme))
    {
        return Err(VantageError::integrity(format!(
            "pre-signed scheme '{scheme}' not permitted by grant"
        )));
    }
    if !scope.allowed_hosts.is_empty()
        && !scope
            .allowed_hosts
            .iter()
            .any(|h| h.eq_ignore_ascii_case(&host))
    {
        return Err(VantageError::integrity(format!(
            "pre-signed host '{host}' not permitted by grant"
        )));
    }
    if !scope.allowed_ports.is_empty() && !scope.allowed_ports.contains(&port) {
        return Err(VantageError::integrity(format!(
            "pre-signed port {port} not permitted by grant"
        )));
    }
    let full_path = format!("/{rel_path}");
    if !scope.allowed_paths.is_empty()
        && !scope
            .allowed_paths
            .iter()
            .any(|p| full_path.starts_with(p.trim_end_matches('*')))
    {
        return Err(VantageError::integrity(format!(
            "pre-signed path '{full_path}' outside grant allowed_paths (bucket={})",
            archive.bucket
        )));
    }
    Ok(())
}

fn fetch_presigned_range_slice(
    agent: &ureq::Agent,
    presigned: &RedactedPresignedUrl,
    first: u64,
    last: u64,
    etag: Option<&str>,
) -> Result<Vec<u8>, VantageError> {
    let expected_len = usize::try_from(last - first + 1)
        .map_err(|_| VantageError::transport("range length overflow"))?;
    let label = presigned.redacted_target();
    let mut req = agent
        .get(presigned.as_str())
        .header("Range", &format!("bytes={first}-{last}"))
        .header("Accept-Encoding", "identity");
    if let Some(tag) = etag.map(str::trim).filter(|t| !t.is_empty()) {
        req = req.header("If-Match", tag);
    }
    let mut resp = req
        .call()
        .map_err(|err| VantageError::transport(format!("GET '{label}' failed: {err}")))?;
    let status = resp.status().as_u16();
    if status != 206 && !(status == 200 && first == 0) {
        return Err(VantageError::transport(format!(
            "pre-signed GET '{label}' returned HTTP {status}"
        )));
    }
    let mut buf = Vec::new();
    resp.body_mut()
        .as_reader()
        .take((expected_len + 1) as u64)
        .read_to_end(&mut buf)
        .map_err(|err| VantageError::transport(format!("failed reading '{label}': {err}")))?;
    if buf.len() != expected_len {
        return Err(VantageError::transport(format!(
            "pre-signed response length {} != expected {expected_len}",
            buf.len()
        )));
    }
    Ok(buf)
}

/// Local NVR `analysis_read` HTTP/HTTPS reader.
#[derive(Debug, Clone)]
pub struct NvrAnalysisReader {
    pub scheme: String,
    pub port: u16,
    pub timeout: Duration,
    pub explicit_base_url: Option<String>,
    pub host_suffix: Option<String>,
    pub tls_ca_file: Option<PathBuf>,
    pub tls_cert_file: Option<PathBuf>,
    pub tls_key_file: Option<PathBuf>,
    pub auth_token_file: Option<PathBuf>,
}

impl Default for NvrAnalysisReader {
    fn default() -> Self {
        Self {
            scheme: "https".to_string(),
            port: 8444,
            timeout: Duration::from_secs(10),
            explicit_base_url: None,
            host_suffix: None,
            tls_ca_file: None,
            tls_cert_file: None,
            tls_key_file: None,
            auth_token_file: None,
        }
    }
}

impl NvrAnalysisReader {
    pub async fn fetch_local_plan(
        &self,
        plan: &ReadGrantPlan,
    ) -> Result<VerifiedKeyframeBlock, VantageError> {
        let base_url = self.resolve_base_url(plan)?;
        let plan_clone = plan.clone();
        let timeout = self.timeout;
        let tls_ca = self.tls_ca_file.clone();
        let tls_cert = self.tls_cert_file.clone();
        let tls_key = self.tls_key_file.clone();
        let token_file = self.auth_token_file.clone();

        tokio::task::spawn_blocking(move || {
            execute_nvr_local_reads(
                &base_url,
                &plan_clone,
                timeout,
                tls_ca.as_deref(),
                tls_cert.as_deref(),
                tls_key.as_deref(),
                token_file.as_deref(),
            )
        })
        .await
        .map_err(|err| VantageError::transport(format!("NVR reader task panicked: {err}")))?
    }

    pub fn resolve_base_url(&self, plan: &ReadGrantPlan) -> Result<String, VantageError> {
        if let Some(url) = plan.local.as_ref().and_then(|l| l.endpoint.as_deref()) {
            return Ok(url.trim_end_matches('/').to_string());
        }
        if let Some(url) = &self.explicit_base_url {
            return Ok(url.trim_end_matches('/').to_string());
        }
        let member = plan
            .local
            .as_ref()
            .and_then(|l| l.nvr_member.as_deref())
            .or(plan.nvr_member.as_deref())
            .ok_or_else(|| {
                VantageError::transport("local read grant missing nvr_member target hostname")
            })?;
        let host = match &self.host_suffix {
            Some(suffix) if !member.contains('.') => format!("{member}{suffix}"),
            _ => member.to_string(),
        };
        Ok(format!("{}://{}:{}", self.scheme, host, self.port))
    }
}

fn build_nvr_agent(
    timeout: Duration,
    tls_ca_file: Option<&Path>,
    tls_cert_file: Option<&Path>,
    tls_key_file: Option<&Path>,
) -> Result<ureq::Agent, VantageError> {
    let mut builder = ureq::config::Config::builder()
        .http_status_as_error(false)
        .max_redirects(0)
        .timeout_global(Some(timeout));

    if let (Some(ca_path), Some(cert_path), Some(key_path)) =
        (tls_ca_file, tls_cert_file, tls_key_file)
    {
        let ca_pem = std::fs::read(ca_path)
            .map_err(|err| VantageError::transport(format!("failed reading CA PEM: {err}")))?;
        let cert_pem = std::fs::read(cert_path)
            .map_err(|err| VantageError::transport(format!("failed reading cert PEM: {err}")))?;
        let key_pem = std::fs::read(key_path)
            .map_err(|err| VantageError::transport(format!("failed reading key PEM: {err}")))?;

        let ca_certs: Vec<ureq::tls::Certificate<'static>> = ureq::tls::parse_pem(&ca_pem)
            .filter_map(|item| match item.ok()? {
                ureq::tls::PemItem::Certificate(c) => Some(c.to_owned()),
                _ => None,
            })
            .collect();
        let client_certs: Vec<ureq::tls::Certificate<'static>> = ureq::tls::parse_pem(&cert_pem)
            .filter_map(|item| match item.ok()? {
                ureq::tls::PemItem::Certificate(c) => Some(c.to_owned()),
                _ => None,
            })
            .collect();
        let client_key = ureq::tls::parse_pem(&key_pem)
            .find_map(|item| match item.ok()? {
                ureq::tls::PemItem::PrivateKey(k) => Some(k.to_owned()),
                _ => None,
            })
            .ok_or_else(|| VantageError::transport("NVR client key PEM had no private key"))?;

        let tls_cfg = ureq::tls::TlsConfig::builder()
            .root_certs(ureq::tls::RootCerts::new_with_certs(&ca_certs))
            .client_cert(Some(ureq::tls::ClientCert::new_with_certs(
                &client_certs,
                client_key,
            )))
            .build();
        builder = builder.tls_config(tls_cfg);
    }

    Ok(builder.build().new_agent())
}

fn execute_nvr_local_reads(
    base_url: &str,
    plan: &ReadGrantPlan,
    timeout: Duration,
    tls_ca_file: Option<&Path>,
    tls_cert_file: Option<&Path>,
    tls_key_file: Option<&Path>,
    auth_token_file: Option<&Path>,
) -> Result<VerifiedKeyframeBlock, VantageError> {
    let agent = build_nvr_agent(timeout, tls_ca_file, tls_cert_file, tls_key_file)?;
    let bearer = if let Some(path) = auth_token_file {
        Some(
            std::fs::read_to_string(path)
                .map_err(|err| VantageError::transport(format!("failed reading token: {err}")))?
                .trim()
                .to_string(),
        )
    } else {
        None
    };

    let default_init_path = format!("/v1/blocks/{}/init", plan.block_key);
    let init_path = plan
        .init
        .path
        .as_deref()
        .or_else(|| plan.local.as_ref().and_then(|l| l.init_path.as_deref()))
        .unwrap_or(&default_init_path);
    let init_url = append_descriptor_query(
        format!("{base_url}/{}", init_path.trim_start_matches('/')),
        &plan.descriptor_sha256,
    );
    let init_bytes = fetch_nvr_bytes(
        &agent,
        &init_url,
        bearer.as_deref(),
        MAX_INIT_SEGMENT_BYTES as usize,
    )?;
    verify_sha256_hex(&init_bytes, &plan.init_sha256, "init.mp4")?;

    let mut raw_fragments = Vec::with_capacity(plan.fragments.len());
    for frag in &plan.fragments {
        let default_frag_path =
            format!("/v1/blocks/{}/fragments/{}", plan.block_key, frag.sequence);
        let frag_path = frag.path.as_deref().unwrap_or(&default_frag_path);
        let frag_url = append_descriptor_query(
            format!("{base_url}/{}", frag_path.trim_start_matches('/')),
            &plan.descriptor_sha256,
        );
        let bytes = fetch_nvr_bytes(
            &agent,
            &frag_url,
            bearer.as_deref(),
            MAX_COALESCED_RANGE_BYTES as usize,
        )?;
        raw_fragments.push((frag.clone(), bytes));
    }

    VerifiedKeyframeBlock::from_unverified(init_bytes, &plan.init_sha256, raw_fragments)
}

fn append_descriptor_query(url: String, descriptor_sha256: &str) -> String {
    if url.contains("descriptor_sha256=") {
        url
    } else if url.contains('?') {
        format!("{url}&descriptor_sha256={descriptor_sha256}")
    } else {
        format!("{url}?descriptor_sha256={descriptor_sha256}")
    }
}

fn fetch_nvr_bytes(
    agent: &ureq::Agent,
    url: &str,
    bearer_token: Option<&str>,
    max_bytes: usize,
) -> Result<Vec<u8>, VantageError> {
    let mut req = agent
        .get(url)
        .header("X-ServiceRadar-Read-Pool", "analysis_read")
        .header("X-ServiceRadar-Read-Purpose", "analysis_read");
    if let Some(token) = bearer_token {
        req = req.header("Authorization", &format!("Bearer {token}"));
    }
    let mut resp = req
        .call()
        .map_err(|err| VantageError::transport(format!("NVR GET '{url}' failed: {err}")))?;
    let status = resp.status().as_u16();
    if status != 200 && status != 206 {
        return Err(VantageError::transport(format!(
            "NVR GET '{url}' returned HTTP {status}"
        )));
    }
    let mut buf = Vec::new();
    resp.body_mut()
        .as_reader()
        .take((max_bytes + 1) as u64)
        .read_to_end(&mut buf)
        .map_err(|err| VantageError::transport(format!("NVR read failed: {err}")))?;
    if buf.len() > max_bytes {
        return Err(VantageError::integrity(format!(
            "NVR response {} exceeds {max_bytes}",
            buf.len()
        )));
    }
    Ok(buf)
}

#[derive(Debug, Clone, Default)]
pub struct HybridGrantStore {
    pub archive_reader: PresignedArchiveReader,
    pub local_reader: NvrAnalysisReader,
}

impl FragmentStore for HybridGrantStore {
    async fn fetch_verified_block(
        &self,
        plan: &ReadGrantPlan,
    ) -> Result<VerifiedKeyframeBlock, VantageError> {
        match plan.source {
            BackingSource::Archive => self.archive_reader.fetch_archive_plan(plan).await,
            BackingSource::Local => self.local_reader.fetch_local_plan(plan).await,
        }
    }
}
