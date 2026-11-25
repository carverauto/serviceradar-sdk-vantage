// SPDX-License-Identifier: Apache-2.0

//! Typed error definitions for `serviceradar-vantage-sdk`.

use thiserror::Error;

/// Error category for Vantage SDK operations.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum VantageErrorKind {
    #[error("invalid configuration: {0}")]
    InvalidConfiguration(String),
    #[error("protocol validation error: {0}")]
    Protocol(String),
    #[error("invalid frame: {0}")]
    InvalidFrame(String),
    #[error("invalid container: {0}")]
    InvalidContainer(String),
    #[error("decode error ({reason}): {detail}")]
    Decode { reason: String, detail: String },
    #[error("integrity verification failed: {0}")]
    Integrity(String),
    #[error("read grant rejected (HTTP {status}): {reason}")]
    ControlPlaneRejected { status: u16, reason: String },
    #[error("storage or HTTP transport error: {0}")]
    Transport(String),
    #[error("NATS / JetStream error: {0}")]
    Nats(String),
    #[error("thumbnail / crop error: {0}")]
    Crop(String),
    #[error("worker handler error: {0}")]
    Handler(String),
    #[error("local harness error: {0}")]
    Harness(String),
}

/// Top-level error returned by `serviceradar-vantage-sdk` APIs.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("{0}")]
pub struct VantageError(#[from] pub VantageErrorKind);

impl VantageError {
    pub fn invalid_configuration(detail: impl Into<String>) -> Self {
        Self(VantageErrorKind::InvalidConfiguration(detail.into()))
    }

    pub fn protocol(detail: impl Into<String>) -> Self {
        Self(VantageErrorKind::Protocol(detail.into()))
    }

    pub fn invalid_frame(detail: impl Into<String>) -> Self {
        Self(VantageErrorKind::InvalidFrame(detail.into()))
    }

    pub fn invalid_container(detail: impl Into<String>) -> Self {
        Self(VantageErrorKind::InvalidContainer(detail.into()))
    }

    pub fn decode(reason: impl Into<String>, detail: impl Into<String>) -> Self {
        Self(VantageErrorKind::Decode {
            reason: reason.into(),
            detail: detail.into(),
        })
    }

    pub fn integrity(detail: impl Into<String>) -> Self {
        Self(VantageErrorKind::Integrity(detail.into()))
    }

    pub fn control_plane_rejected(status: u16, reason: impl Into<String>) -> Self {
        Self(VantageErrorKind::ControlPlaneRejected {
            status,
            reason: reason.into(),
        })
    }

    pub fn transport(detail: impl Into<String>) -> Self {
        Self(VantageErrorKind::Transport(detail.into()))
    }

    pub fn nats(detail: impl Into<String>) -> Self {
        Self(VantageErrorKind::Nats(detail.into()))
    }

    pub fn crop(detail: impl Into<String>) -> Self {
        Self(VantageErrorKind::Crop(detail.into()))
    }

    pub fn handler(detail: impl Into<String>) -> Self {
        Self(VantageErrorKind::Handler(detail.into()))
    }

    pub fn harness(detail: impl Into<String>) -> Self {
        Self(VantageErrorKind::Harness(detail.into()))
    }

    pub fn kind(&self) -> &VantageErrorKind {
        &self.0
    }
}
