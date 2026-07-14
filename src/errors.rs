use std::{fmt, io};

use crate::constants::RESOLVE_TIMEOUT;

#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    Config(String),
    InvalidResolver(String),
    Doh(DohError),
    UdpTimeout,
    UpstreamUnreachable,
    NoHealthyResolvers,
    ResolveTimeout,
}

#[derive(Debug)]
pub enum DohError {
    Timeout,
    Request(reqwest::Error),
    Status(reqwest::StatusCode),
    Body(reqwest::Error),
}

impl fmt::Display for DohError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Timeout => write!(f, "DoH request timed out"),
            Self::Request(err) => write!(f, "DoH request failed: {err}"),
            Self::Status(status) => write!(f, "DoH upstream returned status {status}"),
            Self::Body(err) => write!(f, "failed to read DoH response body: {err}"),
        }
    }
}

impl std::error::Error for DohError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Request(err) | Self::Body(err) => Some(err),
            Self::Timeout | Self::Status(_) => None,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(err) => write!(f, "{err}"),
            Self::Config(msg) => write!(f, "config error: {msg}"),
            Self::InvalidResolver(resolver) => write!(f, "invalid resolver address: {resolver}"),
            Self::Doh(err) => write!(f, "{err}"),
            Self::UdpTimeout => write!(f, "UDP request timed out"),
            Self::UpstreamUnreachable => write!(f, "could not resolve domain upstream"),
            Self::NoHealthyResolvers => {
                write!(
                    f,
                    "all provided DNS upstream resolvers are unhealthy or unreachable"
                )
            }
            Self::ResolveTimeout => write!(f, "resolve timed out after {RESOLVE_TIMEOUT:?}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(err) => Some(err),
            Self::Doh(err) => Some(err),
            _ => None,
        }
    }
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Self {
        Self::Io(err)
    }
}

impl From<DohError> for Error {
    fn from(err: DohError) -> Self {
        Self::Doh(err)
    }
}
