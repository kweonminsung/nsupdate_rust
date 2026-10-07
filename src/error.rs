use std::fmt;

#[derive(Debug)]
pub enum NsUpdateError {
    InvalidAlgorithm(String),
    Base64DecodeError(base64::DecodeError),
    Io(std::io::Error),
    Parse(ParseError),
    Encode(EncodeError),
    Auth(AuthError),
    TruncatedResponse,
    InvalidTimeout,
    Timeout,
}

impl fmt::Display for NsUpdateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidAlgorithm(algorithm) => {
                write!(f, "Unsupported TSIG algorithm: {algorithm}")
            }
            Self::Base64DecodeError(error) => write!(f, "Invalid base64 TSIG key: {error}"),
            Self::Io(error) => write!(f, "IO error: {error}"),
            Self::Parse(error) => write!(f, "Parse error: {error}"),
            Self::Encode(error) => write!(f, "Encode error: {error}"),
            Self::Auth(error) => write!(f, "Authentication error: {error}"),
            Self::TruncatedResponse => write!(f, "Truncated DNS response; TCP is required"),
            Self::InvalidTimeout => {
                write!(f, "Timeout must be positive and fit the platform clock")
            }
            Self::Timeout => write!(f, "DNS update timed out"),
        }
    }
}

impl std::error::Error for NsUpdateError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidAlgorithm(_)
            | Self::TruncatedResponse
            | Self::InvalidTimeout
            | Self::Timeout => None,
            Self::Base64DecodeError(error) => Some(error),
            Self::Io(error) => Some(error),
            Self::Parse(error) => Some(error),
            Self::Encode(error) => Some(error),
            Self::Auth(error) => Some(error),
        }
    }
}

impl From<std::io::Error> for NsUpdateError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<ParseError> for NsUpdateError {
    fn from(error: ParseError) -> Self {
        Self::Parse(error)
    }
}

impl From<base64::DecodeError> for NsUpdateError {
    fn from(error: base64::DecodeError) -> Self {
        Self::Base64DecodeError(error)
    }
}

impl From<EncodeError> for NsUpdateError {
    fn from(error: EncodeError) -> Self {
        Self::Encode(error)
    }
}

/// A request cannot be represented as a valid DNS UPDATE message.
#[derive(Debug, PartialEq, Eq)]
pub enum EncodeError {
    InvalidDomainName(String),
    InvalidRecord(String),
    InvalidMessage(String),
    LengthExceeded {
        field: &'static str,
        length: usize,
        max: usize,
    },
}

impl fmt::Display for EncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidDomainName(reason) => write!(f, "Invalid domain name: {reason}"),
            Self::InvalidRecord(reason) => write!(f, "Invalid record: {reason}"),
            Self::InvalidMessage(reason) => write!(f, "Invalid message: {reason}"),
            Self::LengthExceeded { field, length, max } => {
                write!(f, "{field} length {length} exceeds {max}")
            }
        }
    }
}

impl std::error::Error for EncodeError {}

#[derive(Debug)]
pub enum ParseError {
    Incomplete,
    InvalidDomainName,
    InvalidMessage(&'static str),
    UnsupportedRecordType(u16),
    Utf8(std::string::FromUtf8Error),
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Incomplete => write!(f, "Incomplete data"),
            Self::InvalidDomainName => write!(f, "Invalid domain name"),
            Self::InvalidMessage(reason) => write!(f, "Invalid DNS message: {reason}"),
            Self::UnsupportedRecordType(record_type) => {
                write!(f, "Unsupported record type: {record_type}")
            }
            Self::Utf8(error) => write!(f, "UTF-8 error: {error}"),
        }
    }
}

impl std::error::Error for ParseError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Utf8(error) => Some(error),
            _ => None,
        }
    }
}

impl From<std::string::FromUtf8Error> for ParseError {
    fn from(error: std::string::FromUtf8Error) -> Self {
        Self::Utf8(error)
    }
}

impl From<AuthError> for NsUpdateError {
    fn from(error: AuthError) -> Self {
        Self::Auth(error)
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum AuthError {
    MissingTsig,
    UnexpectedTsig,
    KeyMismatch,
    AlgorithmMismatch,
    InvalidMacLength,
    InvalidMac,
    TimeOutsideWindow,
    ResponseMismatch(&'static str),
    /// An authenticated TSIG error from the server.
    ServerError {
        code: u16,
        server_time: Option<u64>,
    },
}

impl fmt::Display for AuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingTsig => write!(f, "Response has no TSIG"),
            Self::UnexpectedTsig => write!(f, "Unsigned request received a TSIG response"),
            Self::KeyMismatch => write!(f, "TSIG key name differs from the request"),
            Self::AlgorithmMismatch => write!(f, "TSIG algorithm differs from the request"),
            Self::InvalidMacLength => write!(f, "Response requires a full-length TSIG MAC"),
            Self::InvalidMac => write!(f, "TSIG MAC verification failed"),
            Self::TimeOutsideWindow => write!(f, "TSIG time is outside its validity window"),
            Self::ResponseMismatch(reason) => {
                write!(f, "Response does not match the request: {reason}")
            }
            Self::ServerError { code, server_time } => {
                write!(f, "Authenticated TSIG error {code}")?;
                if let Some(time) = server_time {
                    write!(f, " (server UNIX time {time})")?;
                }
                Ok(())
            }
        }
    }
}

impl std::error::Error for AuthError {}
