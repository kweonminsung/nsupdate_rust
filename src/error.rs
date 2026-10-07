use std::fmt;

#[derive(Debug)]
pub enum NsUpdateError {
    InvalidAlgorithm(String),
    Base64DecodeError(base64::DecodeError),
    Io(std::io::Error),
    Parse(ParseError),
    Encode(EncodeError),
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
        }
    }
}

impl std::error::Error for NsUpdateError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidAlgorithm(_) => None,
            Self::Base64DecodeError(error) => Some(error),
            Self::Io(error) => Some(error),
            Self::Parse(error) => Some(error),
            Self::Encode(error) => Some(error),
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
    UnsupportedRecordType(u16),
    Utf8(std::string::FromUtf8Error),
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Incomplete => write!(f, "Incomplete data"),
            Self::InvalidDomainName => write!(f, "Invalid domain name"),
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
