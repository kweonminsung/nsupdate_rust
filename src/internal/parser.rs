use crate::internal::protocol::DnsHeader;
use std::fmt;

/// ---------------------------
/// Error Definitions
/// ---------------------------
#[derive(Debug)]
pub enum ParseError {
    Incomplete,
    InvalidDomainName,
    UnsupportedRecordType(u16),
    Utf8(std::string::FromUtf8Error),
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ParseError::Incomplete => write!(f, "Incomplete data"),
            ParseError::InvalidDomainName => write!(f, "Invalid domain name"),
            ParseError::UnsupportedRecordType(t) => write!(f, "Unsupported record type: {}", t),
            ParseError::Utf8(e) => write!(f, "UTF-8 error: {}", e),
        }
    }
}

impl std::error::Error for ParseError {}
impl From<std::string::FromUtf8Error> for ParseError {
    fn from(err: std::string::FromUtf8Error) -> ParseError {
        ParseError::Utf8(err)
    }
}

/// ---------------------------
/// Basic Response Parser
/// ---------------------------
use crate::internal::protocol::DnsMessage;

impl DnsHeader {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ParseError> {
        if bytes.len() < 12 {
            return Err(ParseError::Incomplete);
        }
        Ok(DnsHeader {
            id: u16::from_be_bytes(bytes[0..2].try_into().unwrap()),
            flags: u16::from_be_bytes(bytes[2..4].try_into().unwrap()),
            qdcount: u16::from_be_bytes(bytes[4..6].try_into().unwrap()),
            ancount: u16::from_be_bytes(bytes[6..8].try_into().unwrap()),
            nscount: u16::from_be_bytes(bytes[8..10].try_into().unwrap()),
            arcount: u16::from_be_bytes(bytes[10..12].try_into().unwrap()),
        })
    }
}

impl DnsMessage {
    /// Simplified parser for BIND response (Header only)
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ParseError> {
        let header = DnsHeader::from_bytes(bytes)?;
        Ok(DnsMessage {
            header,
            questions: Vec::new(),
            updates: Vec::new(),
        })
    }
}
