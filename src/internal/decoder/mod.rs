use crate::error::ParseError;
use crate::internal::protocol::{DnsHeader, DnsMessage};

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

#[cfg(test)]
mod tests;
