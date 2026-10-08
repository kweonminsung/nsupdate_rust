use super::{DnsRecord, DnsUpdateMessage, RData};
use crate::EncodeError;

pub(crate) fn checked_count(field: &'static str, length: usize) -> Result<u16, EncodeError> {
    u16::try_from(length).map_err(|_| EncodeError::LengthExceeded {
        field,
        length,
        max: u16::MAX as usize,
    })
}

pub(crate) fn check_message_length(length: usize) -> Result<(), EncodeError> {
    checked_count("DNS message", length).map(|_| ())
}

pub(crate) fn append_message(bytes: &mut Vec<u8>, data: &[u8]) -> Result<(), EncodeError> {
    check_message_length(bytes.len() + data.len())?;
    bytes.extend_from_slice(data);
    Ok(())
}

impl RData {
    pub(crate) fn record_type(&self) -> Option<u16> {
        Some(match self {
            Self::A(_) => 1,
            Self::NS(_) => 2,
            Self::CNAME(_) => 5,
            Self::SOA { .. } => 6,
            Self::PTR(_) => 12,
            Self::MX { .. } => 15,
            Self::TXT(_) => 16,
            Self::AAAA(_) => 28,
            Self::SRV { .. } => 33,
            Self::Empty => return None,
        })
    }
}

impl DnsRecord {
    pub(super) fn validate_data(&self) -> Result<(), EncodeError> {
        // RFC 6895 3.1 reserves 128..=255 for query/meta types. ANY (255)
        // remains valid for name prerequisites and deleting all RRsets.
        if matches!(self.rtype, 0 | 41 | 128..=254 | 65535) {
            return Err(invalid(
                "Reserved and query/meta types cannot be used as record data",
            ));
        }
        if self.ttl > i32::MAX as u32 {
            return Err(invalid("TTL must be in 0..=2147483647"));
        }
        match self.rdata.record_type() {
            Some(rtype) if rtype != self.rtype => Err(invalid("TYPE does not match RDATA")),
            None if !matches!(self.rclass, 254 | 255) || self.ttl != 0 => Err(invalid(
                "Empty RDATA requires class ANY or NONE and TTL zero",
            )),
            _ => Ok(()),
        }
    }

    pub(super) fn validate_prerequisite(&self) -> Result<(), EncodeError> {
        if self.ttl != 0 {
            return Err(invalid("Prerequisite TTL must be zero"));
        }
        match self.rclass {
            1 if self.rdata.record_type().is_some() => Ok(()),
            254 | 255 if matches!(self.rdata, RData::Empty) => Ok(()),
            _ => Err(invalid(
                "Prerequisites require IN with RDATA, or ANY/NONE with empty RDATA",
            )),
        }
    }

    pub(super) fn validate_update(&self) -> Result<(), EncodeError> {
        // RFC 2136 4.2: SOA updates require a nonzero serial.
        if self.rclass == 1 && matches!(self.rdata, RData::SOA { serial: 0, .. }) {
            return Err(invalid("SOA updates require a nonzero serial"));
        }
        match self.rclass {
            1 if self.rdata.record_type().is_some() => Ok(()),
            255 if self.ttl == 0 && matches!(self.rdata, RData::Empty) => Ok(()),
            254 if self.ttl == 0 && self.rdata.record_type().is_some() => Ok(()),
            _ => Err(invalid(
                "Updates require IN additions, ANY empty deletions, or NONE value deletions with TTL zero",
            )),
        }
    }
}

impl DnsUpdateMessage {
    pub(super) fn validate_header(&self) -> Result<(), EncodeError> {
        if self.header.flags != 0x2800 {
            return Err(EncodeError::InvalidMessage(
                "Expected an UPDATE request with zero reserved flags and RCODE".into(),
            ));
        }
        if self.header.qdcount != 1
            || self.header.ancount != checked_count("Prerequisite count", self.prerequisites.len())?
            || self.header.nscount != checked_count("Update count", self.updates.len())?
            || self.header.arcount != checked_count("Additional count", self.additional.len())?
        {
            return Err(EncodeError::InvalidMessage(
                "Header counts do not match the message sections".into(),
            ));
        }
        Ok(())
    }
}

fn invalid(reason: &str) -> EncodeError {
    EncodeError::InvalidRecord(reason.into())
}
