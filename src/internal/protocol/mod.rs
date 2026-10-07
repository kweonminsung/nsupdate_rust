mod name;
mod validation;

use crate::EncodeError;
pub(crate) use name::encode_domain_name;
use name::is_in_zone;
pub(crate) use validation::{append_message, check_message_length, checked_count};

use std::net::{Ipv4Addr, Ipv6Addr};

// RFC 1035 Section 4.1.1 – DNS Header
#[derive(Debug, Default, PartialEq, Eq)]
pub struct DnsHeader {
    pub id: u16,
    pub flags: u16,
    pub qdcount: u16,
    pub ancount: u16,
    pub nscount: u16,
    pub arcount: u16,
}

impl DnsHeader {
    pub fn to_bytes(&self) -> [u8; 12] {
        let mut bytes = [0u8; 12];
        bytes[0..2].copy_from_slice(&self.id.to_be_bytes());
        bytes[2..4].copy_from_slice(&self.flags.to_be_bytes());
        bytes[4..6].copy_from_slice(&self.qdcount.to_be_bytes());
        bytes[6..8].copy_from_slice(&self.ancount.to_be_bytes());
        bytes[8..10].copy_from_slice(&self.nscount.to_be_bytes());
        bytes[10..12].copy_from_slice(&self.arcount.to_be_bytes());
        bytes
    }
}

// RFC 1035 Section 4.1.2 – Question Section
#[derive(Debug)]
pub struct DnsQuestion {
    pub qname: String,
    pub qtype: u16,
    pub qclass: u16,
}

impl DnsQuestion {
    pub fn to_bytes(&self) -> Result<Vec<u8>, EncodeError> {
        let mut bytes = encode_domain_name(&self.qname)?;
        bytes.extend_from_slice(&self.qtype.to_be_bytes());
        bytes.extend_from_slice(&self.qclass.to_be_bytes());
        Ok(bytes)
    }
}

// RFC 1035 Section 4.1.3 – Resource Record
#[derive(Debug)]
pub struct DnsRecord {
    pub name: String,
    pub rtype: u16,
    pub rclass: u16,
    pub ttl: u32,
    pub rdata: RData,
}

// RFC 1035 Section 3.3 – RDATA Types
#[derive(Debug)]
pub enum RData {
    A(Ipv4Addr),
    AAAA(Ipv6Addr),
    CNAME(String),
    MX {
        preference: u16,
        exchange: String,
    },
    NS(String),
    PTR(String),
    SOA {
        mname: String,
        rname: String,
        serial: u32,
        refresh: u32,
        retry: u32,
        expire: u32,
        minimum: u32,
    },
    SRV {
        priority: u16,
        weight: u16,
        port: u16,
        target: String,
    },
    /// A single UTF-8 character-string, at most 255 bytes (not characters).
    TXT(String),
    /// RFC 2136 삭제용 (RDLENGTH=0로 직렬화)
    Empty,
}

impl DnsRecord {
    pub fn to_bytes(&self) -> Result<Vec<u8>, EncodeError> {
        self.validate_data()?;
        let mut bytes = encode_domain_name(&self.name)?;
        bytes.extend_from_slice(&self.rtype.to_be_bytes());
        bytes.extend_from_slice(&self.rclass.to_be_bytes());
        bytes.extend_from_slice(&self.ttl.to_be_bytes());

        let rdata_bytes = match &self.rdata {
            RData::A(addr) => addr.octets().to_vec(),
            RData::AAAA(addr) => addr.octets().to_vec(),
            RData::CNAME(name) | RData::NS(name) | RData::PTR(name) => encode_domain_name(name)?,
            RData::MX {
                preference,
                exchange,
            } => {
                let mut data = Vec::new();
                data.extend_from_slice(&preference.to_be_bytes());
                data.extend_from_slice(&encode_domain_name(exchange)?);
                data
            }
            RData::SOA {
                mname,
                rname,
                serial,
                refresh,
                retry,
                expire,
                minimum,
            } => {
                let mut data = Vec::new();
                data.extend_from_slice(&encode_domain_name(mname)?);
                data.extend_from_slice(&encode_domain_name(rname)?);
                data.extend_from_slice(&serial.to_be_bytes());
                data.extend_from_slice(&refresh.to_be_bytes());
                data.extend_from_slice(&retry.to_be_bytes());
                data.extend_from_slice(&expire.to_be_bytes());
                data.extend_from_slice(&minimum.to_be_bytes());
                data
            }
            RData::SRV {
                priority,
                weight,
                port,
                target,
            } => {
                let mut data = Vec::new();
                data.extend_from_slice(&priority.to_be_bytes());
                data.extend_from_slice(&weight.to_be_bytes());
                data.extend_from_slice(&port.to_be_bytes());
                data.extend_from_slice(&encode_domain_name(target)?);
                data
            }
            RData::TXT(txt) => {
                let mut data = Vec::new();
                let length = u8::try_from(txt.len()).map_err(|_| EncodeError::LengthExceeded {
                    field: "TXT string",
                    length: txt.len(),
                    max: 255,
                })?;
                data.push(length);
                data.extend_from_slice(txt.as_bytes());
                data
            }
            RData::Empty => Vec::new(),
        };

        let length = checked_count("RDATA", rdata_bytes.len())?;
        bytes.extend_from_slice(&length.to_be_bytes());
        bytes.extend_from_slice(&rdata_bytes);
        Ok(bytes)
    }
}

// RFC 1035 – DNS Message
#[derive(Default, Debug)]
pub struct DnsMessage {
    pub header: DnsHeader,
    pub questions: Vec<DnsQuestion>,
    pub updates: Vec<DnsRecord>,
}

impl DnsMessage {
    pub fn to_bytes(&self) -> Result<Vec<u8>, EncodeError> {
        if self.header.qdcount != checked_count("Question count", self.questions.len())?
            || self.header.nscount != checked_count("Record count", self.updates.len())?
            || self.header.ancount != 0
            || self.header.arcount != 0
        {
            return Err(EncodeError::InvalidMessage(
                "Header counts do not match the message sections".into(),
            ));
        }
        let mut bytes = self.header.to_bytes().to_vec();
        for question in &self.questions {
            append_message(&mut bytes, &question.to_bytes()?)?;
        }
        for record in &self.updates {
            append_message(&mut bytes, &record.to_bytes()?)?;
        }
        Ok(bytes)
    }
}

// RFC 2136 – DNS Update Message
#[derive(Debug)]
pub struct DnsUpdateMessage {
    pub header: DnsHeader,
    pub zone: ZoneSection, // exactly 1 record (name, type = SOA, class = IN)
    pub prerequisites: Vec<DnsRecord>, // optional
    pub updates: Vec<DnsRecord>, // add/delete records
    pub additional: Vec<DnsRecord>,
}

impl DnsUpdateMessage {
    /// Serialize an unsigned IN-class UPDATE request after validating every section.
    /// TSIG is owned by the client and must not be supplied in `additional`.
    pub fn to_bytes(&self) -> Result<Vec<u8>, EncodeError> {
        self.validate_header()?;
        let zone_name = encode_domain_name(&self.zone.zname)?;
        let mut bytes = self.header.to_bytes().to_vec();
        append_message(&mut bytes, &self.zone.to_bytes()?)?;
        for record in &self.prerequisites {
            self.validate_owner(record, &zone_name)?;
            record.validate_prerequisite()?;
            append_message(&mut bytes, &record.to_bytes()?)?;
        }
        for record in &self.updates {
            self.validate_owner(record, &zone_name)?;
            record.validate_update()?;
            append_message(&mut bytes, &record.to_bytes()?)?;
        }
        for record in &self.additional {
            // Supported additional records are ordinary IN records, e.g. glue.
            if record.rclass != 1 || record.rdata.record_type().is_none() {
                return Err(EncodeError::InvalidRecord(
                    "Additional data must contain IN records with RDATA; the client owns TSIG"
                        .into(),
                ));
            }
            append_message(&mut bytes, &record.to_bytes()?)?;
        }
        Ok(bytes)
    }

    fn validate_owner(&self, record: &DnsRecord, zone: &[u8]) -> Result<(), EncodeError> {
        if !is_in_zone(&encode_domain_name(&record.name)?, zone) {
            return Err(EncodeError::InvalidRecord(
                "Record owner is outside the update zone".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct ZoneSection {
    pub zname: String, // ex) "example.com."
    pub zclass: u16,   // IN = 1
    pub ztype: u16,    // SOA = 6
}

impl ZoneSection {
    pub fn to_bytes(&self) -> Result<Vec<u8>, EncodeError> {
        if self.ztype != 6 || self.zclass != 1 {
            return Err(EncodeError::InvalidMessage(
                "Zone must have type SOA and class IN".into(),
            ));
        }
        let mut bytes = encode_domain_name(&self.zname)?;
        bytes.extend_from_slice(&self.ztype.to_be_bytes());
        bytes.extend_from_slice(&self.zclass.to_be_bytes());
        Ok(bytes)
    }
}

#[cfg(test)]
mod tests;
