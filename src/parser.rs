use crate::protocol::{DnsHeader, DnsMessage, DnsQuestion, DnsRecord, Mx, RData, Soa, Srv};
use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};

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

pub fn decode_domain_name(
    bytes: &[u8],
    _original_message: &[u8],
) -> Result<(String, usize), ParseError> {
    let mut name = String::new();
    let mut i = 0;
    let mut jumped = false;
    let mut final_len = 0;

    loop {
        if i >= bytes.len() {
            return Err(ParseError::Incomplete);
        }
        let len = bytes[i] & 0x3F;
        if len == 0 {
            i += 1;
            break;
        }

        if (bytes[i] & 0xC0) == 0xC0 {
            if !jumped {
                final_len = i + 2;
                jumped = true;
            }
            let offset = u16::from_be_bytes([bytes[i] & 0x3F, bytes[i + 1]]) as usize;
            i = offset;
            continue;
        }

        i += 1;
        if i + len as usize > bytes.len() {
            return Err(ParseError::Incomplete);
        }
        let label_bytes = &bytes[i..i + len as usize];
        name.push_str(&String::from_utf8(label_bytes.to_vec())?);
        name.push('.');
        i += len as usize;
    }

    if !jumped {
        final_len = i;
    }

    if name.ends_with('.') {
        name.pop();
    }

    Ok((name, final_len))
}

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

impl DnsQuestion {
    pub fn from_bytes(bytes: &[u8], original_message: &[u8]) -> Result<(Self, usize), ParseError> {
        let (qname, mut cursor) = decode_domain_name(bytes, original_message)?;
        if cursor + 4 > bytes.len() {
            return Err(ParseError::Incomplete);
        }
        let qtype = u16::from_be_bytes(bytes[cursor..cursor + 2].try_into().unwrap());
        cursor += 2;
        let qclass = u16::from_be_bytes(bytes[cursor..cursor + 2].try_into().unwrap());
        cursor += 2;
        Ok((
            DnsQuestion {
                qname,
                qtype,
                qclass,
            },
            cursor,
        ))
    }
}

impl DnsRecord {
    pub fn from_bytes(bytes: &[u8], original_message: &[u8]) -> Result<(Self, usize), ParseError> {
        let (name, mut cursor) = decode_domain_name(bytes, original_message)?;
        if cursor + 10 > bytes.len() {
            return Err(ParseError::Incomplete);
        }
        let rtype = u16::from_be_bytes(bytes[cursor..cursor + 2].try_into().unwrap());
        cursor += 2;
        let rclass = u16::from_be_bytes(bytes[cursor..cursor + 2].try_into().unwrap());
        cursor += 2;
        let ttl = u32::from_be_bytes(bytes[cursor..cursor + 4].try_into().unwrap());
        cursor += 4;
        let rdlength = u16::from_be_bytes(bytes[cursor..cursor + 2].try_into().unwrap()) as usize;
        cursor += 2;

        if cursor + rdlength > bytes.len() {
            return Err(ParseError::Incomplete);
        }
        let rdata_bytes = &bytes[cursor..cursor + rdlength];
        let rdata = RData::from_bytes(rtype, rdata_bytes, original_message)?;
        cursor += rdlength;

        Ok((
            DnsRecord {
                name,
                rtype,
                rclass,
                ttl,
                rdata,
            },
            cursor,
        ))
    }
}

impl RData {
    pub fn from_bytes(
        rtype: u16,
        bytes: &[u8],
        original_message: &[u8],
    ) -> Result<Self, ParseError> {
        match rtype {
            1 => {
                if bytes.len() < 4 {
                    return Err(ParseError::Incomplete);
                }
                Ok(RData::A(Ipv4Addr::new(
                    bytes[0], bytes[1], bytes[2], bytes[3],
                )))
            }
            28 => {
                if bytes.len() < 16 {
                    return Err(ParseError::Incomplete);
                }
                Ok(RData::AAAA(Ipv6Addr::from(
                    <[u8; 16]>::try_from(bytes).unwrap(),
                )))
            }
            5 | 2 | 12 => {
                let (name, _) = decode_domain_name(bytes, original_message)?;
                match rtype {
                    5 => Ok(RData::CNAME(name)),
                    2 => Ok(RData::NS(name)),
                    12 => Ok(RData::PTR(name)),
                    _ => unreachable!(),
                }
            }
            15 => {
                if bytes.len() < 2 {
                    return Err(ParseError::Incomplete);
                }
                let preference = u16::from_be_bytes(bytes[0..2].try_into().unwrap());
                let (exchange, _) = decode_domain_name(&bytes[2..], original_message)?;
                Ok(RData::MX(Mx {
                    preference,
                    exchange,
                }))
            }
            6 => {
                let (mname, mut cursor) = decode_domain_name(bytes, original_message)?;
                let (rname, offset) = decode_domain_name(&bytes[cursor..], original_message)?;
                cursor += offset;
                if cursor + 20 > bytes.len() {
                    return Err(ParseError::Incomplete);
                }
                let serial = u32::from_be_bytes(bytes[cursor..cursor + 4].try_into().unwrap());
                cursor += 4;
                let refresh = u32::from_be_bytes(bytes[cursor..cursor + 4].try_into().unwrap());
                cursor += 4;
                let retry = u32::from_be_bytes(bytes[cursor..cursor + 4].try_into().unwrap());
                cursor += 4;
                let expire = u32::from_be_bytes(bytes[cursor..cursor + 4].try_into().unwrap());
                cursor += 4;
                let minimum = u32::from_be_bytes(bytes[cursor..cursor + 4].try_into().unwrap());
                Ok(RData::SOA(Soa {
                    mname,
                    rname,
                    serial,
                    refresh,
                    retry,
                    expire,
                    minimum,
                }))
            }
            33 => {
                if bytes.len() < 6 {
                    return Err(ParseError::Incomplete);
                }
                let priority = u16::from_be_bytes(bytes[0..2].try_into().unwrap());
                let weight = u16::from_be_bytes(bytes[2..4].try_into().unwrap());
                let port = u16::from_be_bytes(bytes[4..6].try_into().unwrap());
                let (target, _) = decode_domain_name(&bytes[6..], original_message)?;
                Ok(RData::SRV(Srv {
                    priority,
                    weight,
                    port,
                    target,
                }))
            }
            16 => {
                if bytes.is_empty() {
                    return Err(ParseError::Incomplete);
                }
                let len = bytes[0] as usize;
                if bytes.len() < 1 + len {
                    return Err(ParseError::Incomplete);
                }
                Ok(RData::TXT(String::from_utf8(bytes[1..1 + len].to_vec())?))
            }
            _ => Err(ParseError::UnsupportedRecordType(rtype)),
        }
    }
}

impl DnsMessage {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ParseError> {
        let header = DnsHeader::from_bytes(bytes)?;
        let mut cursor = 12;

        let mut questions = Vec::new();
        for _ in 0..header.qdcount {
            let (question, offset) = DnsQuestion::from_bytes(&bytes[cursor..], bytes)?;
            questions.push(question);
            cursor += offset;
        }

        // In RFC 2136, updates are in the "update" section (nscount)
        let mut updates = Vec::new();
        for _ in 0..header.nscount {
            let (record, offset) = DnsRecord::from_bytes(&bytes[cursor..], bytes)?;
            updates.push(record);
            cursor += offset;
        }

        Ok(DnsMessage {
            header,
            questions,
            updates,
        })
    }
}
