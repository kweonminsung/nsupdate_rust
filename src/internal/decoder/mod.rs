mod reader;

use crate::{AuthError, DnsHeader, NsUpdateError, ParseError, UpdateResponse, ZoneSection};
use reader::{Reader, display_name};

impl DnsHeader {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ParseError> {
        let mut reader = Reader::new(bytes, 0, bytes.len());
        Ok(Self {
            id: reader.u16()?,
            flags: reader.u16()?,
            qdcount: reader.u16()?,
            ancount: reader.u16()?,
            nscount: reader.u16()?,
            arcount: reader.u16()?,
        })
    }
}

pub(crate) struct Tsig<'a> {
    pub start: usize,
    pub key_name: Vec<u8>,
    pub algorithm: Vec<u8>,
    pub time_signed: u64,
    pub fudge: u16,
    pub mac: &'a [u8],
    pub original_id: u16,
    pub error: u16,
    pub other: &'a [u8],
}

pub(crate) struct ParsedResponse<'a> {
    pub response: UpdateResponse,
    pub zone_name: Option<Vec<u8>>,
    pub tsig: Option<Tsig<'a>>,
}

impl ParsedResponse<'_> {
    pub(crate) fn validate_request(&self, id: u16, zone_name: &[u8]) -> Result<(), AuthError> {
        let response = &self.response;
        if response.header.id != id {
            return Err(AuthError::ResponseMismatch("message ID"));
        }
        if response.header.flags & 0xf800 != 0xa800 {
            return Err(AuthError::ResponseMismatch("expected an UPDATE response"));
        }
        if let Some(zone) = &response.zone
            && (zone.ztype != 6
                || zone.zclass != 1
                || !self
                    .zone_name
                    .as_ref()
                    .is_some_and(|name| name.eq_ignore_ascii_case(zone_name)))
        {
            return Err(AuthError::ResponseMismatch("zone"));
        }
        Ok(())
    }
}

pub(crate) fn decode_unsigned_response(
    bytes: &[u8],
    id: u16,
    zone: &[u8],
) -> Result<UpdateResponse, NsUpdateError> {
    let parsed = decode(bytes)?;
    parsed.validate_request(id, zone)?;
    if parsed.tsig.is_some() {
        return Err(AuthError::UnexpectedTsig.into());
    }
    if parsed.response.header.flags & 0x0200 != 0 {
        return Err(NsUpdateError::TruncatedResponse);
    }
    Ok(parsed.response)
}

// Scan all sections; TSIG must be unique, last, and cover the original bytes.
pub(crate) fn decode(bytes: &[u8]) -> Result<ParsedResponse<'_>, ParseError> {
    if bytes.len() > 65535 {
        return Err(ParseError::InvalidMessage("Packet exceeds 65535 bytes"));
    }
    let header = DnsHeader::from_bytes(bytes)?;
    if header.qdcount > 1 {
        return Err(ParseError::InvalidMessage("UPDATE has at most one zone"));
    }
    let mut reader = Reader::new(bytes, 12, bytes.len());
    let (zone, zone_name) = if header.qdcount == 1 {
        let name = reader.name(true)?;
        let zone = ZoneSection {
            zname: display_name(&name),
            ztype: reader.u16()?,
            zclass: reader.u16()?,
        };
        (Some(zone), Some(name))
    } else {
        (None, None)
    };
    let mut tsig = None;
    let mut extended_rcode = None;
    for (section, count) in [header.ancount, header.nscount, header.arcount]
        .into_iter()
        .enumerate()
    {
        for index in 0..count {
            let start = reader.position();
            let name = reader.name(true)?;
            let rtype = reader.u16()?;
            let class = reader.u16()?;
            let ttl = reader.u32()?;
            let length = usize::from(reader.u16()?);
            let data_start = reader.position();
            reader.take(length)?;
            let mut data = Reader::new(bytes, data_start, reader.position());
            if rtype == 250 {
                if section != 2 || index + 1 != count || tsig.is_some() {
                    return Err(ParseError::InvalidMessage(
                        "TSIG must be unique and last in Additional",
                    ));
                }
                if class != 255 || ttl != 0 {
                    return Err(ParseError::InvalidMessage(
                        "TSIG requires class ANY and TTL zero",
                    ));
                }
                let algorithm = data.name(false)?;
                let time_signed = data.u48()?;
                let fudge = data.u16()?;
                let mac_length = usize::from(data.u16()?);
                let mac = data.take(mac_length)?;
                let original_id = data.u16()?;
                let error = data.u16()?;
                let other_length = usize::from(data.u16()?);
                let other = data.take(other_length)?;
                data.finish()?;
                if (error == 18 && other.len() != 6) || (error != 18 && !other.is_empty()) {
                    return Err(ParseError::InvalidMessage("Invalid TSIG Other Data length"));
                }
                tsig = Some(Tsig {
                    start,
                    key_name: name,
                    algorithm,
                    time_signed,
                    fudge,
                    mac,
                    original_id,
                    error,
                    other,
                });
            } else if rtype == 41 {
                if section != 2 || name != [0] || extended_rcode.is_some() {
                    return Err(ParseError::InvalidMessage(
                        "Invalid or duplicate OPT record",
                    ));
                }
                extended_rcode = Some((ttl >> 24) as u16);
                while data.position() < reader.position() {
                    data.u16()?; // option code
                    let option_length = usize::from(data.u16()?);
                    data.take(option_length)?;
                }
            }
        }
    }
    reader.finish()?;
    let rcode = (extended_rcode.unwrap_or(0) << 4) | (header.flags & 15);
    Ok(ParsedResponse {
        response: UpdateResponse {
            header,
            zone,
            rcode,
            authenticated: false,
        },
        zone_name,
        tsig,
    })
}

#[cfg(test)]
mod tests;
