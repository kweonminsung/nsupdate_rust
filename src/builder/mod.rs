use crate::EncodeError;
use crate::internal::protocol::{
    DnsHeader, DnsRecord, DnsUpdateMessage, RData, ZoneSection, checked_count,
};

/// Build an IN-class UPDATE in call order. Names are absolute, with an optional trailing dot.
/// Use ASCII presentation names with `\X` or `\DDD` escapes; IDNs use Punycode.
pub struct UpdateMessageBuilder {
    zone: String,
    updates: Vec<DnsRecord>,
    error: Option<EncodeError>,
}

impl UpdateMessageBuilder {
    pub fn new(zone: impl Into<String>) -> Self {
        Self {
            zone: zone.into(),
            updates: Vec::new(),
            error: None,
        }
    }

    pub fn add_record(mut self, name: impl Into<String>, ttl: u32, rdata: RData) -> Self {
        let Some(rtype) = rdata.record_type() else {
            self.error.get_or_insert_with(|| {
                EncodeError::InvalidRecord("An added record must have RDATA".into())
            });
            return self;
        };
        self.updates.push(DnsRecord {
            name: name.into(),
            rtype,
            rclass: 1,
            ttl,
            rdata,
        });
        self
    }

    /// Delete an entire RRset, or all RRsets at the name when `rtype` is ANY (255).
    pub fn delete_record(mut self, name: impl Into<String>, rtype: u16) -> Self {
        self.updates.push(DnsRecord {
            name: name.into(),
            rtype,
            rclass: 255,
            ttl: 0,
            rdata: RData::Empty,
        });
        self
    }

    /// Validate and build the unsigned request.
    pub fn build(self) -> Result<DnsUpdateMessage, EncodeError> {
        if let Some(error) = self.error {
            return Err(error);
        }
        let message = DnsUpdateMessage {
            header: DnsHeader {
                id: rand::random(),
                flags: 0x2800,
                qdcount: 1,
                ancount: 0,
                nscount: checked_count("Update count", self.updates.len())?,
                arcount: 0,
            },
            zone: ZoneSection {
                zname: self.zone,
                zclass: 1,
                ztype: 6,
            },
            prerequisites: Vec::new(),
            updates: self.updates,
            additional: Vec::new(),
        };
        message.to_bytes()?;
        Ok(message)
    }
}
