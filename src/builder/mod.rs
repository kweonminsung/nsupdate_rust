use crate::EncodeError;
use crate::internal::protocol::{
    DnsHeader, DnsRecord, DnsUpdateMessage, RData, ZoneSection, checked_count,
};

/// Build an IN-class UPDATE in call order. Names are absolute, with an optional trailing dot.
/// Use ASCII presentation names with `\X` or `\DDD` escapes; IDNs use Punycode.
pub struct UpdateMessageBuilder {
    zone: String,
    prerequisites: Vec<DnsRecord>,
    updates: Vec<DnsRecord>,
    error: Option<EncodeError>,
}

impl UpdateMessageBuilder {
    pub fn new(zone: impl Into<String>) -> Self {
        Self {
            zone: zone.into(),
            prerequisites: Vec::new(),
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

    /// Delete only the record with matching RDATA; infer its type from `rdata`.
    pub fn delete_record_value(mut self, name: impl Into<String>, rdata: RData) -> Self {
        let Some(rtype) = rdata.record_type() else {
            self.error.get_or_insert_with(|| {
                EncodeError::InvalidRecord("A value deletion must have RDATA".into())
            });
            return self;
        };
        self.updates.push(DnsRecord {
            name: name.into(),
            rtype,
            rclass: 254,
            ttl: 0,
            rdata,
        });
        self
    }

    /// Require at least one record at this name, regardless of type.
    pub fn require_name_exists(self, name: impl Into<String>) -> Self {
        self.require_empty(name, 255, 255)
    }

    /// Require no records at this name. Records at child names do not count.
    pub fn require_name_absent(self, name: impl Into<String>) -> Self {
        self.require_empty(name, 255, 254)
    }

    /// Require at least one record of this type. ANY (255) is not an RRset type.
    pub fn require_rrset_exists(self, name: impl Into<String>, rtype: u16) -> Self {
        self.require_rrset_presence(name, rtype, 255)
    }

    /// Require no records of this type. ANY (255) is not an RRset type.
    pub fn require_rrset_absent(self, name: impl Into<String>, rtype: u16) -> Self {
        self.require_rrset_presence(name, rtype, 254)
    }

    /// Require an exact RRset match, ignoring order and TTL.
    /// Values must be nonempty and of one type; calls for the same name/type combine.
    pub fn require_rrset_equals(
        mut self,
        name: impl Into<String>,
        values: impl IntoIterator<Item = RData>,
    ) -> Self {
        let name = name.into();
        let mut record_type = None;
        for rdata in values {
            let Some(rtype) = rdata.record_type() else {
                self.error.get_or_insert_with(|| {
                    EncodeError::InvalidRecord("An RRset prerequisite must have RDATA".into())
                });
                return self;
            };
            if record_type.is_some_and(|previous| previous != rtype) {
                self.error.get_or_insert_with(|| {
                    EncodeError::InvalidRecord(
                        "An RRset prerequisite must contain one record type".into(),
                    )
                });
                return self;
            }
            record_type = Some(rtype);
            self.prerequisites.push(DnsRecord {
                name: name.clone(),
                rtype,
                rclass: 1,
                ttl: 0,
                rdata,
            });
        }
        if record_type.is_none() {
            self.error.get_or_insert_with(|| {
                EncodeError::InvalidRecord(
                    "An RRset prerequisite must contain at least one value".into(),
                )
            });
        }
        self
    }

    fn require_rrset_presence(mut self, name: impl Into<String>, rtype: u16, rclass: u16) -> Self {
        if rtype == 255 {
            self.error.get_or_insert_with(|| {
                EncodeError::InvalidRecord("Use a name prerequisite for type ANY".into())
            });
            return self;
        }
        self.require_empty(name, rtype, rclass)
    }

    fn require_empty(mut self, name: impl Into<String>, rtype: u16, rclass: u16) -> Self {
        self.prerequisites.push(DnsRecord {
            name: name.into(),
            rtype,
            rclass,
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
                ancount: checked_count("Prerequisite count", self.prerequisites.len())?,
                nscount: checked_count("Update count", self.updates.len())?,
                arcount: 0,
            },
            zone: ZoneSection {
                zname: self.zone,
                zclass: 1,
                ztype: 6,
            },
            prerequisites: self.prerequisites,
            updates: self.updates,
            additional: Vec::new(),
        };
        message.to_bytes()?;
        Ok(message)
    }
}
