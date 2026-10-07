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

// Encode domain name to DNS wire format (RFC 1035 Section 4.1.2)
pub fn encode_domain_name(name: &str) -> Vec<u8> {
    let mut encoded = Vec::new();
    let trimmed = name.trim_end_matches('.');

    for label in trimmed.split('.') {
        if label.is_empty() {
            continue;
        }
        encoded.push(label.len() as u8);
        encoded.extend_from_slice(label.as_bytes());
    }

    encoded.push(0); // Null terminator for root
    encoded
}

// RFC 1035 Section 4.1.2 – Question Section
#[derive(Debug)]
pub struct DnsQuestion {
    pub qname: String,
    pub qtype: u16,
    pub qclass: u16,
}

impl DnsQuestion {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = encode_domain_name(&self.qname);
        bytes.extend_from_slice(&self.qtype.to_be_bytes());
        bytes.extend_from_slice(&self.qclass.to_be_bytes());
        bytes
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
    TXT(String),
    /// RFC 2136 삭제용 (RDLENGTH=0로 직렬화)
    Empty,
}

impl DnsRecord {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = encode_domain_name(&self.name);
        bytes.extend_from_slice(&self.rtype.to_be_bytes());
        bytes.extend_from_slice(&self.rclass.to_be_bytes());
        bytes.extend_from_slice(&self.ttl.to_be_bytes());

        let rdata_bytes = match &self.rdata {
            RData::A(addr) => addr.octets().to_vec(),
            RData::AAAA(addr) => addr.octets().to_vec(),
            RData::CNAME(name) | RData::NS(name) | RData::PTR(name) => encode_domain_name(name),
            RData::MX {
                preference,
                exchange,
            } => {
                let mut data = Vec::new();
                data.extend_from_slice(&preference.to_be_bytes());
                data.extend_from_slice(&encode_domain_name(exchange));
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
                data.extend_from_slice(&encode_domain_name(mname));
                data.extend_from_slice(&encode_domain_name(rname));
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
                data.extend_from_slice(&encode_domain_name(target));
                data
            }
            RData::TXT(txt) => {
                let mut data = Vec::new();
                data.push(txt.len() as u8);
                data.extend_from_slice(txt.as_bytes());
                data
            }
            RData::Empty => Vec::new(),
        };

        bytes.extend_from_slice(&(rdata_bytes.len() as u16).to_be_bytes());
        bytes.extend_from_slice(&rdata_bytes);
        bytes
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
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = self.header.to_bytes().to_vec();
        for q in &self.questions {
            bytes.extend_from_slice(&q.to_bytes());
        }
        for u in &self.updates {
            bytes.extend_from_slice(&u.to_bytes());
        }
        bytes
    }
}

// RFC 2136 – DNS Update Message
pub struct DnsUpdateMessage {
    pub header: DnsHeader,
    pub zone: ZoneSection, // exactly 1 record (name, type = SOA, class = IN)
    pub prerequisites: Vec<DnsRecord>, // optional
    pub updates: Vec<DnsRecord>, // add/delete records
    pub additional: Vec<DnsRecord>,
}

impl DnsUpdateMessage {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = self.header.to_bytes().to_vec();

        // Zone section (1)
        bytes.extend_from_slice(&self.zone.to_bytes());

        // Prerequisite section (PRCOUNT)
        for p in &self.prerequisites {
            bytes.extend_from_slice(&p.to_bytes());
        }

        // Update section (UPCOUNT)
        for u in &self.updates {
            bytes.extend_from_slice(&u.to_bytes());
        }

        // Additional section (ARCOUNT, TSIG)
        for a in &self.additional {
            bytes.extend_from_slice(&a.to_bytes());
        }

        bytes
    }
}

#[derive(Debug)]
pub struct ZoneSection {
    pub zname: String, // ex) "example.com."
    pub zclass: u16,   // IN = 1
    pub ztype: u16,    // SOA = 6
}

impl ZoneSection {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = encode_domain_name(&self.zname);
        bytes.extend_from_slice(&self.ztype.to_be_bytes());
        bytes.extend_from_slice(&self.zclass.to_be_bytes());
        bytes
    }
}
