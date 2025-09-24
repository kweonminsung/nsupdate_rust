use std::net::{Ipv4Addr, Ipv6Addr};

// RFC 1035 Section 4.1.1
#[derive(Debug, Default)]
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

pub fn encode_domain_name(name: &str) -> Vec<u8> {
    let mut encoded = Vec::new();
    for label in name.split('.') {
        encoded.push(label.len() as u8);
        encoded.extend_from_slice(label.as_bytes());
    }
    encoded.push(0); // Null terminator for the root
    encoded
}

// RFC 1035 Section 4.1.2
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

// RFC 1035 Section 4.1.3
#[derive(Debug)]
pub struct DnsRecord {
    pub name: String,
    pub rtype: u16,
    pub rclass: u16,
    pub ttl: u32,
    pub rdata: RData,
}

// RFC 1035 Section 3.3.13
#[derive(Debug)]
pub struct Soa {
    pub mname: String,
    pub rname: String,
    pub serial: u32,
    pub refresh: u32,
    pub retry: u32,
    pub expire: u32,
    pub minimum: u32,
}

// RFC 1035 Section 3.3.9
#[derive(Debug)]
pub struct Mx {
    pub preference: u16,
    pub exchange: String,
}

// RFC 2782
#[derive(Debug)]
pub struct Srv {
    pub priority: u16,
    pub weight: u16,
    pub port: u16,
    pub target: String,
}

#[derive(Debug)]
pub enum RData {
    A(Ipv4Addr),
    AAAA(Ipv6Addr),
    CNAME(String),
    MX(Mx),
    NS(String),
    PTR(String),
    SOA(Soa),
    SRV(Srv),
    TXT(String),
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
            RData::MX(mx) => {
                let mut data = Vec::new();
                data.extend_from_slice(&mx.preference.to_be_bytes());
                data.extend_from_slice(&encode_domain_name(&mx.exchange));
                data
            }
            RData::SOA(soa) => {
                let mut data = Vec::new();
                data.extend_from_slice(&encode_domain_name(&soa.mname));
                data.extend_from_slice(&encode_domain_name(&soa.rname));
                data.extend_from_slice(&soa.serial.to_be_bytes());
                data.extend_from_slice(&soa.refresh.to_be_bytes());
                data.extend_from_slice(&soa.retry.to_be_bytes());
                data.extend_from_slice(&soa.expire.to_be_bytes());
                data.extend_from_slice(&soa.minimum.to_be_bytes());
                data
            }
            RData::SRV(srv) => {
                let mut data = Vec::new();
                data.extend_from_slice(&srv.priority.to_be_bytes());
                data.extend_from_slice(&srv.weight.to_be_bytes());
                data.extend_from_slice(&srv.port.to_be_bytes());
                data.extend_from_slice(&encode_domain_name(&srv.target));
                data
            }
            RData::TXT(txt) => {
                let mut data = Vec::new();
                data.push(txt.len() as u8);
                data.extend_from_slice(txt.as_bytes());
                data
            }
        };
        bytes.extend_from_slice(&(rdata_bytes.len() as u16).to_be_bytes());
        bytes.extend_from_slice(&rdata_bytes);
        bytes
    }
}

// RFC 2136
#[derive(Default)]
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
