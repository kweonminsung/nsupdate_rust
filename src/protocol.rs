use std::net::Ipv4Addr;

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

#[derive(Debug)]
pub struct DnsRecord {
    pub name: String,
    pub rtype: u16,
    pub rclass: u16,
    pub ttl: u32,
    pub rdata: RData,
}

#[derive(Debug)]
pub enum RData {
    A(Ipv4Addr),
    // Other types can be added here
}

impl DnsRecord {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = encode_domain_name(&self.name);
        bytes.extend_from_slice(&self.rtype.to_be_bytes());
        bytes.extend_from_slice(&self.rclass.to_be_bytes());
        bytes.extend_from_slice(&self.ttl.to_be_bytes());

        let rdata_bytes = match &self.rdata {
            RData::A(addr) => addr.octets().to_vec(),
        };
        bytes.extend_from_slice(&(rdata_bytes.len() as u16).to_be_bytes());
        bytes.extend_from_slice(&rdata_bytes);
        bytes
    }
}

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
