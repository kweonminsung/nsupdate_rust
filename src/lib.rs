use std::fmt;
use std::net::SocketAddr;
use tokio::net::UdpSocket;

pub mod parser;
pub mod protocol;
use parser::ParseError;
use protocol::{DnsHeader, DnsMessage, DnsQuestion, DnsRecord, RData};

#[derive(Debug)]
pub enum NsUpdateError {
    Io(std::io::Error),
    Parse(ParseError),
}

impl fmt::Display for NsUpdateError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            NsUpdateError::Io(e) => write!(f, "IO error: {}", e),
            NsUpdateError::Parse(e) => write!(f, "Parse error: {}", e),
        }
    }
}

impl std::error::Error for NsUpdateError {}

impl From<std::io::Error> for NsUpdateError {
    fn from(err: std::io::Error) -> NsUpdateError {
        NsUpdateError::Io(err)
    }
}

impl From<ParseError> for NsUpdateError {
    fn from(err: ParseError) -> NsUpdateError {
        NsUpdateError::Parse(err)
    }
}

pub struct NsUpdateClient {
    server: SocketAddr,
}

impl NsUpdateClient {
    pub fn new(server: SocketAddr) -> Self {
        Self { server }
    }

    pub async fn send(&self, message: &DnsMessage) -> Result<DnsMessage, NsUpdateError> {
        let request_bytes = message.to_bytes();
        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        socket.connect(self.server).await?;
        socket.send(&request_bytes).await?;

        let mut response_bytes = [0u8; 512];
        let len = socket.recv(&mut response_bytes).await?;

        let response = DnsMessage::from_bytes(&response_bytes[..len])?;
        Ok(response)
    }
}

pub struct UpdateMessageBuilder {
    zone: String,
    records_to_add: Vec<DnsRecord>,
}

impl UpdateMessageBuilder {
    pub fn new(zone: String) -> Self {
        Self {
            zone,
            records_to_add: Vec::new(),
        }
    }

    pub fn add_record(mut self, name: String, ttl: u32, rdata: RData) -> Self {
        let rtype = match rdata {
            RData::A(_) => 1,
            RData::AAAA(_) => 28,
            RData::CNAME(_) => 5,
            RData::MX(_) => 15,
            RData::NS(_) => 2,
            RData::PTR(_) => 12,
            RData::SOA(_) => 6,
            RData::SRV(_) => 33,
            RData::TXT(_) => 16,
        };
        self.records_to_add.push(DnsRecord {
            name,
            rtype,
            rclass: 1, // IN
            ttl,
            rdata,
        });
        self
    }

    pub fn build(self) -> DnsMessage {
        let header = DnsHeader {
            id: rand::random(),
            flags: 0x2800, // Update operation (0 0101 0 0 0 0 000 0000)
            qdcount: 1,
            ancount: 0,
            nscount: self.records_to_add.len() as u16,
            arcount: 0,
        };

        let question = DnsQuestion {
            qname: self.zone,
            qtype: 6,  // SOA
            qclass: 1, // IN
        };

        DnsMessage {
            header,
            questions: vec![question],
            updates: self.records_to_add,
        }
    }
}
