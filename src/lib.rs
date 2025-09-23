use std::fmt;
use std::net::{Ipv4Addr, SocketAddr};
use tokio::net::UdpSocket;

pub mod protocol;
use protocol::{DnsHeader, DnsMessage, DnsQuestion, DnsRecord, RData};

#[derive(Debug)]
pub enum NsUpdateError {
    Io(std::io::Error),
    // Add other error types here
}

impl fmt::Display for NsUpdateError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            NsUpdateError::Io(e) => write!(f, "IO error: {}", e),
        }
    }
}

impl std::error::Error for NsUpdateError {}

impl From<std::io::Error> for NsUpdateError {
    fn from(err: std::io::Error) -> NsUpdateError {
        NsUpdateError::Io(err)
    }
}

pub struct NsUpdateClient {
    server: SocketAddr,
}

impl NsUpdateClient {
    pub fn new(server: SocketAddr) -> Self {
        Self { server }
    }

    pub async fn send(&self, message: &DnsMessage) -> Result<(), NsUpdateError> {
        let request_bytes = message.to_bytes();
        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        socket.connect(self.server).await?;
        socket.send(&request_bytes).await?;
        // TODO: Receive and parse response
        Ok(())
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

    pub fn add_a_record(mut self, name: String, ip: Ipv4Addr) -> Self {
        self.records_to_add.push(DnsRecord {
            name,
            rtype: 1,  // A
            rclass: 1, // IN
            ttl: 300,
            rdata: RData::A(ip),
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
