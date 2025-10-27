mod builder;
mod internal;

use std::fmt;
use base64::Engine;
use tokio::net::UdpSocket;
use base64::engine::general_purpose;
use internal::parser::ParseError;
use internal::protocol::{DnsMessage};
use internal::constants::TsigAlg;
use internal::encoder;

pub use builder::UpdateMessageBuilder;
pub use internal::protocol::{RData, DnsRecord};

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
    server_url: String,
    algorithm: TsigAlg,
    tsig_key_name: String,
    tsig_key: Vec<u8>,
}

impl NsUpdateClient {
    pub fn new(server_url: &str, algorithm: &str, tsig_key_name: &str, tsig_key_b64: &str) -> Self {
        let tsig_key = general_purpose::STANDARD
            .decode(tsig_key_b64.as_bytes())
            .expect("Invalid base64 TSIG key");

        NsUpdateClient {
            server_url: server_url.to_string(),
            tsig_key_name: tsig_key_name.to_string(),
            algorithm: TsigAlg::from_string(algorithm)
                .expect("Unsupported TSIG algorithm"),
            tsig_key,
        }
    }

    pub async fn send(&self, message: &DnsMessage) -> Result<DnsMessage, NsUpdateError> {
        let request_bytes = encoder::encode(message, &self.tsig_key_name, &self.algorithm, &self.tsig_key);

        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        socket.connect(&self.server_url).await?;
        // socket.send(&request_bytes).await?;

        println!("Sending to {:?}", self.server_url);
        let sent = socket.send(&request_bytes).await?;
        println!("Sent {} bytes", sent);

        let mut response_bytes = [0u8; 512];
        let len = socket.recv(&mut response_bytes).await?;

        let response = DnsMessage::from_bytes(&response_bytes[..len])?;
        Ok(response)
    }
}

