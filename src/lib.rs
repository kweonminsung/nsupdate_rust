mod builder;
mod error;
mod internal;

use base64::Engine;
use base64::engine::general_purpose;
use internal::constants::TsigAlg;
use internal::encoder;
use tokio::net::UdpSocket;

pub use builder::UpdateMessageBuilder;
pub use error::{NsUpdateError, ParseError};
pub use internal::protocol::{
    DnsHeader, DnsMessage, DnsQuestion, DnsRecord, DnsUpdateMessage, RData, ZoneSection,
};

pub struct NsUpdateClient {
    server_url: String,
    algorithm: TsigAlg,
    tsig_key_name: String,
    tsig_key: Vec<u8>,
}

impl NsUpdateClient {
    pub fn new(
        server_url: &str,
        algorithm: &str,
        tsig_key_name: &str,
        tsig_key_b64: &str,
    ) -> Result<Self, NsUpdateError> {
        let tsig_key = general_purpose::STANDARD.decode(tsig_key_b64.as_bytes())?;

        Ok(NsUpdateClient {
            server_url: server_url.to_string(),
            tsig_key_name: tsig_key_name.to_string(),
            algorithm: TsigAlg::from_string(algorithm)?,
            tsig_key,
        })
    }

    pub async fn send(&self, message: &DnsUpdateMessage) -> Result<DnsMessage, NsUpdateError> {
        let request_bytes = encoder::encode(
            message,
            &self.tsig_key_name,
            &self.algorithm,
            &self.tsig_key,
        );

        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        socket.connect(&self.server_url).await?;
        socket.send(&request_bytes).await?;

        let mut response_bytes = [0u8; 512];
        let len = socket.recv(&mut response_bytes).await?;

        let response = DnsMessage::from_bytes(&response_bytes[..len])?;
        Ok(response)
    }
}
