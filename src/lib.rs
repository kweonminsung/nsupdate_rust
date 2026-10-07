mod builder;
mod error;
mod internal;
mod tsig;

use internal::{auth, decoder, encoder};
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::{Instant, timeout};

pub use builder::UpdateMessageBuilder;
pub use error::{AuthError, EncodeError, NsUpdateError, ParseError};
pub use internal::protocol::{
    DnsHeader, DnsRecord, DnsUpdateMessage, RData, UpdateResponse, ZoneSection,
};
pub use tsig::TsigKey;

pub struct NsUpdateClient {
    server_url: String,
    tsig_key: Option<TsigKey>,
    timeout: Option<Duration>,
}

impl NsUpdateClient {
    /// `None` sends unsigned updates; `Some(key)` requires authenticated responses.
    pub fn new(server_url: &str, tsig_key: Option<TsigKey>) -> Self {
        Self {
            server_url: server_url.to_string(),
            tsig_key,
            timeout: None,
        }
    }

    /// Limit address resolution and I/O together. `None` (default) disables the limit.
    /// Zero and durations that exceed the platform clock range are rejected.
    pub fn with_timeout(mut self, timeout: Option<Duration>) -> Result<Self, NsUpdateError> {
        if let Some(duration) = timeout
            && (duration.is_zero() || Instant::now().checked_add(duration).is_none())
        {
            return Err(NsUpdateError::InvalidTimeout);
        }
        self.timeout = timeout;
        Ok(self)
    }

    /// Send an UPDATE, signing and authenticating it when a TSIG key is configured.
    /// Check `is_success()` or `rcode()` on an `Ok` result for the update outcome.
    pub async fn send(&self, message: &DnsUpdateMessage) -> Result<UpdateResponse, NsUpdateError> {
        let request = encoder::encode(message, self.tsig_key.as_ref())?;

        match self.timeout {
            Some(duration) => timeout(duration, self.exchange(&request))
                .await
                .map_err(|_| NsUpdateError::Timeout)?,
            None => self.exchange(&request).await,
        }
    }

    async fn exchange(
        &self,
        request: &encoder::EncodedRequest,
    ) -> Result<UpdateResponse, NsUpdateError> {
        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        socket.connect(&self.server_url).await?;
        socket.send(&request.bytes).await?;

        // One extra byte detects datagrams beyond the DNS wire-size limit.
        let mut response_bytes = vec![0u8; 65536];
        let len = socket.recv(&mut response_bytes).await?;

        match &self.tsig_key {
            Some(key) => auth::verify_response(
                &response_bytes[..len],
                request,
                &key.name,
                &key.algorithm,
                &key.secret,
                auth::unix_time()?,
            ),
            None => {
                decoder::decode_unsigned_response(&response_bytes[..len], request.id, &request.zone)
            }
        }
    }
}
