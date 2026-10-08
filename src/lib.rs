mod builder;
mod error;
mod internal;
mod tsig;

use internal::{auth, decoder, encoder, transport};
use std::time::Duration;
use tokio::time::{Instant, timeout};

pub use builder::UpdateMessageBuilder;
pub use error::{AuthError, EncodeError, NsUpdateError, ParseError};
pub use internal::protocol::{
    DnsHeader, DnsRecord, DnsUpdateMessage, RData, UpdateResponse, ZoneSection,
};
pub use internal::transport::Transport;
pub use tsig::TsigKey;

pub struct NsUpdateClient {
    server_url: String,
    tsig_key: Option<TsigKey>,
    timeout: Option<Duration>,
    transport: Transport,
}

impl NsUpdateClient {
    /// `None` sends unsigned updates; `Some(key)` requires authenticated responses.
    /// Addresses use `host:port` or `[IPv6]:port`.
    pub fn new(server_url: &str, tsig_key: Option<TsigKey>) -> Self {
        Self {
            server_url: server_url.to_string(),
            tsig_key,
            timeout: None,
            transport: Transport::Auto,
        }
    }

    /// Select UDP, TCP, or automatic transport selection (the default).
    pub fn with_transport(mut self, transport: Transport) -> Self {
        self.transport = transport;
        self
    }

    /// Limit address resolution and I/O together. `None` (default) disables the limit.
    /// Accepts `Duration`, `Some(Duration)`, or `None`.
    /// Zero and durations that exceed the platform clock range are rejected.
    pub fn with_timeout(
        mut self,
        timeout: impl Into<Option<Duration>>,
    ) -> Result<Self, NsUpdateError> {
        let timeout = timeout.into();
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
    /// I/O failures are returned without automatically resending the update.
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
        if self.transport.uses_tcp(request.bytes.len())? {
            let response = transport::exchange_tcp(&self.server_url, &request.bytes).await?;
            return self.decode_response(&response, request);
        }
        let (response, peer) = transport::exchange_udp(&self.server_url, &request.bytes).await?;
        match self.decode_response(&response, request) {
            Err(NsUpdateError::TruncatedResponse) if self.transport == Transport::Auto => {
                // Keep the same peer and signed request when switching to TCP.
                let response = transport::exchange_tcp(peer, &request.bytes).await?;
                self.decode_response(&response, request)
            }
            result => result,
        }
    }

    fn decode_response(
        &self,
        response: &[u8],
        request: &encoder::EncodedRequest,
    ) -> Result<UpdateResponse, NsUpdateError> {
        match &self.tsig_key {
            Some(key) => auth::verify_response(
                response,
                request,
                &key.name,
                &key.algorithm,
                &key.secret,
                auth::unix_time()?,
            ),
            None => decoder::decode_unsigned_response(response, request.id, &request.zone),
        }
    }
}
