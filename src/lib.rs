#![doc = include_str!("../README.md")]

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

    /// Set a shared timeout for address resolution and I/O; `None` (default) disables it.
    /// Accepts `Duration` or `Option<Duration>`; rejects zero or clock overflow.
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

    /// Send an UPDATE; check `is_success()` or `rcode()` on an `Ok` response.
    /// I/O errors are not retried. UDP ignores malformed, mismatched, or invalid
    /// TSIG replies within the original timeout. Without a timeout, it may wait indefinitely.
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
        let mut exchange = transport::UdpExchange::send(&self.server_url, &request.bytes).await?;
        loop {
            let response = exchange.receive().await?;
            match self.decode_response(response, request) {
                Err(NsUpdateError::TruncatedResponse) if self.transport == Transport::Auto => {
                    // Reuse the peer and signed request for TCP fallback.
                    let response =
                        transport::exchange_tcp(exchange.peer_addr()?, &request.bytes).await?;
                    return self.decode_response(&response, request);
                }
                Err(error @ NsUpdateError::Auth(AuthError::ServerError { .. })) => {
                    return Err(error);
                }
                Err(NsUpdateError::Parse(_) | NsUpdateError::Auth(_)) => {
                    // Invalid datagrams do not end the transaction, including
                    // failed TSIG checks (RFC 8945 5.4). Keep the same deadline.
                }
                result => return result,
            }
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
