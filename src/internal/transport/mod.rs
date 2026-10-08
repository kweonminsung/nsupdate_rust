use crate::internal::protocol::checked_count;
use crate::{EncodeError, NsUpdateError, ParseError};
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, ToSocketAddrs, UdpSocket, lookup_host};

const UDP_LIMIT: usize = 512;

/// Transport for an UPDATE transaction.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Transport {
    /// Use TCP for requests over 512 bytes or after a validated truncated UDP response.
    /// The size limit includes TSIG.
    #[default]
    Auto,
    /// Use UDP only. Requests over 512 bytes and truncated responses are errors.
    Udp,
    /// Use TCP directly, with a new connection per request.
    Tcp,
}

impl Transport {
    pub(crate) fn uses_tcp(self, length: usize) -> Result<bool, EncodeError> {
        match self {
            Self::Auto => Ok(length > UDP_LIMIT),
            Self::Tcp => Ok(true),
            Self::Udp if length <= UDP_LIMIT => Ok(false),
            Self::Udp => Err(EncodeError::LengthExceeded {
                field: "UDP message",
                length,
                max: UDP_LIMIT,
            }),
        }
    }
}

async fn connect_udp(server: &str) -> io::Result<UdpSocket> {
    let addresses = lookup_host(server).await?;
    let mut last_error = io::Error::new(
        io::ErrorKind::InvalidInput,
        "Server address resolved to no socket addresses",
    );
    for address in addresses {
        let local = match address {
            SocketAddr::V4(_) => SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)),
            SocketAddr::V6(_) => SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0)),
        };
        let connect = async {
            let socket = UdpSocket::bind(local).await?;
            socket.connect(address).await?;
            Ok(socket)
        };
        match connect.await {
            Ok(socket) => return Ok(socket),
            Err(error) => last_error = error,
        }
    }
    Err(last_error)
}

pub(crate) struct UdpExchange {
    socket: UdpSocket,
    response: Vec<u8>,
}

impl UdpExchange {
    pub(crate) async fn send(server: &str, request: &[u8]) -> io::Result<Self> {
        let socket = connect_udp(server).await?;
        if socket.send(request).await? != request.len() {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "Incomplete UDP send",
            ));
        }
        Ok(Self {
            socket,
            // One extra byte detects datagrams beyond the DNS wire-size limit.
            response: vec![0; 65536],
        })
    }

    pub(crate) async fn receive(&mut self) -> io::Result<&[u8]> {
        let length = self.socket.recv(&mut self.response).await?;
        Ok(&self.response[..length])
    }

    pub(crate) fn peer_addr(&self) -> io::Result<SocketAddr> {
        self.socket.peer_addr()
    }
}

pub(crate) async fn exchange_tcp(
    server: impl ToSocketAddrs,
    request: &[u8],
) -> Result<Vec<u8>, NsUpdateError> {
    let length = checked_count("DNS message", request.len())?;
    let mut stream = TcpStream::connect(server).await?;
    let mut frame = Vec::with_capacity(request.len() + 2);
    frame.extend_from_slice(&length.to_be_bytes());
    frame.extend_from_slice(request);
    stream.write_all(&frame).await?;

    let mut prefix = [0; 2];
    stream.read_exact(&mut prefix).await?;
    let length = usize::from(u16::from_be_bytes(prefix));
    if length < 12 {
        return Err(ParseError::InvalidMessage("TCP frame is shorter than a DNS header").into());
    }
    let mut response = vec![0; length];
    stream.read_exact(&mut response).await?;
    Ok(response)
}
