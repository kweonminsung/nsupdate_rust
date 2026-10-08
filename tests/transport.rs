mod support;

use nsupdate::{
    DnsUpdateMessage, EncodeError, NsUpdateClient, NsUpdateError, RData, Transport, TsigKey,
    UpdateMessageBuilder,
};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::time::{sleep, timeout};

fn client(address: &str, algorithm: Option<&str>) -> NsUpdateClient {
    let key = algorithm.map(|algorithm| TsigKey::new(algorithm, "test-key.", "dGVzdA==").unwrap());
    NsUpdateClient::new(address, key)
}

fn request() -> DnsUpdateMessage {
    UpdateMessageBuilder::new("example.test")
        .delete_record("host.example.test", 1)
        .build()
        .unwrap()
}

fn response(request: &[u8], algorithm: Option<&str>, flags: u16) -> Vec<u8> {
    if let Some(algorithm) = algorithm {
        if flags == 0xa800 {
            support::response(request, algorithm, 0, false)
        } else {
            support::response_with_flags(request, algorithm, flags, false)
        }
    } else {
        let mut response = request[..2].to_vec();
        response.extend_from_slice(&flags.to_be_bytes());
        response.extend_from_slice(&[0; 8]);
        response
    }
}

async fn read_request(stream: &mut TcpStream) -> Vec<u8> {
    let length = stream.read_u16().await.unwrap();
    assert!(length >= 12);
    let mut request = vec![0; usize::from(length)];
    stream.read_exact(&mut request).await.unwrap();
    request
}

async fn write_response(stream: &mut TcpStream, response: &[u8]) {
    stream.write_u16(response.len() as u16).await.unwrap();
    stream.write_all(response).await.unwrap();
}

#[tokio::test]
async fn test_udp_supports_both_address_families_with_and_without_tsig() {
    for bind in ["127.0.0.1:0", "[::1]:0"] {
        for algorithm in [None, Some("sha256")] {
            for transport in [Transport::Auto, Transport::Udp] {
                let socket = UdpSocket::bind(bind).await.unwrap();
                let client = client(&socket.local_addr().unwrap().to_string(), algorithm)
                    .with_transport(transport);
                let request = request();
                let server = async {
                    let mut bytes = [0; 4096];
                    let (length, peer) = socket.recv_from(&mut bytes).await.unwrap();
                    assert_eq!(peer.is_ipv6(), socket.local_addr().unwrap().is_ipv6());
                    let response = response(&bytes[..length], algorithm, 0xa800);
                    socket.send_to(&response, peer).await.unwrap();
                };
                let (result, ()) = timeout(Duration::from_secs(5), async {
                    tokio::join!(client.send(&request), server)
                })
                .await
                .unwrap();
                let result = result.unwrap();
                assert!(result.is_success());
                assert_eq!(result.is_authenticated(), algorithm.is_some());
            }
        }
    }
}

async fn tcp_exchange(
    bind: &str,
    transport: Transport,
    algorithm: Option<&str>,
    request: &DnsUpdateMessage,
) -> usize {
    let listener = TcpListener::bind(bind).await.unwrap();
    let client =
        client(&listener.local_addr().unwrap().to_string(), algorithm).with_transport(transport);
    let server = async {
        let (mut stream, peer) = listener.accept().await.unwrap();
        assert_eq!(peer.is_ipv6(), listener.local_addr().unwrap().is_ipv6());
        let packet = read_request(&mut stream).await;
        if algorithm.is_none() {
            assert_eq!(packet, request.to_bytes().unwrap());
        }
        let response = response(&packet, algorithm, 0xa800);
        write_response(&mut stream, &response).await;
        packet.len()
    };
    let (result, length) = timeout(Duration::from_secs(5), async {
        tokio::join!(client.send(request), server)
    })
    .await
    .unwrap();
    let result = result.unwrap();
    assert!(result.is_success());
    assert_eq!(result.is_authenticated(), algorithm.is_some());
    length
}

#[tokio::test]
async fn test_tcp_supports_both_address_families_and_all_tsig_algorithms() {
    for bind in ["127.0.0.1:0", "[::1]:0"] {
        for algorithm in [
            None,
            Some("md5"),
            Some("sha1"),
            Some("sha224"),
            Some("sha256"),
            Some("sha384"),
            Some("sha512"),
        ] {
            tcp_exchange(bind, Transport::Tcp, algorithm, &request()).await;
        }
    }
}

#[tokio::test]
async fn test_auto_uses_tcp_when_tsig_pushes_the_request_over_512_bytes() {
    let request = UpdateMessageBuilder::new("example.test")
        .add_record("host.example.test", 300, RData::TXT("x".repeat(255)))
        .add_record("host.example.test", 300, RData::TXT("y".repeat(100)))
        .build()
        .unwrap();
    assert!(request.to_bytes().unwrap().len() <= 512);
    let length = tcp_exchange("127.0.0.1:0", Transport::Auto, Some("sha256"), &request).await;
    assert!(length > 512);
}

#[tokio::test]
async fn test_auto_sends_the_full_65535_byte_unsigned_request_over_tcp() {
    let mut builder = UpdateMessageBuilder::new(".");
    for _ in 0..245 {
        builder = builder.add_record(".", 0, RData::TXT("x".repeat(255)));
    }
    let request = builder
        .add_record(".", 0, RData::TXT("x".repeat(91)))
        .build()
        .unwrap();
    assert_eq!(
        tcp_exchange("127.0.0.1:0", Transport::Auto, None, &request).await,
        65535
    );
}

#[tokio::test]
async fn test_udp_rejects_oversized_requests_before_address_resolution() {
    let request = UpdateMessageBuilder::new("example.test")
        .add_record("host.example.test", 300, RData::TXT("x".repeat(255)))
        .add_record("host.example.test", 300, RData::TXT("y".repeat(255)))
        .build()
        .unwrap();
    for algorithm in [None, Some("sha256")] {
        let result = client("invalid address", algorithm)
            .with_transport(Transport::Udp)
            .send(&request)
            .await;
        assert!(matches!(
            result,
            Err(NsUpdateError::Encode(EncodeError::LengthExceeded {
                field: "UDP message",
                max: 512,
                ..
            }))
        ));
    }
}

#[tokio::test]
async fn test_auto_retries_validated_tc_over_tcp_with_the_same_request_and_peer() {
    for bind in ["127.0.0.1:0", "[::1]:0"] {
        for algorithm in [None, Some("sha256")] {
            let listener = TcpListener::bind(bind).await.unwrap();
            let address = listener.local_addr().unwrap();
            let socket = UdpSocket::bind(address).await.unwrap();
            let client = client(&address.to_string(), algorithm);
            let request = request();
            let server = async {
                let mut bytes = [0; 4096];
                let (length, peer) = socket.recv_from(&mut bytes).await.unwrap();
                if algorithm.is_some() {
                    let mut forged_tc = response(&bytes[..length], algorithm, 0xaa00);
                    let index = forged_tc.len() - 7;
                    forged_tc[index] ^= 1;
                    socket.send_to(&forged_tc, peer).await.unwrap();
                }
                socket
                    .send_to(&response(&bytes[..length], algorithm, 0xaa00), peer)
                    .await
                    .unwrap();
                let (mut stream, _) = listener.accept().await.unwrap();
                let packet = read_request(&mut stream).await;
                assert_eq!(packet, bytes[..length]);
                write_response(&mut stream, &response(&packet, algorithm, 0xa800)).await;
            };
            let (result, ()) = timeout(Duration::from_secs(5), async {
                tokio::join!(client.send(&request), server)
            })
            .await
            .unwrap();
            let result = result.unwrap();
            assert!(result.is_success());
            assert_eq!(result.is_authenticated(), algorithm.is_some());
        }
    }
}

#[tokio::test]
async fn test_invalid_tc_does_not_trigger_tcp() {
    for (algorithm, mutation) in [
        (None, "id"),
        (None, "trailing"),
        (Some("sha256"), "unsigned"),
        (Some("sha256"), "mac"),
        (Some("sha256"), "id"),
        (Some("sha256"), "trailing"),
    ] {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let socket = UdpSocket::bind(address).await.unwrap();
        let client = client(&address.to_string(), algorithm)
            .with_timeout(Duration::from_millis(100))
            .unwrap();
        let request = request();
        let server = async {
            let mut bytes = [0; 4096];
            let (length, peer) = socket.recv_from(&mut bytes).await.unwrap();
            let mut packet = response(&bytes[..length], algorithm, 0xaa00);
            match mutation {
                "unsigned" => packet = response(&bytes[..length], None, 0xaa00),
                "mac" => {
                    let index = packet.len() - 7;
                    packet[index] ^= 1;
                }
                "id" => packet[0] ^= 1,
                "trailing" => packet.push(0),
                _ => unreachable!(),
            }
            socket.send_to(&packet, peer).await.unwrap();
        };
        let (result, ()) = timeout(Duration::from_secs(5), async {
            tokio::join!(client.send(&request), server)
        })
        .await
        .unwrap();
        assert!(matches!(result, Err(NsUpdateError::Timeout)), "{mutation}");
        assert!(
            timeout(Duration::from_millis(20), listener.accept())
                .await
                .is_err()
        );
    }
}

#[tokio::test]
async fn test_timeout_budget_is_shared_between_udp_and_tcp() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let socket = UdpSocket::bind(address).await.unwrap();
    let client = client(&address.to_string(), Some("sha256"))
        .with_timeout(Some(Duration::from_millis(300)))
        .unwrap();
    let request = request();
    let server = async {
        let mut bytes = [0; 4096];
        let (length, peer) = socket.recv_from(&mut bytes).await.unwrap();
        sleep(Duration::from_millis(200)).await;
        socket
            .send_to(&response(&bytes[..length], Some("sha256"), 0xaa00), peer)
            .await
            .unwrap();
        let (mut stream, _) = listener.accept().await.unwrap();
        let packet = read_request(&mut stream).await;
        sleep(Duration::from_millis(200)).await;
        // A fresh timeout for TCP would accept this late response.
        let reply = response(&packet, Some("sha256"), 0xa800);
        let mut frame = (reply.len() as u16).to_be_bytes().to_vec();
        frame.extend_from_slice(&reply);
        let _ = stream.write_all(&frame).await;
    };
    let (result, ()) = timeout(Duration::from_secs(5), async {
        tokio::join!(client.send(&request), server)
    })
    .await
    .unwrap();
    assert!(matches!(result, Err(NsUpdateError::Timeout)));
}
