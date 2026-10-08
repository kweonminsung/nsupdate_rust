use nsupdate::{NsUpdateClient, NsUpdateError, Transport, UpdateMessageBuilder, UpdateResponse};
use std::io::ErrorKind;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::{sleep, timeout};

async fn exchange(
    mutate: impl FnOnce(&mut Vec<u8>),
    follow_up: bool,
) -> Result<UpdateResponse, NsUpdateError> {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let client = NsUpdateClient::new(&socket.local_addr().unwrap().to_string(), None)
        .with_transport(Transport::Udp)
        .with_timeout(Duration::from_millis(100))
        .unwrap();
    let mut request = UpdateMessageBuilder::new("example.test")
        .delete_record("host.example.test", 1)
        .build()
        .unwrap();
    request.header.id = 0x1234;
    let respond = async {
        let mut bytes = [0; 4096];
        let (length, peer) = socket.recv_from(&mut bytes).await.unwrap();
        assert_eq!(&bytes[..length], request.to_bytes().unwrap());
        let mut response = vec![0x12, 0x34, 0xa8, 0, 0, 1, 0, 0, 0, 0, 0, 0];
        response.extend_from_slice(b"\x07EXAMPLE\x04TEST\x00\x00\x06\x00\x01");
        let valid = response.clone();
        mutate(&mut response);
        socket.send_to(&response, peer).await.unwrap();
        if follow_up {
            sleep(Duration::from_millis(20)).await;
            socket.send_to(&valid, peer).await.unwrap();
        }
    };
    let (result, ()) = timeout(Duration::from_secs(5), async {
        tokio::join!(client.send(&request), respond)
    })
    .await
    .expect("unsigned exchange did not finish");
    assert_eq!(
        socket.try_recv_from(&mut [0; 4096]).unwrap_err().kind(),
        ErrorKind::WouldBlock,
        "discarding a response must not resend the UPDATE"
    );
    result
}

async fn assert_discarded(mutate: impl Fn(&mut Vec<u8>)) {
    let response = exchange(&mutate, true).await.unwrap();
    assert!(response.is_success());
    assert!(!response.is_authenticated());
    assert!(matches!(
        exchange(mutate, false).await,
        Err(NsUpdateError::Timeout)
    ));
}

#[tokio::test]
async fn test_unsigned_success_with_and_without_zone() {
    for omit_zone in [false, true] {
        let response = exchange(
            |response| {
                if omit_zone {
                    response.truncate(12);
                    response[5] = 0;
                }
            },
            false,
        )
        .await
        .unwrap();
        assert!(response.is_success());
        assert!(!response.is_authenticated());
        assert_eq!(response.rcode(), 0);
        assert_eq!(response.zone.is_none(), omit_zone);
    }
}

#[tokio::test]
async fn test_unsigned_dns_errors_preserve_rcode() {
    let refused = exchange(|response| response[3] = 5, false).await.unwrap();
    assert_eq!(refused.rcode(), 5);
    assert!(!refused.is_success());
    assert!(!refused.is_authenticated());

    let extended = exchange(
        |response| {
            response[11] = 1;
            // OPT with extended RCODE 1 and no options.
            response.extend_from_slice(&[0, 0, 41, 4, 208, 1, 0, 0, 0, 0, 0]);
        },
        false,
    )
    .await
    .unwrap();
    assert_eq!(extended.rcode(), 16);
    assert!(!extended.is_success());
    assert!(!extended.is_authenticated());
}

#[tokio::test]
async fn test_discards_responses_for_a_different_request() {
    for (index, value) in [(0, 0), (2, 0x28), (2, 0x80), (13, b'X'), (27, 1), (29, 3)] {
        assert_discarded(|response| response[index] = value).await;
    }
}

#[tokio::test]
async fn test_discards_incomplete_and_trailing_data() {
    assert_discarded(|response| response.truncate(11)).await;
    assert_discarded(|response| response.push(0)).await;
    assert_discarded(|response| response[11] = 1).await;
}

#[tokio::test]
async fn test_rejects_truncated_response() {
    assert!(matches!(
        exchange(|response| response[2] |= 2, false).await,
        Err(NsUpdateError::TruncatedResponse)
    ));
}

#[tokio::test]
async fn test_discards_unexpected_tsig() {
    let hex = include_str!("fixtures/tsig.txt")
        .lines()
        .find_map(|line| line.strip_prefix("sha256-response "))
        .unwrap();
    let signed: Vec<u8> = hex
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect();
    assert_discarded(|response| *response = signed.clone()).await;
}

#[tokio::test]
async fn test_discarded_responses_do_not_extend_the_deadline() {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let client = NsUpdateClient::new(&socket.local_addr().unwrap().to_string(), None)
        .with_timeout(Duration::from_millis(100))
        .unwrap();
    let request = UpdateMessageBuilder::new("example.test").build().unwrap();
    let server = async {
        let mut bytes = [0; 4096];
        let (_, peer) = socket.recv_from(&mut bytes).await.unwrap();
        let mut response = bytes[..2].to_vec();
        response.extend_from_slice(&[0xa8, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        response[0] ^= 1;
        for _ in 0..12 {
            socket.send_to(&response, peer).await.unwrap();
            sleep(Duration::from_millis(20)).await;
        }
        // A reset deadline would accept this late response with the correct ID.
        response[0] ^= 1;
        socket.send_to(&response, peer).await.unwrap();
    };
    let (result, ()) = timeout(Duration::from_secs(5), async {
        tokio::join!(client.send(&request), server)
    })
    .await
    .unwrap();
    assert!(matches!(result, Err(NsUpdateError::Timeout)));
}

#[tokio::test]
async fn test_unsigned_request_respects_timeout() {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let client = NsUpdateClient::new(&socket.local_addr().unwrap().to_string(), None)
        .with_timeout(Some(Duration::from_millis(100)))
        .unwrap();
    let request = UpdateMessageBuilder::new("example.test").build().unwrap();
    let mut bytes = [0; 4096];
    let (result, received) = timeout(Duration::from_secs(5), async {
        tokio::join!(client.send(&request), socket.recv_from(&mut bytes))
    })
    .await
    .unwrap();
    assert!(received.is_ok());
    assert!(matches!(result, Err(NsUpdateError::Timeout)));
}
