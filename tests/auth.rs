mod support;

use hmac::{Hmac, Mac};
use nsupdate::{
    AuthError, NsUpdateClient, NsUpdateError, TsigKey, UpdateMessageBuilder, UpdateResponse,
};
use sha2::Sha256;
use std::io::ErrorKind;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::{sleep, timeout};

fn corrupt(response: &mut Vec<u8>, tamper: &str) {
    match tamper {
        "mac" => {
            let index = response.len() - 7;
            response[index] ^= 1;
        }
        "rcode" => response[3] ^= 1,
        "unsigned" => {
            response.truncate(12);
            response[11] = 0;
        }
        "id" => response[0] ^= 1,
        "key" => response[13] ^= 1,
        "algorithm" => response[33] ^= 1,
        "trailing" => response.push(0),
        "short" => response.truncate(11),
        "none" => {}
        _ => panic!("unknown mutation"),
    }
}

async fn exchange(
    algorithm: &'static str,
    rcode: u8,
    padding: bool,
    tamper: &'static str,
    follow_up: bool,
) -> Result<UpdateResponse, NsUpdateError> {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap().to_string();
    let server = async {
        let mut packet = vec![0; 65536];
        let (length, peer) = timeout(Duration::from_secs(5), socket.recv_from(&mut packet))
            .await
            .unwrap()
            .unwrap();
        let valid = support::response(&packet[..length], algorithm, rcode, padding);
        let mut response = valid.clone();
        corrupt(&mut response, tamper);
        socket.send_to(&response, peer).await.unwrap();
        if follow_up {
            sleep(Duration::from_millis(20)).await;
            socket.send_to(&valid, peer).await.unwrap();
        }
    };
    let client = NsUpdateClient::new(
        &address,
        Some(TsigKey::new(algorithm, "TEST-KEY.", "dGVzdA==").unwrap()),
    )
    .with_timeout((tamper != "none" && !follow_up).then_some(Duration::from_millis(100)))
    .unwrap();
    let request = UpdateMessageBuilder::new("example.test")
        .delete_record("host.example.test", 1)
        .build()
        .unwrap();
    let (response, ()) = timeout(Duration::from_secs(5), async {
        tokio::join!(client.send(&request), server)
    })
    .await
    .expect("client did not finish");
    // Discarding a reply must not resend the UPDATE.
    assert_eq!(
        socket.try_recv_from(&mut [0; 4096]).unwrap_err().kind(),
        ErrorKind::WouldBlock
    );
    response
}

#[tokio::test]
async fn test_authenticates_live_udp_exchange_for_all_algorithms() {
    for algorithm in ["md5", "sha1", "sha224", "sha256", "sha384", "sha512"] {
        let response = exchange(algorithm, 0, false, "none", false).await.unwrap();
        assert!(response.is_success());
        assert!(response.is_authenticated());
        assert_eq!(response.rcode(), 0);
    }
}

#[tokio::test]
async fn test_dns_refusal_is_authenticated_and_preserved() {
    for tamper in ["none", "mac"] {
        let response = exchange("sha256", 5, false, tamper, tamper != "none")
            .await
            .unwrap();
        assert_eq!(response.rcode(), 5);
        assert!(response.is_authenticated());
        assert!(!response.is_success());
    }
}

#[tokio::test]
async fn test_authenticates_response_larger_than_512_bytes() {
    assert!(
        exchange("sha256", 0, true, "none", false)
            .await
            .unwrap()
            .is_success()
    );
}

#[tokio::test]
async fn test_discards_invalid_udp_responses_and_accepts_a_valid_follow_up() {
    for tamper in [
        "mac",
        "rcode",
        "unsigned",
        "id",
        "key",
        "algorithm",
        "trailing",
        "short",
    ] {
        let response = exchange("sha256", 0, false, tamper, true).await.unwrap();
        assert!(response.is_success(), "{tamper}");
        assert!(response.is_authenticated(), "{tamper}");
    }
}

#[tokio::test]
async fn test_invalid_udp_responses_alone_end_in_timeout() {
    for tamper in [
        "mac",
        "rcode",
        "unsigned",
        "id",
        "key",
        "algorithm",
        "trailing",
        "short",
    ] {
        assert!(
            matches!(
                exchange("sha256", 0, false, tamper, false).await,
                Err(NsUpdateError::Timeout)
            ),
            "{tamper}"
        );
    }
}

#[tokio::test]
async fn test_invalid_udp_responses_do_not_extend_the_deadline() {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let client = NsUpdateClient::new(
        &socket.local_addr().unwrap().to_string(),
        Some(TsigKey::new("sha256", "test-key.", "dGVzdA==").unwrap()),
    )
    .with_timeout(Duration::from_millis(100))
    .unwrap();
    let request = UpdateMessageBuilder::new("example.test").build().unwrap();
    let server = async {
        let mut packet = [0; 4096];
        let (length, peer) = socket.recv_from(&mut packet).await.unwrap();
        let valid = support::response(&packet[..length], "sha256", 0, false);
        let mut invalid = valid.clone();
        corrupt(&mut invalid, "mac");
        for _ in 0..12 {
            socket.send_to(&invalid, peer).await.unwrap();
            sleep(Duration::from_millis(20)).await;
        }
        // A reset deadline would accept this late response.
        socket.send_to(&valid, peer).await.unwrap();
    };
    let (result, ()) = timeout(Duration::from_secs(5), async {
        tokio::join!(client.send(&request), server)
    })
    .await
    .unwrap();
    assert!(matches!(result, Err(NsUpdateError::Timeout)));
}

fn tsig_error_response(request: &[u8], error: u16) -> (Vec<u8>, Option<u64>) {
    let mut response = support::response(request, "sha256", 9, false);
    // The mock response has no zone, then an uncompressed key name and SHA256 TSIG.
    let key_end = 12 + b"\x08test-key\0".len();
    let data_start = key_end + 10;
    let time_start = data_start + b"\x0bhmac-sha256\0".len();
    let mac_start = time_start + 10;
    let error_start = mac_start + 32 + 2;
    let mut other = Vec::new();
    let server_time = if error == 18 {
        let time = response[time_start..time_start + 6]
            .iter()
            .fold(0u64, |time, byte| (time << 8) | u64::from(*byte))
            + 3600;
        other.extend_from_slice(&time.to_be_bytes()[2..]);
        Some(time)
    } else {
        None
    };
    response[error_start..error_start + 2].copy_from_slice(&error.to_be_bytes());
    response[error_start + 2..error_start + 4].copy_from_slice(&(other.len() as u16).to_be_bytes());
    response.extend_from_slice(&other);
    let data_length = (response.len() - data_start) as u16;
    response[data_start - 2..data_start].copy_from_slice(&data_length.to_be_bytes());

    let mut unsigned = response[..12].to_vec();
    unsigned[10..12].copy_from_slice(&0u16.to_be_bytes());
    let mut data = 32u16.to_be_bytes().to_vec();
    data.extend_from_slice(&request[request.len() - 38..request.len() - 6]);
    data.extend_from_slice(&unsigned);
    data.extend_from_slice(&response[12..key_end]);
    data.extend_from_slice(&[0, 255, 0, 0, 0, 0]);
    data.extend_from_slice(&response[data_start..time_start + 8]);
    data.extend_from_slice(&response[error_start..]);
    let mut mac = Hmac::<Sha256>::new_from_slice(b"test").unwrap();
    mac.update(&data);
    response[mac_start..mac_start + 32].copy_from_slice(&mac.finalize().into_bytes());
    (response, server_time)
}

#[tokio::test]
async fn test_authenticated_tsig_errors_are_returned_without_waiting() {
    for code in [18, 22] {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client = NsUpdateClient::new(
            &socket.local_addr().unwrap().to_string(),
            Some(TsigKey::new("sha256", "test-key.", "dGVzdA==").unwrap()),
        );
        let request = UpdateMessageBuilder::new("example.test").build().unwrap();
        let server = async {
            let mut packet = [0; 4096];
            let (length, peer) = socket.recv_from(&mut packet).await.unwrap();
            let (response, server_time) = tsig_error_response(&packet[..length], code);
            socket.send_to(&response, peer).await.unwrap();
            server_time
        };
        let (result, server_time) = timeout(Duration::from_secs(5), async {
            tokio::join!(client.send(&request), server)
        })
        .await
        .expect("authenticated TSIG error was discarded");
        assert!(
            matches!(result, Err(NsUpdateError::Auth(AuthError::ServerError {
            code: actual_code, server_time: actual_time,
        })) if actual_code == code && actual_time == server_time)
        );
    }
}
