mod support;

use nsupdate::{
    AuthError, NsUpdateClient, NsUpdateError, TsigKey, UpdateMessageBuilder, UpdateResponse,
};
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::timeout;

async fn exchange(
    algorithm: &'static str,
    rcode: u8,
    padding: bool,
    tamper: &'static str,
) -> Result<UpdateResponse, NsUpdateError> {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap().to_string();
    let server = tokio::spawn(async move {
        let mut packet = vec![0; 65536];
        let (length, peer) = timeout(Duration::from_secs(5), socket.recv_from(&mut packet))
            .await
            .unwrap()
            .unwrap();
        let mut response = support::response(&packet[..length], algorithm, rcode, padding);
        match tamper {
            "mac" => {
                let index = response.len() - 7;
                response[index] ^= 1;
            }
            "rcode" => {
                response[3] ^= 1;
            }
            "unsigned" => {
                response.truncate(12);
                response[11] = 0;
            }
            "id" => {
                response[0] ^= 1;
            }
            "trailing" => response.push(0),
            "none" => {}
            _ => panic!("unknown mutation"),
        }
        socket.send_to(&response, peer).await.unwrap();
    });
    let client = NsUpdateClient::new(
        &address,
        Some(TsigKey::new(algorithm, "TEST-KEY.", "dGVzdA==").unwrap()),
    );
    let request = UpdateMessageBuilder::new("example.test")
        .delete_record("host.example.test", 1)
        .build()
        .unwrap();
    let response = timeout(Duration::from_secs(5), client.send(&request))
        .await
        .expect("client did not finish");
    server.await.unwrap();
    response
}

#[tokio::test]
async fn test_authenticates_live_udp_exchange_for_all_algorithms() {
    for algorithm in ["md5", "sha1", "sha224", "sha256", "sha384", "sha512"] {
        let response = exchange(algorithm, 0, false, "none").await.unwrap();
        assert!(response.is_success());
        assert!(response.is_authenticated());
        assert_eq!(response.rcode(), 0);
    }
}

#[tokio::test]
async fn test_dns_refusal_is_authenticated_and_preserved() {
    let response = exchange("sha256", 5, false, "none").await.unwrap();
    assert_eq!(response.rcode(), 5);
    assert!(response.is_authenticated());
    assert!(!response.is_success());
}

#[tokio::test]
async fn test_authenticates_response_larger_than_512_bytes() {
    assert!(
        exchange("sha256", 0, true, "none")
            .await
            .unwrap()
            .is_success()
    );
}

#[tokio::test]
async fn test_rejects_tampered_and_unsigned_responses_through_public_api() {
    for tamper in ["mac", "rcode"] {
        assert!(matches!(
            exchange("sha256", 0, false, tamper).await,
            Err(NsUpdateError::Auth(AuthError::InvalidMac))
        ));
    }
    assert!(matches!(
        exchange("sha256", 0, false, "unsigned").await,
        Err(NsUpdateError::Auth(AuthError::MissingTsig))
    ));
    assert!(matches!(
        exchange("sha256", 0, false, "id").await,
        Err(NsUpdateError::Auth(AuthError::ResponseMismatch(_)))
    ));
    assert!(matches!(
        exchange("sha256", 0, false, "trailing").await,
        Err(NsUpdateError::Parse(_))
    ));
}
