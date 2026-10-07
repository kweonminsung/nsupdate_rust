mod support;

use nsupdate::{NsUpdateClient, NsUpdateError, TsigKey, UpdateMessageBuilder};
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::{sleep, timeout};

fn client(address: &str) -> NsUpdateClient {
    NsUpdateClient::new(
        address,
        Some(TsigKey::new("sha256", "test-key.", "dGVzdA==").unwrap()),
    )
}

#[test]
fn test_rejects_zero_and_unrepresentable_timeouts() {
    for duration in [Duration::ZERO, Duration::MAX] {
        assert!(matches!(
            client("127.0.0.1:53").with_timeout(Some(duration)),
            Err(NsUpdateError::InvalidTimeout)
        ));
    }
    assert!(client("127.0.0.1:53").with_timeout(None).is_ok());
    assert!(
        client("127.0.0.1:53")
            .with_timeout(Some(Duration::from_secs(1)))
            .is_ok()
    );
}

#[tokio::test]
async fn test_times_out_without_a_response_and_can_be_used_again() {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap().to_string();
    let client = client(&address)
        .with_timeout(Some(Duration::from_millis(100)))
        .unwrap();
    let request = UpdateMessageBuilder::new("example.test").build().unwrap();
    let mut bytes = vec![0; 65536];
    let (response, received) = timeout(Duration::from_secs(5), async {
        tokio::join!(client.send(&request), socket.recv_from(&mut bytes))
    })
    .await
    .expect("configured timeout did not finish");
    assert!(received.is_ok());
    assert!(matches!(response, Err(NsUpdateError::Timeout)));

    let respond = async {
        let (length, peer) = socket.recv_from(&mut bytes).await.unwrap();
        let response = support::response(&bytes[..length], "sha256", 0, false);
        socket.send_to(&response, peer).await.unwrap();
    };
    let (response, ()) = timeout(Duration::from_secs(5), async {
        tokio::join!(client.send(&request), respond)
    })
    .await
    .unwrap();
    assert!(response.unwrap().is_success());
}

async fn delayed_response(limit: Option<Option<Duration>>) {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap().to_string();
    let client = match limit {
        None => client(&address),
        Some(None) => client(&address)
            .with_timeout(Some(Duration::from_nanos(1)))
            .unwrap()
            .with_timeout(None)
            .unwrap(),
        Some(Some(duration)) => client(&address).with_timeout(Some(duration)).unwrap(),
    };
    let request = UpdateMessageBuilder::new("example.test").build().unwrap();
    let respond = async {
        let mut bytes = vec![0; 65536];
        let (length, peer) = socket.recv_from(&mut bytes).await.unwrap();
        sleep(Duration::from_millis(50)).await;
        let response = support::response(&bytes[..length], "sha256", 0, false);
        socket.send_to(&response, peer).await.unwrap();
    };
    let (response, ()) = timeout(Duration::from_secs(5), async {
        tokio::join!(client.send(&request), respond)
    })
    .await
    .unwrap();
    assert!(response.unwrap().is_success());
}

#[tokio::test]
async fn test_default_timeout_is_disabled() {
    delayed_response(None).await;
}

#[tokio::test]
async fn test_none_clears_a_previously_configured_timeout() {
    delayed_response(Some(None)).await;
}

#[tokio::test]
async fn test_accepts_an_authenticated_response_before_the_deadline() {
    delayed_response(Some(Some(Duration::from_secs(1)))).await;
}
