//! Start the isolated BIND fixture from the repository root:
//! ```sh
//! docker run --rm --name nsupdate-test -p 127.0.0.1:15353:53/udp -p 127.0.0.1:15353:53/tcp \
//!   --mount type=bind,src="$PWD/tests/bind",dst=/fixtures,readonly \
//!   --entrypoint named ubuntu/bind9:9.20-26.04 -g -c /fixtures/named.conf
//! ```
//! Run the tests once the zone is loaded, then stop the fixture:
//! ```sh
//! NSUPDATE_TEST_SERVER=127.0.0.1:15353 cargo test --locked --test bind -- --ignored
//! docker stop nsupdate-test
//! ```
use nsupdate::{
    AuthError, NsUpdateClient, NsUpdateError, RData, Transport, TsigKey, UpdateMessageBuilder,
};
use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::timeout;

fn client(algorithm: &str, transport: Transport) -> NsUpdateClient {
    let address = std::env::var("NSUPDATE_TEST_SERVER")
        .expect("set NSUPDATE_TEST_SERVER to the isolated BIND fixture");
    NsUpdateClient::new(
        &address,
        Some(TsigKey::new(algorithm, &format!("TEST-{algorithm}."), "dGVzdA==").unwrap()),
    )
    .with_transport(transport)
    .with_timeout(Some(Duration::from_secs(5)))
    .unwrap()
}

async fn query_a(name: &str) -> (u16, bool) {
    let address: SocketAddr = std::env::var("NSUPDATE_TEST_SERVER")
        .unwrap()
        .parse()
        .unwrap();
    let local = if address.is_ipv6() {
        "[::1]:0"
    } else {
        "127.0.0.1:0"
    };
    let socket = UdpSocket::bind(local).await.unwrap();
    socket.connect(address).await.unwrap();
    let mut packet = vec![0x56, 0x78, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    for label in name.split('.') {
        packet.push(label.len() as u8);
        packet.extend_from_slice(label.as_bytes());
    }
    packet.extend_from_slice(&[0, 0, 1, 0, 1]);
    socket.send(&packet).await.unwrap();
    let mut bytes = [0; 4096];
    let length = timeout(Duration::from_secs(5), socket.recv(&mut bytes))
        .await
        .unwrap()
        .unwrap();
    assert!(length >= 12);
    assert_eq!(&bytes[..2], &[0x56, 0x78]);
    assert_eq!(bytes[3] & 15, 0);
    let count = u16::from_be_bytes([bytes[6], bytes[7]]);
    (
        count,
        bytes[..length]
            .windows(4)
            .any(|chunk| chunk == [192, 0, 2, 123]),
    )
}

#[tokio::test]
#[ignore = "requires an isolated BIND instance configured with tests/bind/named.conf"]
async fn test_add_and_delete_with_all_tsig_algorithms() {
    for transport in [Transport::Udp, Transport::Tcp] {
        for algorithm in ["md5", "sha1", "sha224", "sha256", "sha384", "sha512"] {
            let client = client(algorithm, transport);
            let name = format!("auth-{algorithm}-{transport:?}.example.test");
            let add = UpdateMessageBuilder::new("example.test")
                .delete_record(&name, 1)
                .add_record(&name, 300, RData::A(Ipv4Addr::new(192, 0, 2, 123)))
                .build()
                .unwrap();
            let result = timeout(Duration::from_secs(5), client.send(&add))
                .await
                .unwrap()
                .unwrap();
            assert!(result.is_success(), "{algorithm}: RCODE {}", result.rcode());
            assert!(result.is_authenticated());
            assert_eq!(query_a(&name).await, (1, true));
            // Leave a TXT at the owner so the post-delete query is NOERROR/NODATA.
            let delete = UpdateMessageBuilder::new("example.test")
                .add_record(&name, 300, RData::TXT("marker".into()))
                .delete_record(&name, 1)
                .build()
                .unwrap();
            assert!(
                timeout(Duration::from_secs(5), client.send(&delete))
                    .await
                    .unwrap()
                    .unwrap()
                    .is_success()
            );
            assert_eq!(query_a(&name).await, (0, false));
            let cleanup = UpdateMessageBuilder::new("example.test")
                .delete_record(&name, 255)
                .build()
                .unwrap();
            assert!(
                timeout(Duration::from_secs(5), client.send(&cleanup))
                    .await
                    .unwrap()
                    .unwrap()
                    .is_success()
            );
        }
    }
}

#[tokio::test]
#[ignore = "requires an isolated BIND instance configured with tests/bind/named.conf"]
async fn test_authenticated_refusal_and_wrong_secret() {
    for transport in [Transport::Udp, Transport::Tcp] {
        let update = UpdateMessageBuilder::new("refused.test")
            .delete_record("host.refused.test", 1)
            .build()
            .unwrap();
        let result = timeout(
            Duration::from_secs(5),
            client("sha256", transport).send(&update),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(result.rcode(), 5);
        assert!(result.is_authenticated());
        assert!(!result.is_success());
        let address = std::env::var("NSUPDATE_TEST_SERVER").unwrap();
        let wrong = NsUpdateClient::new(
            &address,
            Some(TsigKey::new("sha256", "test-sha256.", "d3Jvbmc=").unwrap()),
        )
        .with_transport(transport);
        let error = timeout(Duration::from_secs(5), wrong.send(&update))
            .await
            .unwrap()
            .unwrap_err();
        assert!(matches!(
            error,
            NsUpdateError::Auth(AuthError::InvalidMacLength)
        ));
    }
}

#[tokio::test]
#[ignore = "requires an isolated BIND instance configured with tests/bind/named.conf"]
async fn test_unsigned_add_delete_and_refusal() {
    for transport in [Transport::Udp, Transport::Tcp] {
        let address = std::env::var("NSUPDATE_TEST_SERVER").unwrap();
        let client = NsUpdateClient::new(&address, None)
            .with_transport(transport)
            .with_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let name = "host.unsigned.test";
        let add = UpdateMessageBuilder::new("unsigned.test")
            .delete_record(name, 1)
            .add_record(name, 300, RData::A(Ipv4Addr::new(192, 0, 2, 123)))
            .build()
            .unwrap();
        let result = client.send(&add).await.unwrap();
        assert!(result.is_success());
        assert!(!result.is_authenticated());
        assert_eq!(query_a(name).await, (1, true));

        let delete = UpdateMessageBuilder::new("unsigned.test")
            .add_record(name, 300, RData::TXT("marker".into()))
            .delete_record(name, 1)
            .build()
            .unwrap();
        let result = client.send(&delete).await.unwrap();
        assert!(result.is_success());
        assert!(!result.is_authenticated());
        assert_eq!(query_a(name).await, (0, false));
        let cleanup = UpdateMessageBuilder::new("unsigned.test")
            .delete_record(name, 255)
            .build()
            .unwrap();
        assert!(client.send(&cleanup).await.unwrap().is_success());

        let denied = UpdateMessageBuilder::new("example.test")
            .delete_record("unsigned.example.test", 1)
            .build()
            .unwrap();
        let result = client.send(&denied).await.unwrap();
        assert_eq!(result.rcode(), 5);
        assert!(!result.is_success());
        assert!(!result.is_authenticated());
    }
}

#[tokio::test]
#[ignore = "requires an isolated BIND instance configured with tests/bind/named.conf"]
async fn test_auto_sends_large_updates_over_tcp() {
    for signed in [false, true] {
        let zone = if signed {
            "example.test"
        } else {
            "unsigned.test"
        };
        let name = format!("large.{zone}");
        let address = std::env::var("NSUPDATE_TEST_SERVER").unwrap();
        let client = if signed {
            client("sha256", Transport::Auto)
        } else {
            NsUpdateClient::new(&address, None)
                .with_timeout(Some(Duration::from_secs(5)))
                .unwrap()
        };
        let mut add = UpdateMessageBuilder::new(zone)
            .delete_record(&name, 255)
            .add_record(&name, 300, RData::A(Ipv4Addr::new(192, 0, 2, 123)));
        for value in ['x', 'y', 'z'] {
            add = add.add_record(&name, 300, RData::TXT(value.to_string().repeat(255)));
        }
        let add = add.build().unwrap();
        assert!(add.to_bytes().unwrap().len() > 512);
        let response = client.send(&add).await.unwrap();
        assert!(response.is_success());
        assert_eq!(response.is_authenticated(), signed);
        assert_eq!(query_a(&name).await, (1, true));
        let cleanup = UpdateMessageBuilder::new(zone)
            .delete_record(&name, 255)
            .build()
            .unwrap();
        assert!(client.send(&cleanup).await.unwrap().is_success());
    }
}
