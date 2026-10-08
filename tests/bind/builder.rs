use super::{client, query_a};
use nsupdate::{RData, Transport, UpdateMessageBuilder};
use std::net::Ipv4Addr;

#[tokio::test]
#[ignore = "requires an isolated BIND instance configured with tests/bind/named.conf"]
async fn test_name_and_rrset_presence_prerequisites() {
    for transport in [Transport::Udp, Transport::Tcp] {
        let client = client("sha256", transport);
        let name = format!("presence-{transport:?}.example.test");
        let absent = format!("absent-{transport:?}.example.test");
        let initial = UpdateMessageBuilder::new("example.test")
            .delete_record(&name, 255)
            .delete_record(&absent, 255)
            .add_record(&name, 300, RData::A(Ipv4Addr::new(192, 0, 2, 123)))
            .build()
            .unwrap();
        assert!(client.send(&initial).await.unwrap().is_success());

        for (builder, rcode) in [
            (
                UpdateMessageBuilder::new("example.test").require_name_exists(&name),
                0,
            ),
            (
                UpdateMessageBuilder::new("example.test").require_name_exists(&absent),
                3,
            ),
            (
                UpdateMessageBuilder::new("example.test").require_name_absent(&absent),
                0,
            ),
            (
                UpdateMessageBuilder::new("example.test").require_name_absent(&name),
                6,
            ),
            (
                UpdateMessageBuilder::new("example.test").require_rrset_exists(&name, 1),
                0,
            ),
            (
                UpdateMessageBuilder::new("example.test").require_rrset_exists(&name, 28),
                8,
            ),
            (
                UpdateMessageBuilder::new("example.test").require_rrset_absent(&name, 28),
                0,
            ),
            (
                UpdateMessageBuilder::new("example.test").require_rrset_absent(&name, 1),
                7,
            ),
        ] {
            let response = client.send(&builder.build().unwrap()).await.unwrap();
            assert_eq!(response.rcode(), rcode, "{transport:?}");
            assert!(response.is_authenticated());
        }
        let cleanup = UpdateMessageBuilder::new("example.test")
            .delete_record(&name, 255)
            .build()
            .unwrap();
        assert!(client.send(&cleanup).await.unwrap().is_success());
    }
}

#[tokio::test]
#[ignore = "requires an isolated BIND instance configured with tests/bind/named.conf"]
async fn test_rrset_equality_is_exact_and_value_deletion_preserves_other_values() {
    for transport in [Transport::Udp, Transport::Tcp] {
        let client = client("sha256", transport);
        let name = format!("values-{transport:?}.example.test");
        let initial = UpdateMessageBuilder::new("example.test")
            .delete_record(&name, 255)
            .add_record(&name, 300, RData::A(Ipv4Addr::new(192, 0, 2, 123)))
            .add_record(&name, 300, RData::A(Ipv4Addr::new(192, 0, 2, 124)))
            .add_record(&name, 300, RData::TXT("marker".into()))
            .build()
            .unwrap();
        assert!(client.send(&initial).await.unwrap().is_success());

        let subset = UpdateMessageBuilder::new("example.test")
            .require_rrset_equals(&name, [RData::A(Ipv4Addr::new(192, 0, 2, 123))])
            .delete_record(&name, 1)
            .build()
            .unwrap();
        let response = client.send(&subset).await.unwrap();
        assert_eq!(response.rcode(), 8);
        assert!(response.is_authenticated());
        assert_eq!(query_a(&name).await, (2, true));

        let matching = UpdateMessageBuilder::new("example.test")
            .require_rrset_equals(
                &name,
                [
                    RData::A(Ipv4Addr::new(192, 0, 2, 124)),
                    RData::A(Ipv4Addr::new(192, 0, 2, 123)),
                ],
            )
            .delete_record_value(&name, RData::A(Ipv4Addr::new(192, 0, 2, 123)))
            .build()
            .unwrap();
        let response = client.send(&matching).await.unwrap();
        assert!(response.is_success());
        assert!(response.is_authenticated());
        assert_eq!(query_a(&name).await, (1, false));

        let remove_last = UpdateMessageBuilder::new("example.test")
            .require_rrset_equals(&name, [RData::A(Ipv4Addr::new(192, 0, 2, 124))])
            .delete_record_value(&name, RData::A(Ipv4Addr::new(192, 0, 2, 124)))
            .build()
            .unwrap();
        assert!(client.send(&remove_last).await.unwrap().is_success());
        assert_eq!(query_a(&name).await, (0, false));

        let cleanup = UpdateMessageBuilder::new("example.test")
            .delete_record(&name, 255)
            .build()
            .unwrap();
        assert!(client.send(&cleanup).await.unwrap().is_success());
    }
}
