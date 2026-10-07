use super::*;
use crate::{DnsRecord, RData, UpdateMessageBuilder};
use std::net::Ipv4Addr;

#[test]
fn test_serializes_all_update_sections_before_appending_tsig() {
    let mut message = UpdateMessageBuilder::new("example.test")
        .add_record(
            "host.example.test",
            300,
            RData::A(Ipv4Addr::new(192, 0, 2, 1)),
        )
        .build()
        .unwrap();
    message.header.id = 0x1234;
    message.prerequisites.push(DnsRecord {
        name: "host.example.test.".into(),
        rtype: 1,
        rclass: 254,
        ttl: 0,
        rdata: RData::Empty,
    });
    message.header.ancount = 1;
    message.additional.push(DnsRecord {
        name: "ns.example.test.".into(),
        rtype: 1,
        rclass: 1,
        ttl: 300,
        rdata: RData::A(Ipv4Addr::new(192, 0, 2, 53)),
    });
    message.header.arcount = 1;
    let unsigned = message.to_bytes().unwrap();
    let signed = encode(&message, "test-key.", &TsigAlg::SHA256, b"test").unwrap();

    assert_eq!(
        &signed[..12],
        &[0x12, 0x34, 0x28, 0, 0, 1, 0, 1, 0, 1, 0, 2]
    );
    assert_eq!(&signed[12..unsigned.len()], &unsigned[12..]);
    assert!(signed[unsigned.len()..].starts_with(b"\x08test-key\x00\x00\xfa\x00\xff"));
    assert_eq!(message.header.arcount, 1);
}

#[test]
fn test_message_length_limit_includes_tsig() {
    let mut builder = UpdateMessageBuilder::new(".");
    for _ in 0..245 {
        builder = builder.add_record(".", 0, RData::TXT("x".repeat(255)));
    }
    let mut message = builder
        .add_record(".", 0, RData::TXT("x".repeat(10)))
        .build()
        .unwrap();
    // Unsigned: header + root zone + 245 full TXT records + one short TXT.
    // TSIG: 10-byte key name + 10-byte RR header + 61-byte SHA256 RDATA.
    assert_eq!(message.to_bytes().unwrap().len(), 65454);
    assert_eq!(
        encode(&message, "test-key.", &TsigAlg::SHA256, b"test")
            .unwrap()
            .len(),
        65535
    );

    message.updates.last_mut().unwrap().rdata = RData::TXT("x".repeat(11));
    assert_eq!(message.to_bytes().unwrap().len(), 65455);
    assert!(matches!(
        encode(&message, "test-key.", &TsigAlg::SHA256, b"test"),
        Err(EncodeError::LengthExceeded {
            field: "DNS message",
            length: 65536,
            max: 65535
        })
    ));
}
