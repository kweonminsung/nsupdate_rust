use nsupdate::{EncodeError, RData, UpdateMessageBuilder};
use std::net::Ipv4Addr;

#[test]
fn test_serializes_prerequisites_and_value_deletion_with_section_counts() {
    let mut message = UpdateMessageBuilder::new("example.test")
        .delete_record_value("host.example.test", RData::A(Ipv4Addr::new(192, 0, 2, 1)))
        .require_name_exists("host.example.test")
        .require_name_absent("new.example.test")
        .require_rrset_exists("host.example.test", 1)
        .require_rrset_absent("host.example.test", 28)
        .require_rrset_equals("host.example.test", [RData::A(Ipv4Addr::new(192, 0, 2, 1))])
        .add_record(
            "host.example.test",
            60,
            RData::A(Ipv4Addr::new(192, 0, 2, 2)),
        )
        .build()
        .unwrap();
    message.header.id = 0x1234;
    let expected = [
        b"\x12\x34\x28\x00\x00\x01\x00\x05\x00\x02\x00\x00".as_slice(),
        b"\x07example\x04test\x00\x00\x06\x00\x01",
        b"\x04host\x07example\x04test\x00\x00\xff\x00\xff\x00\x00\x00\x00\x00\x00",
        b"\x03new\x07example\x04test\x00\x00\xff\x00\xfe\x00\x00\x00\x00\x00\x00",
        b"\x04host\x07example\x04test\x00\x00\x01\x00\xff\x00\x00\x00\x00\x00\x00",
        b"\x04host\x07example\x04test\x00\x00\x1c\x00\xfe\x00\x00\x00\x00\x00\x00",
        b"\x04host\x07example\x04test\x00\x00\x01\x00\x01\x00\x00\x00\x00\x00\x04\xc0\x00\x02\x01",
        b"\x04host\x07example\x04test\x00\x00\x01\x00\xfe\x00\x00\x00\x00\x00\x04\xc0\x00\x02\x01",
        b"\x04host\x07example\x04test\x00\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\xc0\x00\x02\x02",
    ]
    .concat();
    assert_eq!(message.to_bytes().unwrap(), expected);
}

#[test]
fn test_rejects_empty_or_mixed_rrset_values_and_preserves_the_error() {
    let invalid = [
        Vec::new(),
        vec![RData::Empty],
        vec![RData::A(Ipv4Addr::LOCALHOST), RData::Empty],
        vec![RData::A(Ipv4Addr::LOCALHOST), RData::TXT("value".into())],
    ];
    for values in invalid {
        let result = UpdateMessageBuilder::new("example.test")
            .require_rrset_equals("host.example.test", values)
            .require_rrset_equals("host.example.test", [RData::A(Ipv4Addr::LOCALHOST)])
            .add_record("host.example.test", 60, RData::A(Ipv4Addr::LOCALHOST))
            .build();
        assert!(matches!(result, Err(EncodeError::InvalidRecord(_))));
    }
    assert!(matches!(
        UpdateMessageBuilder::new("example.test")
            .delete_record_value("host.example.test", RData::Empty)
            .delete_record_value("host.example.test", RData::A(Ipv4Addr::LOCALHOST))
            .build(),
        Err(EncodeError::InvalidRecord(_))
    ));
}

#[test]
fn test_empty_txt_value_is_valid_rdata_for_prerequisites_and_deletions() {
    let message = UpdateMessageBuilder::new("example.test")
        .require_rrset_equals("host.example.test", [RData::TXT(String::new())])
        .delete_record_value("host.example.test", RData::TXT(String::new()))
        .build()
        .unwrap();
    assert_eq!(message.header.ancount, 1);
    assert_eq!(message.header.nscount, 1);
    assert_eq!(
        message.prerequisites[0].to_bytes().unwrap(),
        b"\x04host\x07example\x04test\x00\x00\x10\x00\x01\x00\x00\x00\x00\x00\x01\x00"
    );
    assert_eq!(
        message.updates[0].to_bytes().unwrap(),
        b"\x04host\x07example\x04test\x00\x00\x10\x00\xfe\x00\x00\x00\x00\x00\x01\x00"
    );
}

#[test]
fn test_new_methods_validate_owners_and_rdata_at_build_time() {
    for name in ["outside.test", "bad..example.test"] {
        for builder in [
            UpdateMessageBuilder::new("example.test").require_name_exists(name),
            UpdateMessageBuilder::new("example.test").require_name_absent(name),
            UpdateMessageBuilder::new("example.test").require_rrset_exists(name, 1),
            UpdateMessageBuilder::new("example.test").require_rrset_absent(name, 1),
            UpdateMessageBuilder::new("example.test")
                .require_rrset_equals(name, [RData::A(Ipv4Addr::LOCALHOST)]),
            UpdateMessageBuilder::new("example.test")
                .delete_record_value(name, RData::A(Ipv4Addr::LOCALHOST)),
        ] {
            assert!(builder.build().is_err(), "{name}");
        }
    }
    for builder in [
        UpdateMessageBuilder::new("example.test")
            .require_rrset_equals("host.example.test", [RData::CNAME("bad..test".into())]),
        UpdateMessageBuilder::new("example.test")
            .delete_record_value("host.example.test", RData::CNAME("bad..test".into())),
        UpdateMessageBuilder::new("example.test")
            .require_rrset_equals("host.example.test", [RData::TXT("x".repeat(256))]),
        UpdateMessageBuilder::new("example.test")
            .delete_record_value("host.example.test", RData::TXT("x".repeat(256))),
    ] {
        assert!(builder.build().is_err());
    }
}

#[test]
fn test_rrset_presence_rejects_meta_types_and_accepts_unknown_data_types() {
    for rtype in [0, 41, 65535].into_iter().chain(128..=255) {
        for builder in [
            UpdateMessageBuilder::new("example.test")
                .require_rrset_exists("host.example.test", rtype),
            UpdateMessageBuilder::new("example.test")
                .require_rrset_absent("host.example.test", rtype),
        ] {
            assert!(
                matches!(builder.build(), Err(EncodeError::InvalidRecord(_))),
                "{rtype}"
            );
        }
    }
    for rtype in [1, 28, 127, 256, 257, 61439, 65280, 65534] {
        assert!(
            UpdateMessageBuilder::new("example.test")
                .require_rrset_exists("host.example.test", rtype)
                .require_rrset_absent("other.example.test", rtype)
                .build()
                .is_ok(),
            "{rtype}"
        );
    }
}

#[test]
fn test_prerequisite_count_and_packet_length_do_not_overflow() {
    let mut builder = UpdateMessageBuilder::new("example.test");
    for _ in 0..65536 {
        builder = builder.require_name_exists("example.test");
    }
    assert!(matches!(
        builder.build(),
        Err(EncodeError::LengthExceeded {
            field: "Prerequisite count",
            length: 65536,
            max: 65535,
        })
    ));

    let values = (0..240).map(|_| RData::TXT("x".repeat(255)));
    assert!(matches!(
        UpdateMessageBuilder::new("example.test")
            .require_rrset_equals("example.test", values)
            .build(),
        Err(EncodeError::LengthExceeded {
            field: "DNS message",
            max: 65535,
            ..
        })
    ));
}
