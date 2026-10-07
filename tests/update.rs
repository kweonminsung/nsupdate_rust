use nsupdate::{DnsRecord, DnsUpdateMessage, EncodeError, RData, UpdateMessageBuilder};
use std::net::Ipv4Addr;

fn empty_update() -> DnsUpdateMessage {
    UpdateMessageBuilder::new("example.test").build().unwrap()
}

fn address_record() -> DnsRecord {
    DnsRecord {
        name: "host.example.test".into(),
        rtype: 1,
        rclass: 1,
        ttl: 300,
        rdata: RData::A(Ipv4Addr::new(192, 0, 2, 1)),
    }
}

#[test]
fn test_builder_preserves_interleaved_add_and_delete_order() {
    let message = UpdateMessageBuilder::new("example.test")
        .add_record(
            "host.example.test",
            100,
            RData::A(Ipv4Addr::new(192, 0, 2, 1)),
        )
        .delete_record("host.example.test", 1)
        .add_record(
            "host.example.test",
            200,
            RData::A(Ipv4Addr::new(192, 0, 2, 2)),
        )
        .delete_record("other.example.test", 255)
        .build()
        .unwrap();
    assert_eq!(message.header.nscount, 4);
    assert_eq!(
        message
            .updates
            .iter()
            .map(|rr| (rr.rclass, rr.rtype, rr.ttl))
            .collect::<Vec<_>>(),
        [(1, 1, 100), (255, 1, 0), (1, 1, 200), (255, 255, 0)]
    );
}

#[test]
fn test_builder_serializes_a_complete_update_packet() {
    let mut message = UpdateMessageBuilder::new("example.test")
        .delete_record("host.example.test", 1)
        .add_record(
            "host.example.test",
            300,
            RData::A(Ipv4Addr::new(192, 0, 2, 1)),
        )
        .build()
        .unwrap();
    message.header.id = 0x1234;
    let expected = [
        b"\x12\x34\x28\x00\x00\x01\x00\x00\x00\x02\x00\x00".as_slice(),
        b"\x07example\x04test\x00\x00\x06\x00\x01",
        b"\x04host\x07example\x04test\x00\x00\x01\x00\xff\x00\x00\x00\x00\x00\x00",
        b"\x04host\x07example\x04test\x00\x00\x01\x00\x01\x00\x00\x01\x2c\x00\x04\xc0\x00\x02\x01",
    ]
    .concat();
    assert_eq!(message.to_bytes().unwrap(), expected);
}

#[test]
fn test_empty_addition_returns_an_error_at_build_time() {
    let result = UpdateMessageBuilder::new("example.test")
        .add_record("host.example.test", 300, RData::Empty)
        .add_record("host.example.test", 300, RData::A(Ipv4Addr::LOCALHOST))
        .build();
    assert!(matches!(result, Err(EncodeError::InvalidRecord(_))));
}

#[test]
fn test_builder_checks_zone_owner_and_rdata_names() {
    assert!(matches!(
        UpdateMessageBuilder::new("").build(),
        Err(EncodeError::InvalidDomainName(_))
    ));
    for owner in [
        "bad..example.test",
        "notexample.test",
        "example.test.other",
        r"host\.example.test",
    ] {
        assert!(
            UpdateMessageBuilder::new("example.test")
                .delete_record(owner, 1)
                .build()
                .is_err(),
            "{owner}"
        );
    }
    for owner in [
        "EXAMPLE.TEST.",
        "host.example.test",
        r"host.\101xample.test",
    ] {
        assert!(
            UpdateMessageBuilder::new("example.test")
                .delete_record(owner, 1)
                .build()
                .is_ok(),
            "{owner}"
        );
    }
    // Names in RDATA may reference a different zone.
    assert!(
        UpdateMessageBuilder::new("example.test")
            .add_record(
                "alias.example.test",
                300,
                RData::CNAME("target.other.test".into())
            )
            .build()
            .is_ok()
    );
    assert!(
        UpdateMessageBuilder::new("example.test")
            .add_record(
                "alias.example.test",
                300,
                RData::CNAME("target..test".into())
            )
            .build()
            .is_err()
    );
}

#[test]
fn test_rejects_reserved_and_meta_record_types_but_allows_unknown_rrset_deletion() {
    for rtype in [0, 41, 249, 250, 251, 252, 253, 254, 65535] {
        assert!(
            UpdateMessageBuilder::new("example.test")
                .delete_record("host.example.test", rtype)
                .build()
                .is_err(),
            "{rtype}"
        );
    }
    for rtype in [1, 255, 65280] {
        assert!(
            UpdateMessageBuilder::new("example.test")
                .delete_record("host.example.test", rtype)
                .build()
                .is_ok(),
            "{rtype}"
        );
    }
}

#[test]
fn test_ttl_boundaries() {
    for ttl in [0, 2147483647] {
        assert!(
            UpdateMessageBuilder::new("example.test")
                .add_record("host.example.test", ttl, RData::A(Ipv4Addr::LOCALHOST))
                .build()
                .is_ok()
        );
    }
    for ttl in [2147483648, u32::MAX] {
        assert!(matches!(
            UpdateMessageBuilder::new("example.test")
                .add_record("host.example.test", ttl, RData::A(Ipv4Addr::LOCALHOST))
                .build(),
            Err(EncodeError::InvalidRecord(_))
        ));
    }
}

#[test]
fn test_revalidates_public_header_and_zone_fields() {
    for flags in [0, 0xa800, 0x2801, 0x2900, 0x2a00] {
        let mut message = empty_update();
        message.header.flags = flags;
        assert!(matches!(
            message.to_bytes(),
            Err(EncodeError::InvalidMessage(_))
        ));
    }
    for index in 0..4 {
        let mut message = empty_update();
        let counts = [
            &mut message.header.qdcount,
            &mut message.header.ancount,
            &mut message.header.nscount,
            &mut message.header.arcount,
        ];
        *counts.into_iter().nth(index).unwrap() += 1;
        assert!(matches!(
            message.to_bytes(),
            Err(EncodeError::InvalidMessage(_))
        ));
    }
    let mut message = empty_update();
    message.zone.ztype = 1;
    assert!(message.to_bytes().is_err());
    message.zone.ztype = 6;
    message.zone.zclass = 255;
    assert!(message.to_bytes().is_err());
    message.zone.zclass = 1;
    message.zone.zname = "bad..test".into();
    assert!(message.to_bytes().is_err());
}

#[test]
fn test_revalidates_record_type_and_update_class_semantics() {
    for (rtype, rclass, ttl, empty, valid) in [
        (1, 1, 300, false, true),
        (1, 254, 0, false, true),
        (1, 255, 0, true, true),
        (255, 255, 0, true, true),
        (28, 1, 300, false, false),
        (1, 1, 0, true, false),
        (1, 255, 300, true, false),
        (1, 255, 0, false, false),
        (1, 254, 300, false, false),
        (1, 254, 0, true, false),
        (255, 254, 0, false, false),
        (1, 3, 0, false, false),
    ] {
        let mut message = empty_update();
        let mut record = address_record();
        record.rtype = rtype;
        record.rclass = rclass;
        record.ttl = ttl;
        if empty {
            record.rdata = RData::Empty;
        }
        message.updates.push(record);
        message.header.nscount = 1;
        assert_eq!(
            message.to_bytes().is_ok(),
            valid,
            "{rtype} {rclass} {ttl} {empty}"
        );
    }
}

#[test]
fn test_checks_all_prerequisite_forms() {
    for (rtype, rclass, ttl, empty, valid) in [
        (1, 1, 0, false, true),
        (1, 255, 0, true, true),
        (1, 254, 0, true, true),
        (255, 255, 0, true, true),
        (255, 254, 0, true, true),
        (1, 1, 1, false, false),
        (1, 255, 0, false, false),
        (1, 254, 0, false, false),
        (1, 1, 0, true, false),
        (1, 3, 0, true, false),
    ] {
        let mut message = empty_update();
        let mut record = address_record();
        record.rtype = rtype;
        record.rclass = rclass;
        record.ttl = ttl;
        if empty {
            record.rdata = RData::Empty;
        }
        message.prerequisites.push(record);
        message.header.ancount = 1;
        assert_eq!(
            message.to_bytes().is_ok(),
            valid,
            "{rtype} {rclass} {ttl} {empty}"
        );
    }
    let mut message = empty_update();
    let mut record = address_record();
    record.name = "other.test".into();
    record.ttl = 0;
    message.prerequisites.push(record);
    message.header.ancount = 1;
    assert!(message.to_bytes().is_err());
}

#[test]
fn test_allows_out_of_zone_glue_but_rejects_caller_supplied_tsig() {
    let mut message = empty_update();
    let mut glue = address_record();
    glue.name = "ns.other.test".into();
    message.additional.push(glue);
    message.header.arcount = 1;
    assert!(message.to_bytes().is_ok());
    message.additional[0].rtype = 250;
    message.additional[0].rclass = 255;
    message.additional[0].ttl = 0;
    message.additional[0].rdata = RData::Empty;
    assert!(message.to_bytes().is_err());
}

#[test]
fn test_rejects_oversized_counts_and_packets() {
    let mut builder = UpdateMessageBuilder::new("example.test");
    for _ in 0..65536 {
        builder = builder.delete_record("example.test", 1);
    }
    assert!(matches!(
        builder.build(),
        Err(EncodeError::LengthExceeded {
            field: "Update count",
            length: 65536,
            max: 65535
        })
    ));
    let mut builder = UpdateMessageBuilder::new("example.test");
    for _ in 0..240 {
        builder = builder.add_record("example.test", 0, RData::TXT("x".repeat(255)));
    }
    assert!(matches!(
        builder.build(),
        Err(EncodeError::LengthExceeded {
            field: "DNS message",
            max: 65535,
            ..
        })
    ));
    let mut message = empty_update();
    message.additional = (0..65536).map(|_| address_record()).collect();
    assert!(matches!(
        message.to_bytes(),
        Err(EncodeError::LengthExceeded {
            field: "Additional count",
            length: 65536,
            max: 65535
        })
    ));
}
