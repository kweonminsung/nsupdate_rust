use super::*;
use std::net::{Ipv4Addr, Ipv6Addr};

#[test]
fn test_encodes_absolute_names_and_dns_escapes() {
    for (name, expected) in [
        (".", b"\x00".as_slice()),
        ("example.test", b"\x07example\x04test\x00"),
        ("example.test.", b"\x07example\x04test\x00"),
        (r"a\.b.test", b"\x03a.b\x04test\x00"),
        (r"a\046b.test.", b"\x03a.b\x04test\x00"),
        (r"last\.", b"\x05last.\x00"),
        (r"\000\255.test", b"\x02\x00\xff\x04test\x00"),
        (r"a\\b", b"\x03a\\b\x00"),
        ("_sip._tcp.*.test", b"\x04_sip\x04_tcp\x01*\x04test\x00"),
    ] {
        assert_eq!(encode_domain_name(name).unwrap(), expected, "{name}");
    }
}

#[test]
fn test_rejects_malformed_names_without_normalizing_them() {
    for name in [
        "",
        "..",
        ".test",
        "a..test",
        "a.test..",
        "a b",
        "a\0b",
        "한글.test",
        "a\\",
        r"\1",
        r"\12.",
        r"\1xx",
        r"\256",
    ] {
        assert!(
            matches!(
                encode_domain_name(name),
                Err(EncodeError::InvalidDomainName(_))
            ),
            "{name:?}"
        );
    }
}

#[test]
fn test_domain_length_limits_apply_to_decoded_wire_bytes() {
    assert!(encode_domain_name(&"a".repeat(63)).is_ok());
    assert!(matches!(
        encode_domain_name(&"a".repeat(64)),
        Err(EncodeError::LengthExceeded {
            field: "DNS label",
            length: 64,
            max: 63
        })
    ));
    assert!(encode_domain_name(&r"\097".repeat(63)).is_ok());
    assert!(encode_domain_name(&r"\097".repeat(64)).is_err());
    let max_name = format!(
        "{}.{}.{}.{}",
        "a".repeat(63),
        "b".repeat(63),
        "c".repeat(63),
        "d".repeat(61)
    );
    assert_eq!(encode_domain_name(&max_name).unwrap().len(), 255);
    assert_eq!(
        encode_domain_name(&format!("{max_name}.")).unwrap().len(),
        255
    );
    for oversized in [format!("{max_name}d"), format!("{max_name}d.")] {
        assert!(matches!(
            encode_domain_name(&oversized),
            Err(EncodeError::LengthExceeded {
                field: "DNS name",
                length: 256,
                max: 255
            })
        ));
    }
}

#[test]
fn test_zone_membership_uses_case_insensitive_label_boundaries() {
    let zone = encode_domain_name("example.test").unwrap();
    for name in ["example.test", "a.EXAMPLE.test.", r"a.\101xample.test"] {
        assert!(is_in_zone(&encode_domain_name(name).unwrap(), &zone));
    }
    for name in [
        "notexample.test",
        "example.test.evil",
        r"a\.example.test",
        ".",
    ] {
        assert!(!is_in_zone(&encode_domain_name(name).unwrap(), &zone));
    }
    assert!(is_in_zone(&zone, &[0]));
}

#[test]
fn test_serializes_supported_rdata_in_network_byte_order() {
    let cases = [
        (1, RData::A(Ipv4Addr::new(192, 0, 2, 1)), b"\xc0\x00\x02\x01".to_vec()),
        (28, RData::AAAA(Ipv6Addr::LOCALHOST), vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
        (5, RData::CNAME("target.test".into()), b"\x06target\x04test\x00".to_vec()),
        (2, RData::NS("ns.test".into()), b"\x02ns\x04test\x00".to_vec()),
        (12, RData::PTR("ptr.test".into()), b"\x03ptr\x04test\x00".to_vec()),
        (15, RData::MX { preference: 10, exchange: "mx.test".into() }, b"\x00\x0a\x02mx\x04test\x00".to_vec()),
        (6, RData::SOA { mname: "ns.test".into(), rname: "hostmaster.test".into(), serial: 1, refresh: 2, retry: 3, expire: 4, minimum: 5 }, b"\x02ns\x04test\x00\x0ahostmaster\x04test\x00\x00\x00\x00\x01\x00\x00\x00\x02\x00\x00\x00\x03\x00\x00\x00\x04\x00\x00\x00\x05".to_vec()),
        (33, RData::SRV { priority: 1, weight: 2, port: 53, target: ".".into() }, b"\x00\x01\x00\x02\x00\x35\x00".to_vec()),
        (16, RData::TXT("é".into()), b"\x02\xc3\xa9".to_vec()),
    ];
    for (rtype, rdata, expected_data) in cases {
        let record = DnsRecord {
            name: ".".into(),
            rtype,
            rclass: 1,
            ttl: 300,
            rdata,
        };
        let bytes = record.to_bytes().unwrap();
        assert_eq!(&bytes[..1], &[0]);
        assert_eq!(&bytes[1..3], &rtype.to_be_bytes());
        assert_eq!(&bytes[3..9], &[0, 1, 0, 0, 1, 44]);
        assert_eq!(
            usize::from(u16::from_be_bytes(bytes[9..11].try_into().unwrap())),
            expected_data.len()
        );
        assert_eq!(&bytes[11..], &expected_data, "TYPE {rtype}");
    }
}

#[test]
fn test_txt_limits_count_bytes_and_empty_text_is_not_empty_rdata() {
    for text in [String::new(), "x".repeat(255), "é".repeat(127)] {
        let record = DnsRecord {
            name: ".".into(),
            rtype: 16,
            rclass: 1,
            ttl: 0,
            rdata: RData::TXT(text.clone()),
        };
        let bytes = record.to_bytes().unwrap();
        assert_eq!(usize::from(bytes[11]), text.len());
        assert_eq!(&bytes[12..], text.as_bytes());
    }
    for text in ["x".repeat(256), "é".repeat(128)] {
        let record = DnsRecord {
            name: ".".into(),
            rtype: 16,
            rclass: 1,
            ttl: 0,
            rdata: RData::TXT(text),
        };
        assert!(matches!(
            record.to_bytes(),
            Err(EncodeError::LengthExceeded {
                field: "TXT string",
                length: 256,
                max: 255
            })
        ));
    }
}

#[test]
fn test_checks_names_inside_every_domain_rdata_variant() {
    let bad = "bad..test".to_string();
    let cases = [
        (2, RData::NS(bad.clone())),
        (5, RData::CNAME(bad.clone())),
        (12, RData::PTR(bad.clone())),
        (
            15,
            RData::MX {
                preference: 1,
                exchange: bad.clone(),
            },
        ),
        (
            33,
            RData::SRV {
                priority: 1,
                weight: 2,
                port: 3,
                target: bad.clone(),
            },
        ),
        (
            6,
            RData::SOA {
                mname: bad.clone(),
                rname: "valid.test".into(),
                serial: 0,
                refresh: 0,
                retry: 0,
                expire: 0,
                minimum: 0,
            },
        ),
        (
            6,
            RData::SOA {
                mname: "valid.test".into(),
                rname: bad,
                serial: 0,
                refresh: 0,
                retry: 0,
                expire: 0,
                minimum: 0,
            },
        ),
    ];
    for (rtype, rdata) in cases {
        let record = DnsRecord {
            name: ".".into(),
            rtype,
            rclass: 1,
            ttl: 0,
            rdata,
        };
        assert!(matches!(
            record.to_bytes(),
            Err(EncodeError::InvalidDomainName(_))
        ));
    }
}

#[test]
fn test_count_and_message_length_boundaries_do_not_wrap() {
    assert_eq!(checked_count("count", 65535).unwrap(), 65535);
    assert!(matches!(
        checked_count("count", 65536),
        Err(EncodeError::LengthExceeded {
            length: 65536,
            max: 65535,
            ..
        })
    ));
    let mut bytes = vec![0; 65534];
    append_message(&mut bytes, &[1]).unwrap();
    assert!(append_message(&mut bytes, &[2]).is_err());
    assert_eq!(bytes.len(), 65535);
    assert_eq!(bytes[65534], 1);
}
