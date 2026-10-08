use super::*;
use crate::internal::encoder::encode_at;
use crate::{ParseError, RData, UpdateMessageBuilder};
use std::net::Ipv4Addr;

const TIME: u64 = 1700000000;

fn fixture(name: &str) -> Vec<u8> {
    let text = include_str!("../../../tests/fixtures/tsig.txt");
    let hex = text
        .lines()
        .find_map(|line| line.strip_prefix(&format!("{name} ")))
        .unwrap();
    hex.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|chunk| u8::from_str_radix(std::str::from_utf8(chunk).unwrap(), 16).unwrap())
        .collect()
}

fn request(algorithm: &TsigAlg) -> EncodedRequest {
    let mut message = UpdateMessageBuilder::new("example.test")
        .add_record(
            "host.example.test",
            300,
            RData::A(Ipv4Addr::new(192, 0, 2, 1)),
        )
        .build()
        .unwrap();
    message.header.id = 0x1234;
    encode_at(&message, "test-key.", algorithm, b"test", TIME).unwrap()
}

fn verify(bytes: &[u8]) -> Result<UpdateResponse, NsUpdateError> {
    verify_response(
        bytes,
        &request(&TsigAlg::SHA256),
        "test-key.",
        &TsigAlg::SHA256,
        b"test",
        TIME,
    )
}

#[test]
fn test_request_and_response_match_independent_vectors_for_all_algorithms() {
    for (name, algorithm) in [
        ("md5", TsigAlg::MD5),
        ("sha1", TsigAlg::SHA1),
        ("sha224", TsigAlg::SHA224),
        ("sha256", TsigAlg::SHA256),
        ("sha384", TsigAlg::SHA384),
        ("sha512", TsigAlg::SHA512),
    ] {
        let request = request(&algorithm);
        assert_eq!(request.bytes, fixture(&format!("{name}-request")), "{name}");
        let response = verify_response(
            &fixture(&format!("{name}-response")),
            &request,
            "TEST-KEY.",
            &algorithm,
            b"test",
            TIME,
        )
        .unwrap();
        assert!(response.is_success());
        assert!(response.is_authenticated());
        assert_eq!(response.rcode(), 0);
        assert_eq!(response.zone.unwrap().zname, "example.test.");
    }
}

#[test]
fn test_canonicalizes_request_key_name_after_decoding_escapes() {
    let mut message = UpdateMessageBuilder::new("example.test")
        .add_record(
            "host.example.test",
            300,
            RData::A(Ipv4Addr::new(192, 0, 2, 1)),
        )
        .build()
        .unwrap();
    message.header.id = 0x1234;
    let escaped = format!("{}084EST-KEY.", char::from(92));
    let signed = encode_at(&message, &escaped, &TsigAlg::SHA256, b"test", TIME).unwrap();
    assert_eq!(signed.bytes, fixture("sha256-request"));
}

#[test]
fn test_accepts_case_variants_compression_opaque_records_and_omitted_zone() {
    for label in [
        "mixed-case",
        "compressed-glue",
        "opaque-additional",
        "no-zone",
    ] {
        assert!(
            verify(&fixture(&format!("sha256-{label}")))
                .unwrap()
                .is_success(),
            "{label}"
        );
    }
}

#[test]
fn test_returns_authenticated_dns_errors_including_edns() {
    let refused = verify(&fixture("sha256-refused")).unwrap();
    assert_eq!(refused.rcode(), 5);
    assert!(!refused.is_success());
    let badvers = verify(&fixture("sha256-edns-error")).unwrap();
    assert_eq!(badvers.rcode(), 16);
    assert!(!badvers.is_success());
}

#[test]
fn test_reports_only_authenticated_tsig_errors() {
    assert!(matches!(
        verify(&fixture("sha256-badtime")),
        Err(NsUpdateError::Auth(AuthError::ServerError {
            code: 18,
            server_time: Some(1700003600)
        }))
    ));
    assert!(matches!(
        verify(&fixture("sha256-badtrunc")),
        Err(NsUpdateError::Auth(AuthError::ServerError {
            code: 22,
            server_time: None
        }))
    ));
    for label in ["unsigned-badkey", "short-mac"] {
        assert!(matches!(
            verify(&fixture(&format!("sha256-{label}"))),
            Err(NsUpdateError::Auth(AuthError::InvalidMacLength))
        ));
    }
    let mut forged = fixture("sha256-badtime");
    *forged.last_mut().unwrap() ^= 1;
    assert!(matches!(
        verify(&forged),
        Err(NsUpdateError::Auth(AuthError::InvalidMac))
    ));
}

#[test]
fn test_rejects_modified_message_timers_fudge_and_mac() {
    let original = fixture("sha256-compressed-glue");
    let tsig_start = decoder::decode(&original).unwrap().tsig.unwrap().start;
    // Header RCODE, glue RDATA, TSIG Time Signed, Fudge, and MAC are all signed.
    for offset in [
        3,
        tsig_start - 1,
        tsig_start + 10 + 10 + 13 + 5,
        tsig_start + 10 + 10 + 13 + 7,
        tsig_start + 10 + 10 + 13 + 10,
    ] {
        let mut bytes = original.clone();
        bytes[offset] ^= 1;
        assert!(
            matches!(
                verify(&bytes),
                Err(NsUpdateError::Auth(AuthError::InvalidMac))
            ),
            "offset {offset}"
        );
    }
}

#[test]
fn test_binds_response_to_request_mac_id_zone_key_and_algorithm() {
    let bytes = fixture("sha256-response");
    let mut other = request(&TsigAlg::SHA256);
    other.mac.as_mut().unwrap()[0] ^= 1;
    assert!(matches!(
        verify_response(&bytes, &other, "test-key.", &TsigAlg::SHA256, b"test", TIME),
        Err(NsUpdateError::Auth(AuthError::InvalidMac))
    ));
    assert!(matches!(
        verify_response(
            &bytes,
            &request(&TsigAlg::SHA256),
            "other-key.",
            &TsigAlg::SHA256,
            b"test",
            TIME
        ),
        Err(NsUpdateError::Auth(AuthError::KeyMismatch))
    ));
    assert!(matches!(
        verify_response(
            &bytes,
            &request(&TsigAlg::SHA256),
            "test-key.",
            &TsigAlg::SHA512,
            b"test",
            TIME
        ),
        Err(NsUpdateError::Auth(AuthError::AlgorithmMismatch))
    ));
    assert!(matches!(
        verify_response(
            &bytes,
            &request(&TsigAlg::SHA256),
            "test-key.",
            &TsigAlg::SHA256,
            b"wrong",
            TIME
        ),
        Err(NsUpdateError::Auth(AuthError::InvalidMac))
    ));
    assert!(matches!(
        verify(&fixture("sha256-wrong-zone")),
        Err(NsUpdateError::Auth(AuthError::ResponseMismatch("zone")))
    ));
    for offset in [0, bytes.len() - 6] {
        let mut wrong_id = bytes.clone();
        wrong_id[offset] ^= 1;
        assert!(matches!(
            verify(&wrong_id),
            Err(NsUpdateError::Auth(AuthError::ResponseMismatch(
                "message ID"
            )))
        ));
    }
    for flags in [0x2800u16, 0x8000] {
        let mut wrong_flags = bytes.clone();
        wrong_flags[2..4].copy_from_slice(&flags.to_be_bytes());
        assert!(matches!(
            verify(&wrong_flags),
            Err(NsUpdateError::Auth(AuthError::ResponseMismatch(_)))
        ));
    }
}

#[test]
fn test_time_window_is_inclusive_and_mac_is_checked_before_time() {
    let bytes = fixture("sha256-response");
    let request = request(&TsigAlg::SHA256);
    for now in [TIME - 300, TIME + 300] {
        assert!(
            verify_response(
                &bytes,
                &request,
                "test-key.",
                &TsigAlg::SHA256,
                b"test",
                now
            )
            .is_ok()
        );
    }
    for now in [TIME - 301, TIME + 301, u64::MAX] {
        assert!(matches!(
            verify_response(
                &bytes,
                &request,
                "test-key.",
                &TsigAlg::SHA256,
                b"test",
                now
            ),
            Err(NsUpdateError::Auth(AuthError::TimeOutsideWindow))
        ));
    }
    assert!(matches!(
        verify_response(
            &bytes,
            &request,
            "test-key.",
            &TsigAlg::SHA256,
            b"wrong",
            TIME + 301
        ),
        Err(NsUpdateError::Auth(AuthError::InvalidMac))
    ));
}

#[test]
fn test_missing_tsig_truncation_and_trailing_bytes_are_rejected() {
    let original = fixture("sha256-response");
    for length in 0..original.len() {
        assert!(verify(&original[..length]).is_err(), "length {length}");
    }
    let start = decoder::decode(&original).unwrap().tsig.unwrap().start;
    let mut unsigned = original[..start].to_vec();
    unsigned[10..12].copy_from_slice(&0u16.to_be_bytes());
    assert!(matches!(
        verify(&unsigned),
        Err(NsUpdateError::Auth(AuthError::MissingTsig))
    ));
    let mut trailing = original.clone();
    trailing.push(0);
    assert!(matches!(
        verify(&trailing),
        Err(NsUpdateError::Parse(ParseError::InvalidMessage(_)))
    ));
    assert!(matches!(
        verify(&fixture("sha256-tc")),
        Err(NsUpdateError::TruncatedResponse)
    ));
    let mut forged_tc = original;
    forged_tc[2] |= 2;
    assert!(matches!(
        verify(&forged_tc),
        Err(NsUpdateError::Auth(AuthError::InvalidMac))
    ));
}

#[test]
fn test_tsig_time_encoding_rejects_overflow() {
    let message = UpdateMessageBuilder::new("example.test").build().unwrap();
    assert!(
        encode_at(
            &message,
            "test-key.",
            &TsigAlg::SHA256,
            b"test",
            (1 << 48) - 1
        )
        .is_ok()
    );
    assert!(encode_at(&message, "test-key.", &TsigAlg::SHA256, b"test", 1 << 48).is_err());
}
