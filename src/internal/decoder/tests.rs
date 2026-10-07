use super::*;

#[test]
fn test_rejects_truncated_headers() {
    for len in 0..12 {
        assert!(matches!(
            DnsMessage::from_bytes(&[0; 12][..len]),
            Err(ParseError::Incomplete)
        ));
    }
}

#[test]
fn test_parses_update_response_header_fields() {
    let packet = [0x12, 0x34, 0xa8, 0x05, 0, 1, 0, 2, 0, 3, 0, 4];
    let header = DnsHeader::from_bytes(&packet).unwrap();
    assert_eq!(
        header,
        DnsHeader {
            id: 0x1234,
            flags: 0xa805,
            qdcount: 1,
            ancount: 2,
            nscount: 3,
            arcount: 4,
        }
    );
}
