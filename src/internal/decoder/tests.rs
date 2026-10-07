use super::*;

#[test]
fn test_rejects_truncated_headers() {
    for len in 0..12 {
        assert!(matches!(
            DnsHeader::from_bytes(&[0; 12][..len]),
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

fn response_fixture() -> Vec<u8> {
    let hex = include_str!("../../../tests/fixtures/tsig.txt")
        .lines()
        .find_map(|line| line.strip_prefix("sha256-response "))
        .unwrap();
    hex.as_bytes()
        .chunks_exact(2)
        .map(|chunk| u8::from_str_radix(std::str::from_utf8(chunk).unwrap(), 16).unwrap())
        .collect()
}

#[test]
fn test_rejects_duplicate_misplaced_and_nonfinal_tsig() {
    let packet = response_fixture();
    let start = decode(&packet).unwrap().tsig.unwrap().start;
    let mut duplicate = packet.clone();
    duplicate[11] = 2;
    duplicate.extend_from_slice(&packet[start..]);
    assert!(decode(&duplicate).is_err());
    for section in [6, 8] {
        let mut misplaced = packet.clone();
        misplaced[section + 1] = 1;
        misplaced[11] = 0;
        assert!(decode(&misplaced).is_err());
    }
    let mut nonfinal = packet;
    nonfinal[11] = 2;
    nonfinal.extend_from_slice(&[0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 4, 192, 0, 2, 1]);
    assert!(decode(&nonfinal).is_err());
}

#[test]
fn test_rejects_invalid_tsig_class_ttl_rdata_lengths_and_compressed_algorithm() {
    let packet = response_fixture();
    let start = decode(&packet).unwrap().tsig.unwrap().start;
    for offset in [start + 12, start + 14, start + 18, packet.len() - 1] {
        let mut malformed = packet.clone();
        malformed[offset] ^= 1;
        assert!(decode(&malformed).is_err(), "offset {offset}");
    }
    let mut compressed = packet;
    compressed[start + 20..start + 22].copy_from_slice(&[0xc0, 12]);
    assert!(matches!(
        decode(&compressed),
        Err(ParseError::InvalidDomainName)
    ));
}

#[test]
fn test_rejects_dns_name_cycles_forward_pointers_and_invalid_label_types() {
    for name in [
        vec![0xc0, 12],
        vec![0xc0, 14],
        vec![0xc0, 0],
        vec![0xc0],
        vec![0x40, 0],
        vec![0x80, 0],
        vec![63, b'a'],
    ] {
        let mut packet = vec![0; 12];
        packet[5] = 1;
        packet.extend_from_slice(&name);
        assert!(decode(&packet).is_err(), "{name:?}");
    }
    // A backwards pointer whose target runs forwards into the same pointer.
    let mut packet = vec![0; 12];
    packet[11] = 1;
    packet.extend_from_slice(&[1, b'a', 0xc0, 12]);
    assert!(decode(&packet).is_err());
}

#[test]
fn test_name_expansion_and_pointer_chains_are_bounded_without_recursion() {
    use super::reader::Reader;
    let mut expanded = vec![0; 12];
    for _ in 0..4 {
        expanded.push(63);
        expanded.extend_from_slice(&[b'a'; 63]);
    }
    expanded.push(0);
    let length = expanded.len();
    assert!(matches!(
        Reader::new(&expanded, 12, length).name(true),
        Err(ParseError::InvalidDomainName)
    ));

    let mut chain = vec![0; 13]; // root label at offset 12
    let mut target = 12;
    for _ in 0..129 {
        let position = chain.len();
        chain.extend_from_slice(&(0xc000u16 | target as u16).to_be_bytes());
        target = position;
    }
    assert!(
        Reader::new(&chain, target - 2, chain.len())
            .name(true)
            .is_ok()
    );
    assert!(matches!(
        Reader::new(&chain, target, chain.len()).name(true),
        Err(ParseError::InvalidDomainName)
    ));
}

#[test]
fn test_packet_counts_and_oversized_datagrams_are_checked() {
    let mut packet = response_fixture();
    packet[4..6].copy_from_slice(&2u16.to_be_bytes());
    assert!(decode(&packet).is_err());
    let mut packet = response_fixture();
    packet[6..8].copy_from_slice(&u16::MAX.to_be_bytes());
    assert!(decode(&packet).is_err());
    assert!(decode(&vec![0; 65536]).is_err());
}

#[test]
fn test_opt_record_must_be_unique_at_root_in_additional_with_bounded_options() {
    let opt = [0, 0, 41, 4, 208, 1, 0, 0, 0, 0, 0];
    let mut packet = vec![0; 12];
    packet[11] = 2;
    packet.extend_from_slice(&opt);
    packet.extend_from_slice(&opt);
    assert!(decode(&packet).is_err());
    let mut packet = vec![0; 12];
    packet[7] = 1;
    packet.extend_from_slice(&opt);
    assert!(decode(&packet).is_err());
    let mut packet = vec![0; 12];
    packet[11] = 1;
    packet.extend_from_slice(&[1, b'a']);
    packet.extend_from_slice(&opt);
    assert!(decode(&packet).is_err());
    let mut packet = vec![0; 12];
    packet[11] = 1;
    packet.extend_from_slice(&opt);
    packet[22] = 4;
    packet.extend_from_slice(&[0, 1, 0, 1]); // option promises an absent data byte
    assert!(decode(&packet).is_err());
}

#[test]
fn test_bounded_arbitrary_packet_inputs_never_panic() {
    let mut state = 0x12345678u32;
    for length in 0..1024 {
        let bytes: Vec<u8> = (0..length)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 17;
                state ^= state << 5;
                state as u8
            })
            .collect();
        let _ = decode(&bytes);
    }
}
