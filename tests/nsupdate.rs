use nsupdate::{
    DnsHeader, DnsUpdateMessage, EncodeError, NsUpdateClient, NsUpdateError, ParseError, RData,
    TsigKey, UpdateMessageBuilder, UpdateResponse,
};
use std::error::Error;
use std::future::Future;
use std::net::Ipv4Addr;

#[test]
fn test_accepts_supported_algorithm_names() {
    for algorithm in ["md5", "sha1", "sha224", "sha256", "sha384", "sha512"] {
        for name in [algorithm.to_string(), format!("hmac-{algorithm}")] {
            assert!(TsigKey::new(&name, "test-key.", "dGVzdA==").is_ok());
        }
    }
}

#[test]
fn test_returns_an_error_for_an_unsupported_algorithm() {
    let result = TsigKey::new("unsupported", "test-key.", "dGVzdA==");
    assert!(matches!(result, Err(NsUpdateError::InvalidAlgorithm(name)) if name == "unsupported"));
}

#[test]
fn test_returns_an_error_for_an_invalid_base64_key() {
    let error = TsigKey::new("sha256", "test-key.", "not base64!")
        .expect_err("invalid key must be rejected");
    assert!(matches!(error, NsUpdateError::Base64DecodeError(_)));
    assert!(error.source().is_some());
    assert!(!error.to_string().contains("not base64!"));
}

#[test]
fn test_client_accepts_the_public_builder_output() {
    let message: DnsUpdateMessage = UpdateMessageBuilder::new("example.test")
        .add_record(
            "host.example.test",
            300,
            RData::A(Ipv4Addr::new(192, 0, 2, 1)),
        )
        .build()
        .unwrap();

    fn accepts_response_future(_: impl Future<Output = Result<UpdateResponse, NsUpdateError>>) {}
    for key in [
        None,
        Some(TsigKey::new("sha256", "test-key.", "dGVzdA==").unwrap()),
    ] {
        let client = NsUpdateClient::new("127.0.0.1:53", key);
        accepts_response_future(client.send(&message));
    }
}

#[test]
fn test_parse_errors_are_public_and_preserve_their_source() {
    let error = DnsHeader::from_bytes(&[]).unwrap_err();
    assert!(matches!(error, ParseError::Incomplete));
    let error = NsUpdateError::from(error);
    assert!(matches!(
        error,
        NsUpdateError::Parse(ParseError::Incomplete)
    ));
    assert!(error.source().is_some());
}

#[test]
fn test_rejects_invalid_tsig_key_names() {
    for name in ["", "key..test", "key.test.."] {
        assert!(matches!(
            TsigKey::new("sha256", name, "dGVzdA=="),
            Err(NsUpdateError::Encode(EncodeError::InvalidDomainName(_)))
        ));
    }
}

#[tokio::test]
async fn test_send_validates_mutated_request_before_network_io() {
    let mut message = UpdateMessageBuilder::new("example.test")
        .add_record("host.example.test", 300, RData::A(Ipv4Addr::LOCALHOST))
        .build()
        .unwrap();
    message.updates[0].name = "outside.test".into();
    for key in [
        None,
        Some(TsigKey::new("sha256", "test-key.", "dGVzdA==").unwrap()),
    ] {
        let client = NsUpdateClient::new("invalid server address", key);
        let error = client.send(&message).await.unwrap_err();
        assert!(matches!(
            error,
            NsUpdateError::Encode(EncodeError::InvalidRecord(_))
        ));
        assert!(error.source().is_some());
    }
}

#[test]
fn test_tsig_key_debug_omits_the_secret() {
    let key = TsigKey::new("sha256", "key.example.", "c2VjcmV0LWtleQ==").unwrap();
    let debug = format!("{key:?}");
    assert!(debug.contains("key.example."));
    assert!(debug.contains("[REDACTED]"));
    assert!(!debug.contains("secret-key"));
    assert!(!debug.contains("c2VjcmV0LWtleQ=="));
    assert!(!debug.contains(&format!("{:?}", b"secret-key")));
}
