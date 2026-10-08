mod support;

use nsupdate::{
    AuthError, NsUpdateClient, NsUpdateError, Transport, TsigKey, UpdateMessageBuilder,
    UpdateResponse,
};
use std::io::ErrorKind;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::time::timeout;

fn frame(response: &[u8]) -> Vec<u8> {
    let mut frame = (response.len() as u16).to_be_bytes().to_vec();
    frame.extend_from_slice(response);
    frame
}

async fn exchange(
    make_response: impl FnOnce(&[u8]) -> Vec<u8>,
    signed: bool,
    fragmented: bool,
    close: bool,
) -> Result<UpdateResponse, NsUpdateError> {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    // Exercise hostname resolution as well as TCP framing.
    let address = format!("localhost:{}", listener.local_addr().unwrap().port());
    let key = signed.then(|| TsigKey::new("sha256", "test-key.", "dGVzdA==").unwrap());
    let client = NsUpdateClient::new(&address, key)
        .with_transport(Transport::Tcp)
        .with_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    let request = UpdateMessageBuilder::new("example.test").build().unwrap();
    let server = async {
        let (mut stream, _) = listener.accept().await.unwrap();
        let length = stream.read_u16().await.unwrap();
        let mut packet = vec![0; usize::from(length)];
        stream.read_exact(&mut packet).await.unwrap();
        let response = make_response(&packet);
        let chunk_size = if fragmented { 1 } else { response.len().max(1) };
        for chunk in response.chunks(chunk_size) {
            stream.write_all(chunk).await.unwrap();
            if fragmented {
                tokio::task::yield_now().await;
            }
        }
        if close {
            stream.shutdown().await.unwrap();
        } else {
            // Parsing or timeout must finish without waiting for the server to close.
            assert_eq!(stream.read(&mut [0]).await.unwrap(), 0);
        }
    };
    let (result, ()) = timeout(Duration::from_secs(5), async {
        tokio::join!(client.send(&request), server)
    })
    .await
    .unwrap();
    result
}

#[tokio::test]
async fn test_authenticates_fragmented_prefix_and_body_without_waiting_for_eof() {
    let response = exchange(
        |request| frame(&support::response(request, "sha256", 0, true)),
        true,
        true,
        false,
    )
    .await
    .unwrap();
    assert!(response.is_success());
    assert!(response.is_authenticated());
}

#[tokio::test]
async fn test_rejects_short_frame_lengths_without_waiting_for_a_body() {
    for length in [0u16, 1, 11] {
        assert!(matches!(
            exchange(|_| length.to_be_bytes().to_vec(), false, false, false).await,
            Err(NsUpdateError::Parse(_))
        ));
    }
}

#[tokio::test]
async fn test_rejects_eof_in_prefix_or_body() {
    for bytes in [vec![], vec![0], vec![0, 12], vec![0, 12, 0, 1]] {
        assert!(matches!(
            exchange(|_| bytes, false, false, true).await,
            Err(NsUpdateError::Io(error)) if error.kind() == ErrorKind::UnexpectedEof
        ));
    }
}

#[tokio::test]
async fn test_times_out_while_waiting_for_prefix_or_body() {
    for bytes in [vec![], vec![0], vec![0, 12, 0, 1]] {
        assert!(matches!(
            exchange(|_| bytes, false, false, false).await,
            Err(NsUpdateError::Timeout)
        ));
    }
}

#[tokio::test]
async fn test_rejects_unsigned_and_modified_tcp_responses() {
    for mutation in ["unsigned", "mac", "id", "trailing"] {
        let result = exchange(
            |request| {
                let mut response = support::response(request, "sha256", 0, false);
                match mutation {
                    "unsigned" => {
                        response.truncate(12);
                        response[11] = 0;
                    }
                    "mac" => {
                        let index = response.len() - 7;
                        response[index] ^= 1;
                    }
                    "id" => response[0] ^= 1,
                    "trailing" => response.push(0),
                    _ => unreachable!(),
                }
                frame(&response)
            },
            true,
            false,
            false,
        )
        .await;
        match mutation {
            "unsigned" => assert!(matches!(
                result,
                Err(NsUpdateError::Auth(AuthError::MissingTsig))
            )),
            "mac" => assert!(matches!(
                result,
                Err(NsUpdateError::Auth(AuthError::InvalidMac))
            )),
            "id" => assert!(matches!(
                result,
                Err(NsUpdateError::Auth(AuthError::ResponseMismatch(_)))
            )),
            "trailing" => assert!(matches!(result, Err(NsUpdateError::Parse(_)))),
            _ => unreachable!(),
        }
    }
}

#[tokio::test]
async fn test_tcp_truncation_is_reported_without_retrying() {
    let result = exchange(
        |request| {
            frame(&support::response_with_flags(
                request, "sha256", 0xaa00, false,
            ))
        },
        true,
        false,
        false,
    )
    .await;
    assert!(matches!(result, Err(NsUpdateError::TruncatedResponse)));
}

#[tokio::test]
async fn test_accepts_a_65535_byte_tcp_response() {
    let result = exchange(
        |request| {
            let mut response = request[..2].to_vec();
            response.extend_from_slice(&[0xa8, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
            // One opaque Additional RR fills the remaining frame.
            response.extend_from_slice(&[0, 0xff, 0x00, 0, 1, 0, 0, 0, 0]);
            response.extend_from_slice(&65512u16.to_be_bytes());
            response.resize(65535, 0);
            frame(&response)
        },
        false,
        false,
        false,
    )
    .await
    .unwrap();
    assert!(result.is_success());
    assert!(!result.is_authenticated());
}
