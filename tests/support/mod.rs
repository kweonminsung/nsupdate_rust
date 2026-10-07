use hmac::{Hmac, Mac};
use md5::Md5;
use sha1::Sha1;
use sha2::{Sha224, Sha256, Sha384, Sha512};

// Mock server independent of the library parser and signer.
fn name(value: &str) -> Vec<u8> {
    let mut wire = Vec::new();
    for label in value.split('.') {
        wire.push(label.len() as u8);
        wire.extend_from_slice(label.as_bytes());
    }
    wire.push(0);
    wire
}

fn mac(algorithm: &str, data: &[u8]) -> Vec<u8> {
    macro_rules! hash {
        ($hash:ty) => {{
            let mut mac = Hmac::<$hash>::new_from_slice(b"test").unwrap();
            mac.update(data);
            mac.finalize().into_bytes().to_vec()
        }};
    }
    match algorithm {
        "md5" => hash!(Md5),
        "sha1" => hash!(Sha1),
        "sha224" => hash!(Sha224),
        "sha256" => hash!(Sha256),
        "sha384" => hash!(Sha384),
        "sha512" => hash!(Sha512),
        _ => unreachable!(),
    }
}

pub fn response(request: &[u8], algorithm: &str, rcode: u8, padding: bool) -> Vec<u8> {
    let key_name = name("test-key");
    let algorithm_name = name(&if algorithm == "md5" {
        "hmac-md5.sig-alg.reg.int".into()
    } else {
        format!("hmac-{algorithm}")
    });
    let mac_len = mac(algorithm, &[]).len();
    let start = request.len() - key_name.len() - 10 - algorithm_name.len() - 16 - mac_len;
    assert_eq!(&request[start..start + key_name.len()], &key_name);
    let rdata_start = start + key_name.len() + 10;
    assert_eq!(
        &request[rdata_start..rdata_start + algorithm_name.len()],
        &algorithm_name
    );
    let time_start = rdata_start + algorithm_name.len();
    let timers = &request[time_start..time_start + 8];
    let request_mac = &request[time_start + 10..time_start + 10 + mac_len];
    let mut unsigned = request[..start].to_vec();
    let count = u16::from_be_bytes([unsigned[10], unsigned[11]]) - 1;
    unsigned[10..12].copy_from_slice(&count.to_be_bytes());
    let mut variables = key_name.clone();
    variables.extend_from_slice(&[0, 255, 0, 0, 0, 0]);
    variables.extend_from_slice(&algorithm_name);
    variables.extend_from_slice(timers);
    variables.extend_from_slice(&[0, 0, 0, 0]);
    let mut request_data = unsigned;
    request_data.extend_from_slice(&variables);
    assert_eq!(
        mac(algorithm, &request_data),
        request_mac,
        "client request MAC"
    );

    let mut answer = request[..2].to_vec();
    answer.extend_from_slice(&[0xa8, rcode, 0, 0, 0, 0, 0, 0, 0, u8::from(padding)]);
    if padding {
        // Pad the response beyond 512 bytes.
        answer.extend_from_slice(&[0, 0, 41, 4, 208, 0, 0, 0, 0, 2, 92, 0, 12, 2, 88]);
        answer.extend_from_slice(&[0; 600]);
    }
    let mut signed_data = (mac_len as u16).to_be_bytes().to_vec();
    signed_data.extend_from_slice(request_mac);
    signed_data.extend_from_slice(&answer);
    signed_data.extend_from_slice(&variables);
    let response_mac = mac(algorithm, &signed_data);
    let mut rdata = algorithm_name;
    rdata.extend_from_slice(timers);
    rdata.extend_from_slice(&(mac_len as u16).to_be_bytes());
    rdata.extend_from_slice(&response_mac);
    rdata.extend_from_slice(&request[..2]);
    rdata.extend_from_slice(&[0, 0, 0, 0]);
    answer[11] += 1;
    answer.extend_from_slice(&key_name);
    answer.extend_from_slice(&[0, 250, 0, 255, 0, 0, 0, 0]);
    answer.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
    answer.extend_from_slice(&rdata);
    answer
}
