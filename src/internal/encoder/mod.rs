use crate::internal::constants::TsigAlg;
use crate::internal::protocol::{DnsUpdateMessage, encode_domain_name};
use hmac::{Hmac, Mac};
use md5::Md5;
use sha1::Sha1;
use sha2::{Sha224, Sha256, Sha384, Sha512};

pub fn encode(
    message: &DnsUpdateMessage,
    tsig_key_name: &str,
    algorithm: &TsigAlg,
    tsig_key: &[u8],
) -> Vec<u8> {
    // Get the unsigned DNS UPDATE message bytes
    let unsigned_bytes = message.to_bytes();

    // Get current time for TSIG
    let time_signed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // RFC 2845 constants
    let algorithm_name = algorithm.to_name();
    let fudge: u16 = 300; // 5 minutes
    let original_id = message.header.id;
    let error: u16 = 0;
    let other_len: u16 = 0;

    // Build HMAC input (RFC 2845 Section 3.4.2)
    let mut signing_data = Vec::new();

    // Request MAC: empty for initial request
    signing_data.extend_from_slice(&0u16.to_be_bytes());

    // DNS message (without TSIG)
    signing_data.extend_from_slice(&unsigned_bytes);

    // TSIG RDATA fields in order (no RR header)
    signing_data.extend_from_slice(&encode_domain_name(tsig_key_name)); // key name
    signing_data.extend_from_slice(&255u16.to_be_bytes()); // CLASS = ANY (255)
    signing_data.extend_from_slice(&0u32.to_be_bytes()); // TTL = 0
    signing_data.extend_from_slice(&encode_domain_name(algorithm_name)); // algorithm name

    // 48-bit Time Signed  = upper 16 bits + lower 32 bits
    let mut time_buf = [0u8; 6];
    time_buf[..2].copy_from_slice(&((time_signed >> 32) as u16).to_be_bytes());
    time_buf[2..].copy_from_slice(&(time_signed as u32).to_be_bytes());
    signing_data.extend_from_slice(&time_buf);

    signing_data.extend_from_slice(&fudge.to_be_bytes());
    signing_data.extend_from_slice(&error.to_be_bytes());
    signing_data.extend_from_slice(&other_len.to_be_bytes());

    // Compute HMAC
    let mac = calculate_mac(algorithm, tsig_key, &signing_data);

    // Assemble final DNS message with TSIG RR
    let mut header_bytes = message.header.to_bytes().to_vec();
    let arcount = message.header.arcount + 1;
    header_bytes[10..12].copy_from_slice(&arcount.to_be_bytes());

    let mut signed_message = header_bytes;
    signed_message.extend_from_slice(&unsigned_bytes[12..]); // body (skip old header)

    // TSIG RR (RFC 2845 Section 3.2)
    signed_message.extend_from_slice(&encode_domain_name(tsig_key_name)); // NAME
    signed_message.extend_from_slice(&250u16.to_be_bytes()); // TYPE = 250 (TSIG)
    signed_message.extend_from_slice(&255u16.to_be_bytes()); // CLASS = ANY (255)
    signed_message.extend_from_slice(&0u32.to_be_bytes()); // TTL = 0

    // RDATA
    let mut rdata = Vec::new();
    rdata.extend_from_slice(&encode_domain_name(algorithm_name));
    rdata.extend_from_slice(&time_buf); // 48-bit time
    rdata.extend_from_slice(&fudge.to_be_bytes());
    rdata.extend_from_slice(&(mac.len() as u16).to_be_bytes());
    rdata.extend_from_slice(&mac);
    rdata.extend_from_slice(&original_id.to_be_bytes());
    rdata.extend_from_slice(&error.to_be_bytes());
    rdata.extend_from_slice(&other_len.to_be_bytes());

    // RDLENGTH + RDATA
    signed_message.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
    signed_message.extend_from_slice(&rdata);

    signed_message
}

fn calculate_mac(algorithm: &TsigAlg, key: &[u8], data: &[u8]) -> Vec<u8> {
    match algorithm {
        TsigAlg::MD5 => {
            let mut mac = Hmac::<Md5>::new_from_slice(key).expect("HMAC can take key of any size");
            mac.update(data);
            mac.finalize().into_bytes().to_vec()
        }
        TsigAlg::SHA1 => {
            let mut mac = Hmac::<Sha1>::new_from_slice(key).expect("HMAC can take key of any size");
            mac.update(data);
            mac.finalize().into_bytes().to_vec()
        }
        TsigAlg::SHA224 => {
            let mut mac =
                Hmac::<Sha224>::new_from_slice(key).expect("HMAC can take key of any size");
            mac.update(data);
            mac.finalize().into_bytes().to_vec()
        }
        TsigAlg::SHA256 => {
            let mut mac =
                Hmac::<Sha256>::new_from_slice(key).expect("HMAC can take key of any size");
            mac.update(data);
            mac.finalize().into_bytes().to_vec()
        }
        TsigAlg::SHA384 => {
            let mut mac =
                Hmac::<Sha384>::new_from_slice(key).expect("HMAC can take key of any size");
            mac.update(data);
            mac.finalize().into_bytes().to_vec()
        }
        TsigAlg::SHA512 => {
            let mut mac =
                Hmac::<Sha512>::new_from_slice(key).expect("HMAC can take key of any size");
            mac.update(data);
            mac.finalize().into_bytes().to_vec()
        }
    }
}

#[cfg(test)]
mod tests;
