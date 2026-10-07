use crate::internal::protocol::encode_domain_name;
use crate::internal::{constants::TsigAlg, decoder, encoder::EncodedRequest};
use crate::{AuthError, EncodeError, NsUpdateError, UpdateResponse};
use hmac::{Hmac, Mac};
use md5::Md5;
use sha1::Sha1;
use sha2::{Sha224, Sha256, Sha384, Sha512};

pub(crate) fn unix_time() -> Result<u64, EncodeError> {
    let seconds = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| EncodeError::InvalidMessage("System clock precedes the UNIX epoch".into()))?
        .as_secs();
    if seconds >= 1 << 48 {
        return Err(EncodeError::InvalidMessage(
            "System clock exceeds the TSIG 48-bit range".into(),
        ));
    }
    Ok(seconds)
}

pub(crate) fn canonical_name(name: &str) -> Result<Vec<u8>, EncodeError> {
    let mut wire = encode_domain_name(name)?;
    wire.make_ascii_lowercase();
    Ok(wire)
}

// TSIG variables exclude MAC Size and Original ID (RFC 8945 4.3.3).
pub(crate) fn variables(
    key_name: &[u8],
    algorithm_name: &[u8],
    time: u64,
    fudge: u16,
    error: u16,
    other: &[u8],
) -> Vec<u8> {
    let mut data = key_name.to_ascii_lowercase();
    data.extend_from_slice(&255u16.to_be_bytes());
    data.extend_from_slice(&0u32.to_be_bytes());
    data.extend_from_slice(&algorithm_name.to_ascii_lowercase());
    data.extend_from_slice(&time.to_be_bytes()[2..]);
    data.extend_from_slice(&fudge.to_be_bytes());
    data.extend_from_slice(&error.to_be_bytes());
    // Parsed Other Data is bounded by its u16 length; outgoing data is empty.
    data.extend_from_slice(&(other.len() as u16).to_be_bytes());
    data.extend_from_slice(other);
    data
}

macro_rules! with_mac {
    ($algorithm:expr, $key:expr, $data:expr, $mac:ident, $operation:expr) => {{
        macro_rules! run {
            ($hash:ty) => {{
                let mut $mac =
                    Hmac::<$hash>::new_from_slice($key).expect("HMAC accepts any key size");
                $mac.update($data);
                $operation
            }};
        }
        match $algorithm {
            TsigAlg::MD5 => run!(Md5),
            TsigAlg::SHA1 => run!(Sha1),
            TsigAlg::SHA224 => run!(Sha224),
            TsigAlg::SHA256 => run!(Sha256),
            TsigAlg::SHA384 => run!(Sha384),
            TsigAlg::SHA512 => run!(Sha512),
        }
    }};
}

pub(crate) fn calculate_mac(algorithm: &TsigAlg, key: &[u8], data: &[u8]) -> Vec<u8> {
    with_mac!(
        algorithm,
        key,
        data,
        mac,
        mac.finalize().into_bytes().to_vec()
    )
}

fn verify_mac(
    algorithm: &TsigAlg,
    key: &[u8],
    data: &[u8],
    expected: &[u8],
) -> Result<(), AuthError> {
    // Require full-length response MACs to match the request strength.
    if expected.len() != algorithm.mac_length() {
        return Err(AuthError::InvalidMacLength);
    }
    with_mac!(
        algorithm,
        key,
        data,
        mac,
        mac.verify_slice(expected)
            .map_err(|_| AuthError::InvalidMac)
    )
}

pub(crate) fn verify_response(
    bytes: &[u8],
    request: &EncodedRequest,
    key_name: &str,
    algorithm: &TsigAlg,
    key: &[u8],
    now: u64,
) -> Result<UpdateResponse, NsUpdateError> {
    let parsed = decoder::decode(bytes)?;
    parsed.validate_request(request.id, &request.zone)?;
    let tsig = parsed.tsig.ok_or(AuthError::MissingTsig)?;
    let mut response = parsed.response;
    if tsig.original_id != request.id {
        return Err(AuthError::ResponseMismatch("message ID").into());
    }
    let request_mac = request
        .mac
        .as_deref()
        .ok_or(AuthError::ResponseMismatch("request is unsigned"))?;
    if !tsig
        .key_name
        .eq_ignore_ascii_case(&canonical_name(key_name)?)
    {
        return Err(AuthError::KeyMismatch.into());
    }
    if !tsig
        .algorithm
        .eq_ignore_ascii_case(&canonical_name(algorithm.to_name())?)
    {
        return Err(AuthError::AlgorithmMismatch.into());
    }

    let mut unsigned = bytes[..tsig.start].to_vec();
    unsigned[..2].copy_from_slice(&tsig.original_id.to_be_bytes());
    // TSIG in Additional guarantees arcount > 0.
    unsigned[10..12].copy_from_slice(&(response.header.arcount - 1).to_be_bytes());
    let mut data = (request_mac.len() as u16).to_be_bytes().to_vec();
    data.extend_from_slice(request_mac);
    data.extend_from_slice(&unsigned);
    data.extend_from_slice(&variables(
        &tsig.key_name,
        &tsig.algorithm,
        tsig.time_signed,
        tsig.fudge,
        tsig.error,
        tsig.other,
    ));
    verify_mac(algorithm, key, &data, tsig.mac)?;
    if now.abs_diff(tsig.time_signed) > u64::from(tsig.fudge) {
        return Err(AuthError::TimeOutsideWindow.into());
    }
    if tsig.error != 0 {
        let server_time = if tsig.error == 18 {
            Some(
                tsig.other
                    .iter()
                    .fold(0u64, |time, byte| (time << 8) | u64::from(*byte)),
            )
        } else {
            None
        };
        return Err(AuthError::ServerError {
            code: tsig.error,
            server_time,
        }
        .into());
    }
    if response.header.flags & 0x0200 != 0 {
        return Err(NsUpdateError::TruncatedResponse);
    }
    response.authenticated = true;
    Ok(response)
}

#[cfg(test)]
mod tests;
