use crate::internal::auth::{calculate_mac, canonical_name, unix_time, variables};
use crate::internal::constants::TsigAlg;
use crate::internal::protocol::{
    DnsUpdateMessage, check_message_length, checked_count, encode_domain_name,
};
use crate::{EncodeError, TsigKey};

pub(crate) struct EncodedRequest {
    pub bytes: Vec<u8>,
    pub mac: Option<Vec<u8>>,
    pub id: u16,
    pub zone: Vec<u8>,
}

pub(crate) fn encode(
    message: &DnsUpdateMessage,
    key: Option<&TsigKey>,
) -> Result<EncodedRequest, EncodeError> {
    match key {
        Some(key) => encode_at(
            message,
            &key.name,
            &key.algorithm,
            &key.secret,
            unix_time()?,
        ),
        None => Ok(EncodedRequest {
            bytes: message.to_bytes()?,
            mac: None,
            id: message.header.id,
            zone: encode_domain_name(&message.zone.zname)?,
        }),
    }
}

pub(crate) fn encode_at(
    message: &DnsUpdateMessage,
    key_name: &str,
    algorithm: &TsigAlg,
    key: &[u8],
    time: u64,
) -> Result<EncodedRequest, EncodeError> {
    if time >= 1 << 48 {
        return Err(EncodeError::InvalidMessage(
            "TSIG time exceeds the 48-bit range".into(),
        ));
    }
    let unsigned = message.to_bytes()?;
    let key_name = canonical_name(key_name)?;
    let algorithm_name = canonical_name(algorithm.to_name())?;
    let arcount = checked_count(
        "Additional count including TSIG",
        usize::from(message.header.arcount) + 1,
    )?;
    let fudge: u16 = 300;

    // Only responses include the request MAC prefix (RFC 8945 4.3.1).
    let mut data = unsigned.clone();
    data.extend_from_slice(&variables(&key_name, &algorithm_name, time, fudge, 0, &[]));
    let mac = calculate_mac(algorithm, key, &data);

    let mut rdata = algorithm_name;
    rdata.extend_from_slice(&time.to_be_bytes()[2..]);
    rdata.extend_from_slice(&fudge.to_be_bytes());
    rdata.extend_from_slice(&checked_count("TSIG MAC", mac.len())?.to_be_bytes());
    rdata.extend_from_slice(&mac);
    rdata.extend_from_slice(&message.header.id.to_be_bytes());
    rdata.extend_from_slice(&0u16.to_be_bytes()); // Error
    rdata.extend_from_slice(&0u16.to_be_bytes()); // Other Len

    check_message_length(unsigned.len() + key_name.len() + 10 + rdata.len())?;
    let mut bytes = unsigned;
    bytes[10..12].copy_from_slice(&arcount.to_be_bytes());
    bytes.extend_from_slice(&key_name);
    bytes.extend_from_slice(&250u16.to_be_bytes());
    bytes.extend_from_slice(&255u16.to_be_bytes());
    bytes.extend_from_slice(&0u32.to_be_bytes());
    bytes.extend_from_slice(&checked_count("TSIG RDATA", rdata.len())?.to_be_bytes());
    bytes.extend_from_slice(&rdata);
    Ok(EncodedRequest {
        bytes,
        mac: Some(mac),
        id: message.header.id,
        zone: encode_domain_name(&message.zone.zname)?,
    })
}

#[cfg(test)]
mod tests;
