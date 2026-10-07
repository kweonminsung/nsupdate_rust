use crate::EncodeError;

/// Accept ASCII and RFC 1035 escapes (`\X` and `\DDD`); IDNs must use Punycode.
pub(crate) fn encode_domain_name(name: &str) -> Result<Vec<u8>, EncodeError> {
    if name == "." {
        return Ok(vec![0]);
    }
    if name.is_empty() || !name.is_ascii() {
        return Err(invalid("Use a nonempty ASCII name (Punycode for IDNs)"));
    }
    let input = name.as_bytes();
    let mut wire = vec![0];
    let mut label_start = 0;
    let mut index = 0;
    while index < input.len() {
        let mut byte = input[index];
        index += 1;
        if byte == b'.' {
            if wire.len() == label_start + 1 {
                return Err(invalid("Empty labels are only allowed at the root"));
            }
            wire[label_start] = (wire.len() - label_start - 1) as u8;
            label_start = wire.len();
            wire.push(0);
        } else {
            if byte == b'\\' {
                byte = *input
                    .get(index)
                    .ok_or_else(|| invalid("Incomplete escape"))?;
                if byte.is_ascii_digit() {
                    let digits = input
                        .get(index..index + 3)
                        .filter(|digits| digits.iter().all(u8::is_ascii_digit))
                        .ok_or_else(|| invalid("Decimal escapes need exactly three digits"))?;
                    let value = u16::from(digits[0] - b'0') * 100
                        + u16::from(digits[1] - b'0') * 10
                        + u16::from(digits[2] - b'0');
                    byte =
                        u8::try_from(value).map_err(|_| invalid("Decimal escape exceeds 255"))?;
                    index += 3;
                } else {
                    index += 1;
                }
            } else if !byte.is_ascii_graphic() {
                return Err(invalid("Whitespace and control bytes must be escaped"));
            }
            let label_len = wire.len() - label_start;
            if label_len > 63 {
                return Err(EncodeError::LengthExceeded {
                    field: "DNS label",
                    length: label_len,
                    max: 63,
                });
            }
            wire.push(byte);
        }
        if wire.len() > 255 {
            return Err(EncodeError::LengthExceeded {
                field: "DNS name",
                length: wire.len(),
                max: 255,
            });
        }
    }
    if wire.len() != label_start + 1 {
        wire[label_start] = (wire.len() - label_start - 1) as u8;
        wire.push(0);
    }
    if wire.len() > 255 {
        return Err(EncodeError::LengthExceeded {
            field: "DNS name",
            length: wire.len(),
            max: 255,
        });
    }
    Ok(wire)
}

fn invalid(reason: &str) -> EncodeError {
    EncodeError::InvalidDomainName(reason.into())
}

/// Both arguments must be uncompressed names produced by `encode_domain_name`.
pub(super) fn is_in_zone(name: &[u8], zone: &[u8]) -> bool {
    let mut offset = 0;
    loop {
        if name[offset..].eq_ignore_ascii_case(zone) {
            return true;
        }
        if name[offset] == 0 {
            return false;
        }
        offset += usize::from(name[offset]) + 1;
    }
}
