use crate::ParseError;

pub(super) struct Reader<'a> {
    bytes: &'a [u8],
    position: usize,
    end: usize,
}

impl<'a> Reader<'a> {
    pub(super) fn new(bytes: &'a [u8], position: usize, end: usize) -> Self {
        Self {
            bytes,
            position,
            end,
        }
    }

    pub(super) fn position(&self) -> usize {
        self.position
    }

    pub(super) fn take(&mut self, length: usize) -> Result<&'a [u8], ParseError> {
        let end = self
            .position
            .checked_add(length)
            .filter(|end| *end <= self.end)
            .ok_or(ParseError::Incomplete)?;
        let value = self
            .bytes
            .get(self.position..end)
            .ok_or(ParseError::Incomplete)?;
        self.position = end;
        Ok(value)
    }

    pub(super) fn u16(&mut self) -> Result<u16, ParseError> {
        let bytes = self.take(2)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    pub(super) fn u32(&mut self) -> Result<u32, ParseError> {
        let bytes = self.take(4)?;
        Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    pub(super) fn u48(&mut self) -> Result<u64, ParseError> {
        let bytes = self.take(6)?;
        Ok(u64::from_be_bytes([
            0, 0, bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5],
        ]))
    }

    pub(super) fn finish(&self) -> Result<(), ParseError> {
        if self.position != self.end {
            return Err(ParseError::InvalidMessage(
                "Trailing bytes after declared fields",
            ));
        }
        Ok(())
    }

    pub(super) fn name(&mut self, allow_compression: bool) -> Result<Vec<u8>, ParseError> {
        let mut position = self.position;
        let mut limit = self.end;
        let mut next = None;
        let mut pointer_ceiling = position;
        let mut jumps = 0;
        let mut wire = Vec::new();
        loop {
            let first = *self
                .bytes
                .get(position)
                .filter(|_| position < limit)
                .ok_or(ParseError::Incomplete)?;
            match first & 0xc0 {
                0 => {
                    let length = usize::from(first);
                    let end = position + 1 + length;
                    if end > limit {
                        return Err(ParseError::Incomplete);
                    }
                    let label = self
                        .bytes
                        .get(position..end)
                        .ok_or(ParseError::Incomplete)?;
                    if wire.len() + label.len() > 255 {
                        return Err(ParseError::InvalidDomainName);
                    }
                    wire.extend_from_slice(label);
                    position = end;
                    if length == 0 {
                        self.position = next.unwrap_or(position);
                        return Ok(wire);
                    }
                }
                0xc0 if allow_compression => {
                    let second = *self
                        .bytes
                        .get(position + 1)
                        .filter(|_| position + 1 < limit)
                        .ok_or(ParseError::Incomplete)?;
                    let target = ((usize::from(first) & 0x3f) << 8) | usize::from(second);
                    // Bounded, decreasing pointer targets prevent cycles.
                    if target < 12 || target >= pointer_ceiling || jumps >= 128 {
                        return Err(ParseError::InvalidDomainName);
                    }
                    next.get_or_insert(position + 2);
                    pointer_ceiling = target;
                    position = target;
                    limit = self.bytes.len();
                    jumps += 1;
                }
                _ => return Err(ParseError::InvalidDomainName),
            }
        }
    }
}

pub(super) fn display_name(wire: &[u8]) -> String {
    if wire == [0] {
        return ".".into();
    }
    let mut name = String::new();
    let mut position = 0;
    while wire[position] != 0 {
        let length = usize::from(wire[position]);
        for byte in &wire[position + 1..position + 1 + length] {
            if *byte == b'.' || *byte == b'\\' {
                name.push('\\');
                name.push(char::from(*byte));
            } else if byte.is_ascii_graphic() {
                name.push(char::from(*byte));
            } else {
                name.push('\\');
                name.push_str(&format!("{byte:03}"));
            }
        }
        name.push('.');
        position += 1 + length;
    }
    name
}
