use crate::NsUpdateError;
use crate::internal::{constants::TsigAlg, protocol::encode_domain_name};
use base64::{Engine, engine::general_purpose};
use std::fmt;

/// A validated TSIG key. Debug output omits the secret.
#[derive(Clone)]
pub struct TsigKey {
    pub(crate) algorithm: TsigAlg,
    pub(crate) name: String,
    pub(crate) secret: Vec<u8>,
}

impl TsigKey {
    pub fn new(algorithm: &str, name: &str, secret_b64: &str) -> Result<Self, NsUpdateError> {
        let secret = general_purpose::STANDARD.decode(secret_b64)?;
        encode_domain_name(name)?;
        Ok(Self {
            algorithm: TsigAlg::from_string(algorithm)?,
            name: name.to_string(),
            secret,
        })
    }
}

impl fmt::Debug for TsigKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TsigKey")
            .field("algorithm", &self.algorithm)
            .field("name", &self.name)
            .field("secret", &"[REDACTED]")
            .finish()
    }
}
