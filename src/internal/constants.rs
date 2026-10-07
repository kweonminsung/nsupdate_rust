use crate::NsUpdateError;

#[derive(Debug, PartialEq, Clone)]
pub(crate) enum TsigAlg {
    MD5,
    SHA1,
    SHA224,
    SHA256,
    SHA384,
    SHA512,
}

impl TsigAlg {
    pub(crate) fn from_string(alg: &str) -> Result<Self, NsUpdateError> {
        match alg {
            "md5" | "hmac-md5" => Ok(TsigAlg::MD5),
            "sha1" | "hmac-sha1" => Ok(TsigAlg::SHA1),
            "sha224" | "hmac-sha224" => Ok(TsigAlg::SHA224),
            "sha256" | "hmac-sha256" => Ok(TsigAlg::SHA256),
            "sha384" | "hmac-sha384" => Ok(TsigAlg::SHA384),
            "sha512" | "hmac-sha512" => Ok(TsigAlg::SHA512),
            _ => Err(NsUpdateError::InvalidAlgorithm(alg.to_string())),
        }
    }

    pub(crate) fn mac_length(&self) -> usize {
        match self {
            Self::MD5 => 16,
            Self::SHA1 => 20,
            Self::SHA224 => 28,
            Self::SHA256 => 32,
            Self::SHA384 => 48,
            Self::SHA512 => 64,
        }
    }

    pub(crate) fn to_name(&self) -> &'static str {
        match self {
            TsigAlg::MD5 => "hmac-md5.sig-alg.reg.int",
            TsigAlg::SHA1 => "hmac-sha1",
            TsigAlg::SHA224 => "hmac-sha224",
            TsigAlg::SHA256 => "hmac-sha256",
            TsigAlg::SHA384 => "hmac-sha384",
            TsigAlg::SHA512 => "hmac-sha512",
        }
    }
}
