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
    pub(crate) fn from_string(alg: &str) -> Option<Self> {
        match alg {
            "md5" => Some(TsigAlg::MD5),
            "hmac-md5" => Some(TsigAlg::MD5),
            "sha1" => Some(TsigAlg::SHA1),
            "hmac-sha1" => Some(TsigAlg::SHA1),
            "sha224" => Some(TsigAlg::SHA224),
            "hmac-sha224" => Some(TsigAlg::SHA224),
            "sha256" => Some(TsigAlg::SHA256),
            "hmac-sha256" => Some(TsigAlg::SHA256),
            "sha384" => Some(TsigAlg::SHA384),
            "hmac-sha384" => Some(TsigAlg::SHA384),
            "sha512" => Some(TsigAlg::SHA512),
            "hmac-sha512" => Some(TsigAlg::SHA512),
            _ => None,
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
