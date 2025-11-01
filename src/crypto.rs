use aes::cipher::{block_padding::Pkcs7, BlockEncryptMut, KeyIvInit};
use log::trace;
use num_bigint_dig::BigUint;
use rand::random;
use rsa::{Oaep, RsaPublicKey};
use sha1::Sha1;

type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;

pub enum Crypto {
    Clear,
    AES { key: [u8; 16], iv: [u8; 16] },
}

impl Crypto {
    pub fn new(encrypt: bool) -> Crypto {
        if encrypt {
            Crypto::AES { key: random(), iv: random() }
        } else {
            Crypto::Clear
        }
    }

    pub fn is_clear(&self) -> bool {
        matches!(self, Crypto::Clear)
    }

    pub fn sdp(&self) -> String {
        match self {
            Crypto::Clear => String::from(""),
            Crypto::AES { key, iv } => {
                let modules = BigUint::from_bytes_be(&base64::decode("59dE8qLieItsH1WgjrcFRKj6eUWqi+bGLOX1HL3U3GhC/j0Qg90u3sG/1CUtwC5vOYvfDmFI6oSFXi5ELabWJmT2dKHzBJKa3k9ok+8t9ucRqMd6DZHJ2YCCLlDRKSKv6kDqnw4UwPdpOMXziC/AMj3Z/lUVX1G7WSHCAWKf1zNS1eLvqr+boEjXuBOitnZ/bDzPHrTOZz0Dew0uowxf/+sG+NCK3eQJVxqcaJ/vEHKIVd2M+5qL71yJQ+87X6oV3eaYvt3zWZYD6z5vYTcrtij2VZ9Zmni/UAaHqn9JdsBWLUEpVviYnhimNVvYFZeCXg/IdTQ+x4IRdiXNv5hEew==").unwrap());
                let exponent = BigUint::from_bytes_be(&base64::decode("AQAB").unwrap());

                let rsa = RsaPublicKey::new(modules, exponent).unwrap();
                let rsakey = rsa.encrypt(&mut rand::thread_rng(), Oaep::new::<Sha1>(), key).unwrap();

                let rsakey = base64::encode_config(&rsakey, base64::STANDARD_NO_PAD);
                let iv = base64::encode_config(iv, base64::STANDARD_NO_PAD);

                format!("a=rsaaeskey:{}\r\na=aesiv:{}\r\n", rsakey, iv)
            },
        }
    }

    pub fn encrypt(&self, data: Vec<u8>) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        match self {
            Crypto::Clear => Ok(data),
            Crypto::AES { key, iv } => {
                trace!("Encrypting {} bytes using AES 128-bit CBC", data.len());
                Ok(Aes128CbcEnc::new(key.into(), iv.into()).encrypt_padded_vec_mut::<Pkcs7>(&data))
            },
        }
    }
}
