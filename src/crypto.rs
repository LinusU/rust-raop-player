use base64;
use openssl::bn::BigNum;
use openssl::rsa::{Rsa, Padding};
use openssl::symm::{encrypt, Cipher};
use rand::random;
use log::trace;

pub enum Crypto {
    Clear(),
    AES { key: [u8; 16], iv: [u8; 16] },
}

impl Crypto {
    pub fn new(encrypt: bool) -> Crypto {
        if encrypt {
            Crypto::AES { key: random(), iv: random() }
        } else {
            Crypto::Clear()
        }
    }

    pub fn is_clear(&self) -> bool {
        match self {
            Crypto::Clear() => true,
            _ => false,
        }
    }

    pub fn sdp(&self) -> String {
        match self {
            Crypto::Clear() => String::from(""),
            Crypto::AES { key, iv } => {
                let modules = BigNum::from_slice(&base64::decode("59dE8qLieItsH1WgjrcFRKj6eUWqi+bGLOX1HL3U3GhC/j0Qg90u3sG/1CUtwC5vOYvfDmFI6oSFXi5ELabWJmT2dKHzBJKa3k9ok+8t9ucRqMd6DZHJ2YCCLlDRKSKv6kDqnw4UwPdpOMXziC/AMj3Z/lUVX1G7WSHCAWKf1zNS1eLvqr+boEjXuBOitnZ/bDzPHrTOZz0Dew0uowxf/+sG+NCK3eQJVxqcaJ/vEHKIVd2M+5qL71yJQ+87X6oV3eaYvt3zWZYD6z5vYTcrtij2VZ9Zmni/UAaHqn9JdsBWLUEpVviYnhimNVvYFZeCXg/IdTQ+x4IRdiXNv5hEew==").unwrap()).unwrap();
                let exponent = BigNum::from_slice(&base64::decode("AQAB").unwrap()).unwrap();

                let rsa = Rsa::from_public_components(modules, exponent).unwrap();
                let mut rsakey = [0u8; 512];
                let rsakey_size = rsa.public_encrypt(key, &mut rsakey, Padding::PKCS1_OAEP).unwrap();

                let rsakey = base64::encode_config(&rsakey[0..rsakey_size], base64::STANDARD_NO_PAD);
                let iv = base64::encode_config(iv, base64::STANDARD_NO_PAD);

                format!("a=rsaaeskey:{}\r\na=aesiv:{}\r\n", rsakey, iv)
            },
        }
    }

    pub fn encrypt(&self, data: Vec<u8>) -> Result<Vec<u8>, Box<std::error::Error>> {
        match self {
            Crypto::Clear() => Ok(data),
            Crypto::AES { key, iv } => {
                trace!("Encrypting {} bytes using AES 128-bit CBC", data.len());
                Ok(encrypt(Cipher::aes_128_cbc(), key, Some(iv), &data)?)
            },
        }
    }
}
