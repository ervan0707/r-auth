use hmac::{Hmac, Mac};
use sha1::Sha1;
use std::time::{SystemTime, UNIX_EPOCH};
use url::Url;

use crate::error::{AuthError, Result};

type HmacSha1 = Hmac<Sha1>;

/// TOTP implementation based on:
/// - [RFC 6238 - TOTP: Time-Based One-Time Password Algorithm](https://datatracker.ietf.org/doc/html/rfc6238)
/// - [RFC 4226 - HOTP: An HMAC-Based One-Time Password Algorithm](https://datatracker.ietf.org/doc/html/rfc4226)
pub struct TOTP {
    secret: Vec<u8>,
    digits: u32,
    interval: u64,
}

impl TOTP {
    /// Creates a new TOTP instance with the given secret
    /// Secret is decoded using Base32 as specified in [RFC 4648](https://datatracker.ietf.org/doc/html/rfc4648#section-6)
    pub fn new(secret: &str) -> Result<Self> {
        let secret = base32::decode(base32::Alphabet::RFC4648 { padding: true }, secret)
            .ok_or(AuthError::Base32DecodeError)?;

        Ok(Self {
            secret,
            digits: 6,
            interval: 30,
        })
    }

    /// Generates current TOTP code based on current Unix timestamp
    /// As specified in [RFC 6238 Section 4](https://datatracker.ietf.org/doc/html/rfc6238#section-4)
    pub fn now(&self) -> Result<String> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| AuthError::InvalidSecret(e.to_string()))?
            .as_secs();
        self.generate(timestamp)
    }

    /// Generates TOTP code for a given timestamp
    /// Implementation follows [RFC 6238 Section 4.2](https://datatracker.ietf.org/doc/html/rfc6238#section-4.2)
    fn generate(&self, timestamp: u64) -> Result<String> {
        // HMAC-SHA1 is used as specified in RFC 6238
        let counter = timestamp / self.interval;
        let counter_bytes = counter.to_be_bytes();

        let mut mac = HmacSha1::new_from_slice(&self.secret)
            .map_err(|e| AuthError::InvalidSecret(e.to_string()))?;
        mac.update(&counter_bytes);
        let result = mac.finalize();
        let code_bytes = result.into_bytes();

        // Dynamic truncation as specified in RFC 4226 Section 5.4
        let offset = (code_bytes[19] & 0xf) as usize;
        let code = ((code_bytes[offset] & 0x7f) as u32) << 24
            | (code_bytes[offset + 1] as u32) << 16
            | (code_bytes[offset + 2] as u32) << 8
            | (code_bytes[offset + 3] as u32);

        let code = code % 10u32.pow(self.digits);
        Ok(format!("{:0width$}", code, width = self.digits as usize))
    }

    /// Generates an otpauth URI for QR code generation
    /// Format follows Google Authenticator's KeyUriFormat:
    /// https://github.com/google/google-authenticator/wiki/Key-Uri-Format
    pub fn provisioning_uri(&self, name: &str, issuer: &str) -> String {
        // Base32 encoding as specified in RFC 4648
        let secret = base32::encode(base32::Alphabet::RFC4648 { padding: true }, &self.secret);

        let mut url = Url::parse("otpauth://totp/").unwrap();
        url.set_path(&format!("{}", name));

        {
            let mut pairs = url.query_pairs_mut();
            pairs.append_pair("secret", &secret);
            pairs.append_pair("digits", &self.digits.to_string());
            pairs.append_pair("period", &self.interval.to_string());
            pairs.append_pair("issuer", issuer);
        }

        url.to_string()
    }
}
