//! RFC 6238 TOTP (Time-based One-Time Password) generator & Base32 decoder.

use anyhow::{Context, Result, bail};
use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::Sha256;
use std::time::{SystemTime, UNIX_EPOCH};

pub fn current_totp(secret: &str) -> Result<String> {
    let (code, _, _) = current_totp_details(secret)?;
    Ok(code)
}

pub fn current_totp_details(secret: &str) -> Result<(String, u64, u64)> {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("Invalid system time")?
        .as_secs();
    totp_details_at(secret, timestamp)
}

#[cfg(test)]
pub(crate) fn totp_at(secret: &str, timestamp: u64) -> Result<String> {
    let (code, _, _) = totp_details_at(secret, timestamp)?;
    Ok(code)
}

fn totp_details_at(secret: &str, timestamp: u64) -> Result<(String, u64, u64)> {
    let mut seed = secret.trim().to_owned();
    let (mut digits, mut period, mut algorithm) = (6usize, 30u64, "SHA1".to_owned());
    if seed.starts_with("otpauth://") {
        let uri = url::Url::parse(&seed).context("Invalid TOTP URI")?;
        if uri.host_str() != Some("totp") {
            bail!("Only time-based TOTP URIs are supported");
        }
        let pairs: Vec<_> = uri.query_pairs().collect();
        for name in ["secret", "digits", "period", "algorithm"] {
            if pairs.iter().filter(|(key, _)| key == name).count() > 1 {
                bail!("Duplicate TOTP parameter");
            }
        }
        let get = |name| {
            pairs
                .iter()
                .find(|(key, _)| key == name)
                .map(|(_, value)| value.as_ref())
        };
        digits = get("digits")
            .unwrap_or("6")
            .parse()
            .context("Invalid TOTP digits")?;
        period = get("period")
            .unwrap_or("30")
            .parse()
            .context("Invalid TOTP period")?;
        algorithm = get("algorithm").unwrap_or("SHA1").to_ascii_uppercase();
        seed = get("secret").context("Missing TOTP secret")?.to_owned();
    }
    if !(6..=8).contains(&digits) || !(1..=300).contains(&period) {
        bail!("Invalid TOTP digits or period");
    }
    let key = zeroize::Zeroizing::new(decode_base32(&seed)?);
    let counter = timestamp / period;
    macro_rules! digest {
        ($hash:ty) => {{
            let mut mac = Hmac::<$hash>::new_from_slice(&key).context("Invalid TOTP key")?;
            mac.update(&counter.to_be_bytes());
            mac.finalize().into_bytes().to_vec()
        }};
    }
    let digest = match algorithm.as_str() {
        "SHA1" => digest!(Sha1),
        "SHA256" => digest!(Sha256),
        "SHA512" => digest!(sha2::Sha512),
        _ => bail!("Unsupported TOTP algorithm"),
    };
    let offset = (digest[digest.len() - 1] & 0x0f) as usize;
    let value = ((u32::from(digest[offset]) & 0x7f) << 24)
        | (u32::from(digest[offset + 1]) << 16)
        | (u32::from(digest[offset + 2]) << 8)
        | u32::from(digest[offset + 3]);
    let code = format!("{:0digits$}", value % 10u32.pow(digits as u32));
    let remaining = period - (timestamp % period);
    Ok((code, remaining, period))
}

fn decode_base32(value: &str) -> Result<Vec<u8>> {
    let mut buffer = 0_u32;
    let mut bits = 0_u8;
    let mut output = Vec::new();
    for character in value
        .chars()
        .filter(|character| !character.is_whitespace() && *character != '-')
    {
        if character == '=' {
            break;
        }
        let character = character.to_ascii_uppercase();
        let number = match character {
            'A'..='Z' => character as u8 - b'A',
            '2'..='7' => character as u8 - b'2' + 26,
            _ => bail!("TOTP Secret must be Base32"),
        };
        buffer = (buffer << 5) | u32::from(number);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            output.push((buffer >> bits) as u8);
            buffer &= (1_u32 << bits).saturating_sub(1);
        }
    }
    if output.is_empty() {
        bail!("TOTP Secret cannot be empty");
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn otpauth_uses_rfc6238_algorithms_digits_and_period() {
        let base32 = |bytes: &[u8]| {
            let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
            let (mut buffer, mut bits, mut result) = (0u32, 0u32, String::new());
            for byte in bytes {
                buffer = (buffer << 8) | u32::from(*byte);
                bits += 8;
                while bits >= 5 {
                    bits -= 5;
                    result.push(alphabet[((buffer >> bits) & 31) as usize] as char);
                }
                buffer &= (1 << bits) - 1;
            }
            if bits > 0 {
                result.push(alphabet[((buffer << (5 - bits)) & 31) as usize] as char);
            }
            result
        };
        for (algorithm, seed, expected) in [
            ("SHA1", "12345678901234567890", "94287082"),
            ("SHA256", "12345678901234567890123456789012", "46119246"),
            (
                "SHA512",
                "1234567890123456789012345678901234567890123456789012345678901234",
                "90693936",
            ),
        ] {
            let uri = format!(
                "otpauth://totp/Example?secret={}&algorithm={algorithm}&digits=8&period=30",
                base32(seed.as_bytes())
            );
            assert_eq!(totp_at(&uri, 59).unwrap(), expected);
            assert_eq!(
                totp_at(&uri.replace("period=30", "period=60"), 119).unwrap(),
                expected
            );
        }
        assert!(current_totp("otpauth://totp/test?secret=JBSWY3DPEHPK3PXP&period=0").is_err());
        assert!(current_totp("otpauth://totp/test?secret=JBSWY3DPEHPK3PXP&digits=99").is_err());
    }

    #[test]
    fn totp_matches_rfc_vector_truncated_to_six_digits() {
        assert_eq!(
            totp_at("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", 59).unwrap(),
            "287082"
        );
    }
}
