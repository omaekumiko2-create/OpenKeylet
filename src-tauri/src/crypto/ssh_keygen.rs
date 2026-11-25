//! Local Ed25519 SSH keypair generation (OpenSSH PEM + authorized_keys + SHA-256 fingerprint).

use anyhow::Result;
use russh::keys::ssh_key::{
    HashAlg, LineEnding, PrivateKey,
    private::{Ed25519Keypair, KeypairData},
};
use zeroize::Zeroizing;

#[derive(Debug, Clone)]
pub struct GeneratedSshKeypair {
    pub private_key_pem: Zeroizing<String>,
    pub public_key: String,
    pub fingerprint: String,
}

pub fn generate_ed25519_keypair(comment: &str) -> Result<GeneratedSshKeypair> {
    let mut seed = Zeroizing::new([0u8; 32]);
    getrandom::fill(&mut *seed)
        .map_err(|error| anyhow::anyhow!("Random generator unavailable: {error}"))?;
    let clean_comment: String = comment
        .trim()
        .chars()
        .filter(|c| !c.is_control())
        .take(96)
        .collect();
    let comment_str = if clean_comment.is_empty() {
        "openkeylet"
    } else {
        clean_comment.as_str()
    };
    let keypair = Ed25519Keypair::from_seed(&seed);
    let private_key = PrivateKey::new(KeypairData::Ed25519(keypair), comment_str)
        .map_err(|error| anyhow::anyhow!("Unable to build Ed25519 private key: {error}"))?;
    let pem = private_key
        .to_openssh(LineEnding::LF)
        .map_err(|error| anyhow::anyhow!("Unable to encode OpenSSH private key: {error}"))?;
    let public_key = private_key
        .public_key()
        .to_openssh()
        .map_err(|error| anyhow::anyhow!("Unable to encode OpenSSH public key: {error}"))?;
    let fingerprint = private_key.fingerprint(HashAlg::Sha256).to_string();
    Ok(GeneratedSshKeypair {
        private_key_pem: Zeroizing::new(pem.to_string()),
        public_key,
        fingerprint,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_valid_openssh_ed25519_keypair() {
        let kp = generate_ed25519_keypair("deploy@openkeylet").unwrap();
        assert!(kp.private_key_pem.contains("BEGIN OPENSSH PRIVATE KEY"));
        assert!(kp.public_key.starts_with("ssh-ed25519 "));
        assert!(kp.public_key.ends_with("deploy@openkeylet"));
        assert!(kp.fingerprint.starts_with("SHA256:"));
        let decoded = russh::keys::decode_secret_key(&kp.private_key_pem, None).unwrap();
        assert_eq!(
            decoded.fingerprint(HashAlg::Sha256).to_string(),
            kp.fingerprint
        );
    }
}
