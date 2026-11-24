//! Software WebAuthn authenticator. Private keys are only serialized inside the vault envelope.
use anyhow::{Context, Result, bail, ensure};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use ciborium::value::Value as Cbor;
use p256::{
    ecdsa::{Signature, SigningKey, signature::Signer},
    pkcs8::EncodePublicKey,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use url::Url;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(rename_all = "camelCase")]
pub struct StoredPasskey {
    #[serde(default)]
    pub counter: u32,
    pub credential_id: String,
    pub rp_id: String,
    pub user_handle: String,
    pub user_name: String,
    pub display_name: String,
    pub private_key: String,
    pub discoverable: bool,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct PasskeySummary {
    pub credential_id: String,
    pub rp_id: String,
    pub user_name: String,
    pub display_name: String,
    pub created_at: String,
}

impl StoredPasskey {
    pub fn summary(&self) -> PasskeySummary {
        PasskeySummary {
            credential_id: self.credential_id.clone(),
            rp_id: self.rp_id.clone(),
            user_name: self.user_name.clone(),
            display_name: self.display_name.clone(),
            created_at: self.created_at.clone(),
        }
    }
}

pub fn origin(value: &str) -> Result<Url> {
    let url = Url::parse(value).context("Invalid website address")?;
    ensure!(
        matches!(url.scheme(), "http" | "https")
            && url.host_str().is_some()
            && url.username().is_empty()
            && url.password().is_none(),
        "Invalid website address"
    );
    Ok(url)
}

pub fn rp_id(origin_text: &str, options: &Value, create: bool) -> Result<String> {
    let url = origin(origin_text)?;
    let host = url.host_str().context("Missing website host")?;
    ensure!(
        url.scheme() == "https" || host == "localhost",
        "Passkeys require HTTPS (or localhost)"
    );
    let rp = if create {
        options.pointer("/rp/id")
    } else {
        options.get("rpId")
    };
    let rp = match rp {
        Some(v) => v.as_str().context("Invalid relying party ID")?,
        None => host,
    };
    ensure!(
        !rp.is_empty()
            && !rp.ends_with('.')
            && rp == rp.to_ascii_lowercase()
            && (rp == host || host.ends_with(&format!(".{rp}"))),
        "The passkey domain does not match this website"
    );
    ensure!(
        rp == "localhost"
            || (rp.parse::<std::net::IpAddr>().is_err() && psl::domain_str(rp).is_some()),
        "A passkey cannot be registered for a public suffix or IP address"
    );
    let challenge = decode(
        options
            .get("challenge")
            .and_then(Value::as_str)
            .context("Missing challenge")?,
    )?;
    ensure!(
        !challenge.is_empty() && challenge.len() <= 4096,
        "Invalid challenge size"
    );
    if create {
        ensure!(
            options
                .get("pubKeyCredParams")
                .and_then(Value::as_array)
                .is_some_and(|a| a.is_empty()
                    || a.iter()
                        .any(|v| v["type"] == "public-key" && v["alg"] == -7)),
            "This website does not support ES256 passkeys"
        );
        let user = decode(
            options
                .pointer("/user/id")
                .and_then(Value::as_str)
                .context("Missing user handle")?,
        )?;
        ensure!(
            !user.is_empty() && user.len() <= 64,
            "Invalid user handle size"
        );
        ensure!(
            options
                .pointer("/user/name")
                .and_then(Value::as_str)
                .is_some(),
            "Missing account name"
        );
        ensure!(
            options
                .pointer("/authenticatorSelection/authenticatorAttachment")
                .and_then(Value::as_str)
                != Some("cross-platform"),
            "Use a device or security key for this request"
        );
        ensure!(
            options["attestation"] != "enterprise",
            "Enterprise attestation is not supported"
        );
        ensure!(
            options
                .pointer("/extensions/largeBlob/support")
                .and_then(Value::as_str)
                != Some("required"),
            "Required large blobs are not supported"
        );
    }
    Ok(rp.to_owned())
}

pub fn decode(value: &str) -> Result<Vec<u8>> {
    B64.decode(value).context("Invalid base64url data")
}

fn client_data(origin_text: &str, options: &Value, create: bool) -> Result<Vec<u8>> {
    let challenge = B64.encode(decode(
        options["challenge"].as_str().context("Missing challenge")?,
    )?);
    Ok(serde_json::to_vec(
        &json!({"type": if create { "webauthn.create" } else { "webauthn.get" },
        "challenge": challenge, "origin": origin(origin_text)?.origin().ascii_serialization(), "crossOrigin": false}),
    )?)
}

fn auth_data(rp: &str, verified: bool, registration: bool) -> Vec<u8> {
    let mut bytes = Sha256::digest(rp.as_bytes()).to_vec();
    // UP, BE; UV only after PIN verification. BS remains false. Portable credentials use a zero counter.
    bytes.push(0x01 | 0x08 | if verified { 0x04 } else { 0 } | if registration { 0x40 } else { 0 });
    bytes.extend_from_slice(&0u32.to_be_bytes());
    bytes
}

fn cbor(value: Cbor) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(&value, &mut bytes)?;
    Ok(bytes)
}

pub fn requires_verification(options: &Value, create: bool) -> bool {
    (if create {
        options.pointer("/authenticatorSelection/userVerification")
    } else {
        options.get("userVerification")
    })
    .and_then(Value::as_str)
        == Some("required")
}

pub fn create(
    origin_text: &str,
    options: &Value,
    verified: bool,
) -> Result<(StoredPasskey, Value)> {
    let rp = rp_id(origin_text, options, true)?;
    ensure!(
        verified || !requires_verification(options, true),
        "Set a PIN in OpenKeylet to verify this passkey request"
    );
    let key = loop {
        let mut bytes = Zeroizing::new([0u8; 32]);
        getrandom::fill(bytes.as_mut())
            .map_err(|e| anyhow::anyhow!("Random generation failed: {e}"))?;
        if let Ok(key) = SigningKey::from_slice(bytes.as_ref()) {
            break key;
        }
    };
    let mut id = [0u8; 32];
    getrandom::fill(&mut id).map_err(|e| anyhow::anyhow!("Random generation failed: {e}"))?;
    let point = key.verifying_key().to_encoded_point(false);
    let public_key = cbor(Cbor::Map(vec![
        (1.into(), 2.into()),
        (3.into(), (-7).into()),
        ((-1).into(), 1.into()),
        ((-2).into(), Cbor::Bytes(point.x().unwrap().to_vec())),
        ((-3).into(), Cbor::Bytes(point.y().unwrap().to_vec())),
    ]))?;
    let mut auth = auth_data(&rp, verified, true);
    auth.extend_from_slice(&[0u8; 16]); // No attestation identity.
    auth.extend_from_slice(&(id.len() as u16).to_be_bytes());
    auth.extend_from_slice(&id);
    auth.extend(public_key);
    let attestation = cbor(Cbor::Map(vec![
        ("fmt".into(), "none".into()),
        ("attStmt".into(), Cbor::Map(vec![])),
        ("authData".into(), Cbor::Bytes(auth.clone())),
    ]))?;
    let resident = options
        .pointer("/authenticatorSelection/residentKey")
        .and_then(Value::as_str);
    let legacy_rk = options
        .pointer("/authenticatorSelection/requireResidentKey")
        .and_then(Value::as_bool);
    let discoverable = match resident {
        Some("discouraged") => false,
        Some("required" | "preferred") => true,
        _ => legacy_rk.unwrap_or(true),
    };
    let stored = StoredPasskey {
        counter: 0,
        credential_id: B64.encode(id),
        rp_id: rp,
        user_handle: options["user"]["id"].as_str().unwrap().to_owned(),
        user_name: options["user"]["name"].as_str().unwrap().to_owned(),
        display_name: options["user"]["displayName"]
            .as_str()
            .unwrap_or_default()
            .to_owned(),
        private_key: B64.encode(key.to_bytes()),
        discoverable,
        created_at: chrono::Utc::now().to_rfc3339(),
    };
    let mut extensions = json!({});
    if options.pointer("/extensions/credProps") == Some(&Value::Bool(true)) {
        extensions["credProps"] = json!({"rk": discoverable});
    }
    let result = json!({"id": stored.credential_id, "rawId": stored.credential_id, "type": "public-key", "authenticatorAttachment": "platform",
        "response": {"clientDataJSON": B64.encode(client_data(origin_text, options, true)?), "attestationObject": B64.encode(attestation),
            "authenticatorData": B64.encode(auth), "publicKey": B64.encode(key.verifying_key().to_public_key_der()?.as_bytes()), "publicKeyAlgorithm": -7,
            "transports": ["internal"]}, "clientExtensionResults": extensions});
    Ok((stored, result))
}

pub fn matches_request(key: &StoredPasskey, rp: &str, options: &Value) -> bool {
    if key.rp_id != rp {
        return false;
    }
    match options["allowCredentials"]
        .as_array()
        .filter(|a| !a.is_empty())
    {
        Some(allow) => allow
            .iter()
            .any(|v| v["type"] == "public-key" && v["id"] == key.credential_id),
        None => key.discoverable,
    }
}

pub fn get(
    key: &StoredPasskey,
    origin_text: &str,
    options: &Value,
    verified: bool,
) -> Result<Value> {
    let rp = rp_id(origin_text, options, false)?;
    ensure!(
        matches_request(key, &rp, options),
        "This passkey does not match the website request"
    );
    if requires_verification(options, false) && !verified {
        bail!("Set a PIN in OpenKeylet to verify this passkey request");
    }
    let private = Zeroizing::new(decode(&key.private_key)?);
    let signing = SigningKey::from_slice(&private).context("Invalid stored passkey")?;
    let client = client_data(origin_text, options, false)?;
    let mut auth = auth_data(&rp, verified, false);
    auth[33..37].copy_from_slice(&key.counter.to_be_bytes());
    let mut signed = auth.clone();
    signed.extend_from_slice(&Sha256::digest(&client));
    let signature: Signature = signing.sign(&signed);
    Ok(
        json!({"id": key.credential_id, "rawId": key.credential_id, "type": "public-key", "authenticatorAttachment": "platform",
        "response": {"clientDataJSON": B64.encode(client), "authenticatorData": B64.encode(auth), "signature": B64.encode(signature.to_der().as_bytes()),
            "userHandle": key.user_handle}, "clientExtensionResults": {}}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::signature::Verifier;
    pub fn options() -> Value {
        json!({"challenge": B64.encode([42;32]), "rp":{"id":"example.com","name":"Example"},
        "user":{"id":B64.encode([7;16]),"name":"alice","displayName":"Alice"}, "pubKeyCredParams":[{"type":"public-key","alg":-7}],
        "authenticatorSelection":{"residentKey":"required","userVerification":"required"},"extensions":{"credProps":true}})
    }
    #[test]
    fn registration_and_assertion_are_verifiable() {
        let options = options();
        let (key, registration) = create("https://login.example.com", &options, true).unwrap();
        let bytes = decode(
            registration["response"]["attestationObject"]
                .as_str()
                .unwrap(),
        )
        .unwrap();
        let att: Cbor = ciborium::de::from_reader(bytes.as_slice()).unwrap();
        assert!(
            att.as_map()
                .unwrap()
                .iter()
                .any(|(k, v)| k.as_text() == Some("fmt") && v.as_text() == Some("none"))
        );
        let request = json!({"challenge": B64.encode([43;32]), "rpId":"example.com","userVerification":"required"});
        let assertion = get(&key, "https://login.example.com", &request, true).unwrap();
        let auth = decode(assertion["response"]["authenticatorData"].as_str().unwrap()).unwrap();
        assert_eq!(&auth[..32], Sha256::digest(b"example.com").as_slice());
        assert_eq!(auth[32], 0x0d);
        let client = decode(assertion["response"]["clientDataJSON"].as_str().unwrap()).unwrap();
        let mut signed = auth;
        signed.extend_from_slice(&Sha256::digest(client));
        let signature = Signature::from_der(
            &decode(assertion["response"]["signature"].as_str().unwrap()).unwrap(),
        )
        .unwrap();
        SigningKey::from_slice(&decode(&key.private_key).unwrap())
            .unwrap()
            .verifying_key()
            .verify(&signed, &signature)
            .unwrap();
        assert!(get(&key, "https://evil.example", &request, true).is_err());
        assert!(get(&key, "https://login.example.com", &request, false).is_err());
    }
    #[test]
    fn rejects_suffixes_lookalikes_and_unlisted_credentials() {
        let mut o = options();
        o["rp"]["id"] = json!("com");
        assert!(rp_id("https://example.com", &o, true).is_err());
        o["rp"]["id"] = json!("github.io");
        assert!(rp_id("https://attacker.github.io", &o, true).is_err());
        assert!(create("https://notexample.com", &options(), true).is_err());
        let (k, _) = create("https://example.com", &options(), true).unwrap();
        assert!(!matches_request(
            &k,
            "example.com",
            &json!({"allowCredentials":[{"type":"public-key","id":"wrong"}]})
        ));
    }
    #[test]
    fn supports_empty_alg_list_default_discoverable_and_optional_extensions() {
        let mut o = options();
        o["pubKeyCredParams"] = json!([]);
        o["authenticatorSelection"] = json!({});
        o["extensions"] = json!({"credProps": true, "prf": {}, "largeBlob": {"support": "preferred"}});
        let (key, registration) = create("https://github.com", &{
            let mut o2 = o.clone();
            o2["rp"]["id"] = json!("github.com");
            o2
        }, true).unwrap();
        assert!(key.discoverable, "omitted residentKey defaults to discoverable");
        assert_eq!(registration["clientExtensionResults"]["credProps"]["rk"], true);
        let usernameless_get = json!({"challenge": B64.encode([9; 32]), "rpId": "github.com"});
        assert!(matches_request(&key, "github.com", &usernameless_get));
        assert!(get(&key, "https://github.com", &usernameless_get, false).is_ok());

        let mut discouraged = o.clone();
        discouraged["rp"]["id"] = json!("github.com");
        discouraged["authenticatorSelection"]["residentKey"] = json!("discouraged");
        let (non_disc, _) = create("https://github.com", &discouraged, false).unwrap();
        assert!(!non_disc.discoverable);

        let mut required_blob = o.clone();
        required_blob["rp"]["id"] = json!("github.com");
        required_blob["extensions"]["largeBlob"]["support"] = json!("required");
        assert!(create("https://github.com", &required_blob, true).is_err());
    }
}
