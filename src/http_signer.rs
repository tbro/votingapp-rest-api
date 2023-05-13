use crate::{certs::CertStore, parse::AuthHeader};
use anyhow::{anyhow, bail};
use chrono::Utc;
use ring::signature::{EcdsaKeyPair, ECDSA_P384_SHA384_ASN1, ECDSA_P384_SHA384_ASN1_SIGNING};
use ring::{
    digest,
    rand::SystemRandom,
    signature::{Signature, UnparsedPublicKey},
};
use std::sync::Arc;
use warp::{http, http::HeaderMap, hyper::header::HeaderName};
use x509_parser::prelude::*;

const ENV_SIGNING_KEY: &str = "HTTP_SIGNING_KEY";
const ENV_SIGNING_KEY_PUB: &str = "HTTP_SIGNING_KEY_PUB";
const ENV_SIGNING_CERT_CHAIN: &str = "VA_CERTIFICATE_CHAIN";

/// Any `Verifier` should be able to verify signatures and trust.
/// Context specific processing (parsing headers, for example) is left to
/// the implementation. The goal is to be as generic as possible so that
/// these could be called in different scenarios. Though the true agenda is
/// be able to implement these methods separately so we can stub them in tests
pub trait Verifier {
    /// Message signature verification. Returns `Ok(())` or a generic error.
    fn verify_signature(
        &self,
        message: &[u8],
        public_key_bytes: &[u8],
        sig: &[u8],
    ) -> anyhow::Result<()> {
        let peer_public_key = UnparsedPublicKey::new(&ECDSA_P384_SHA384_ASN1, public_key_bytes);
        peer_public_key
            .verify(message, sig)
            .map_err(|_| anyhow!("Signature Verification Error"))
    }

    /// Comprehensive validation and verification of signature chain
    /// This function will validate that:
    ///  - The request has a valid formatted signature for the system
    ///  - The signature and signing certificate are valid
    ///  - The certificate chain is valid
    ///  - The signing certificate or one of the certificates in its chain was
    ///    signed by one of the trusted certificates
    ///
    /// Errors for the different verification steps are hoisted up to the caller.
    fn verify_trust(
        &self,
        sig_chain: Vec<u8>,
        signer_certificate_id: String,
        message: String,
        signature: String,
    ) -> anyhow::Result<()> {
        // Initialize a new / clean store.
        let mut cert_store = CertStore::new()?;
        // Load the decoded PEM structures into the store.
        // `load_pem_files` calls `cert_store.load` internally
        // which validates structure and verifies signatures
        cert_store.load_pem_files(sig_chain)?;
        // Get the *validated* signing certificate from the store
        let signer = cert_store.get(signer_certificate_id)?;

        let pub_key = signer.public_key();
        // Verify signature against public key obtained from signing certificate
        self.verify_signature(message.as_bytes(), pub_key.raw, signature.as_bytes())
    }
}

/// Struct to provide the ability to sign and verify http requests & responses.
#[derive(Debug, Clone)]
pub struct HttpSigner {
    /// Key pair used to sign responses
    signing_key_pair: Arc<EcdsaKeyPair>,
    /// Full chain of the `signingCert`
    signing_cert_chain: Vec<Vec<u8>>,
    /// Certificate that corresponds to the `signing Key`
    signing_cert: Arc<Vec<u8>>,
    /// Identifier of signing cert
    signing_cert_fingerprint: Vec<u8>,
    /// Algorithm used in the signatures
    signature_algorithm: String,
}

// avoid implementing defaults in tests
#[cfg(not(test))]
impl Verifier for HttpSigner {}

impl HttpSigner {
    /// Instantiates a HttpSigner instance that can be used to sign requests &
    ///  responses
    pub fn new() -> anyhow::Result<HttpSigner> {
        let signature_algorithm = "ecdsa-sha384".to_string();

        let signing_key_pair = match HttpSigner::get_signing_key_pair() {
            Ok(key_pair) => Arc::new(key_pair),
            Err(e) => bail!("Failed to get key pair: {}", e),
        };

        let signing_cert_chain = match HttpSigner::get_signing_cert_chain() {
            Ok(chain) => chain,
            Err(e) => bail!("Failed to get certificate chain: {}", e),
        };

        let signing_cert = Arc::new(signing_cert_chain[0].clone());
        let signing_cert_fingerprint = CertStore::get_fingerprint(&signing_cert, None);

        Ok(HttpSigner {
            signature_algorithm,
            signing_key_pair,
            signing_cert_chain,
            signing_cert,
            signing_cert_fingerprint,
        })
    }
    /// Creates headers w/ signature and friends
    ///
    ///  Signs a response by calculating the signature and updating the response
    ///  with the appropriate signature headers such as:

    ///   - Date (if needed)
    ///   - Digest
    ///   - Signature
    ///   - va-signature-chain
    ///
    /// headers are lowercase:
    /// <https://www.rfc-editor.org/rfc/rfc7540#section-8.1.2>
    pub fn sign_response(&self, req_target: String, body: &[u8]) -> HeaderMap {
        // get digest header
        let digest = digest::digest(&digest::SHA256, body);
        let digest_header_value = format!("SHA-256=\"{}\"", base64::encode(digest.as_ref()));
        let date = Utc::now().to_rfc2822();

        // array to hold ordered message for signing
        let sig_data_array: [(&str, &str); 4] = [
            ("(request-target)", req_target.as_str()),
            ("date", date.as_str()),
            ("content-type", "application/json; charset=utf-8"),
            ("digest", digest_header_value.as_str()),
        ];
        // we need a string for signing
        let sig_data = sig_data_array
            .iter()
            .map(|(k, v)| format!("{}:{}", k, v))
            .collect::<Vec<String>>()
            .join(",");

        // ordered headers included in signing string
        let sig_data_headers = sig_data_array
            .iter()
            .map(|(k, _v)| k.to_string())
            .collect::<Vec<String>>()
            .join(" ");

        // sign it
        let sig = self.sign(sig_data.as_ref());

        // omit (request-target) pseudo-header
        let sig_headers = sig_data_array
            .into_iter()
            .filter(|(k, _v)| k != &"(request-target)");
        // create HeaderMap and add valid headers from message signing data
        let mut headers = HeaderMap::new();
        for item in sig_headers {
            let header_name = HeaderName::from_lowercase(item.0.as_bytes()).unwrap();
            headers.insert(header_name, item.1.parse().unwrap());
        }

        // set sig chain header
        let va_header_name = HeaderName::from_lowercase(b"va-signature-chain").unwrap();
        let va_cert_chain: String = self.signing_cert_chain.iter().map(base64::encode).collect();
        headers.insert(va_header_name, va_cert_chain.parse().unwrap());

        // create signature header string
        let sig_header_name = HeaderName::from_lowercase(b"signature").unwrap();
        let sig_header = format!(
            "keyId=\"{}\",algorithm=\"{}\",headers=\"{}\",signature=\"{}\"",
            base64::encode(&self.signing_cert_fingerprint),
            self.signature_algorithm,
            sig_data_headers,
            base64::encode(sig.as_ref())
        );
        headers.insert(sig_header_name, sig_header.parse().unwrap());

        // expose headers for browsers
        let expose = "Authorization, Signature, va-signature-chain, digest, Date, Content-Type";
        headers.insert(
            http::header::ACCESS_CONTROL_EXPOSE_HEADERS,
            expose.parse().unwrap(),
        );

        headers
    }

    /// Message signer
    /// It just calls `sign` method on the keypair
    fn sign(&self, message: &[u8]) -> Signature {
        let nonce = SystemRandom::new();
        self.signing_key_pair
            .sign(&nonce, message)
            .expect("failed to sign")
    }

    /// Parses authentication data from HTTP headers and passes them to
    /// `Verifier.verify_trust`.
    pub fn verify_request(
        &self,
        signature_chain: Vec<u8>,
        auth_headers: String,
    ) -> anyhow::Result<()> {
        // FIXME deal w/ parsing errors
        // Parse header string into usable values
        let AuthHeader {
            key_id,
            message,
            signature,
        } = AuthHeader::parse(&auth_headers);
        self.verify_trust(signature_chain, key_id, message, signature)
    }

    /// retrieve signing keypair from filesystem
    fn get_signing_key_pair() -> anyhow::Result<EcdsaKeyPair> {
        std::env::set_var(
            ENV_SIGNING_KEY,
            "ledger-node-http-digital-signature.priv.pem",
        );
        std::env::set_var(
            ENV_SIGNING_KEY_PUB,
            "ledger-node-http-digital-signature.crt.pem",
        );
        let signing_key_file = std::env::var(ENV_SIGNING_KEY).expect("env var not found");
        let signing_key_pub = std::env::var(ENV_SIGNING_KEY_PUB).expect("env var not found");
        let path = std::path::Path::new("./assets").join(signing_key_file);
        let path_pub = std::path::Path::new("./assets").join(signing_key_pub);
        info!("signing key path: {}", path.display());
        let data = std::fs::read(path)?;
        let cert = std::fs::read(path_pub)?;

        // get priv key from pkcs8 pem
        let s = std::str::from_utf8(&data).expect("could not display buffer");
        let (_, b) = pkcs8::SecretDocument::from_pem(s).unwrap();
        let priv_bytes = &b.as_bytes()[35..83];

        // get pub key from cert
        let ders: Vec<Vec<u8>> = Pem::iter_from_buffer(&cert)
            .map(|pem| pem.unwrap().contents)
            .collect();
        let (_rem, cert) = X509Certificate::from_der(&ders[0])?;

        // validate pub key and return EcdsaKeyPair
        let key_pair = EcdsaKeyPair::from_private_key_and_public_key(
            &ECDSA_P384_SHA384_ASN1_SIGNING,
            priv_bytes,
            &cert.public_key().subject_public_key.data,
        );

        key_pair.map_err(|e| anyhow!("EcdsaKeyPair::from_pkcs8: {}", e))
    }

    /// retrieve and validate certificate chain
    /// chain is logged per cool factor
    fn get_signing_cert_chain() -> anyhow::Result<Vec<Vec<u8>>> {
        let cert_file = std::env::var(ENV_SIGNING_CERT_CHAIN).expect("env var not found");
        let path = std::path::Path::new("./assets").join(cert_file);
        info!("certificate chain path: {}", &path.display());
        let data = std::fs::read(&path)?;

        // validate certificate chain
        let mut cert_store = CertStore::new()?;
        cert_store
            .load_pem_files(data.clone())
            .map_err(|e| anyhow!("Could not validate certificate chain: {}", e))?;

        // log certificate chain
        info!(
            "\n{}",
            std::str::from_utf8(&data).expect("could not display buffer")
        );

        let cert_chain: Vec<Vec<u8>> = Pem::iter_from_buffer(&data)
            .map(|pem| pem.unwrap().contents)
            .collect();

        Ok(cert_chain)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;
    use ring::rand::SystemRandom;
    use ring::signature::KeyPair;
    use std::str;
    use warp::http::Response;
    static CERT_CHAIN_TEST: &str = "ledger-node-http-digital-signature.chain.pem";
    static SIGNING_KEY: &str = "3081b6020100301006072a8648ce3d020106052b8104002204819e30819b02010104301a7023f589c9f2bbf0f615c524708e94455b572dc3e380b3015cd3564e3a1eb4b1055f725cab632eb86ceb81cf32324aa164036200046110553182a17d4070bcb0e84a04782466f6aa580e3d190ccd6d55eaf7dffc8b9e1da3641ebb20781682fc37507550d4d54dd0bded0c97617d0c59a26dd30e0ad7c071be557a156886d88f6a7c0cd10b8e0891c79fa378cbf769e46d4be75970";
    static HEADER_VALUE: &str = r#"signature keyId="71b6b30005df16ff6a5f6eaa3f09e7285b7c1765f5e47849e3cacfdf3ed601c2",algorithm="ecdsa-sha384",headers="date:2022-03-23 18:28:49.131131153 UTC,digest:SHA-256="3fb997211314d8434754b842d4ac2f47dc5a2e5ae8874567376a657296b50fae",(request-target):get state/e24b31896d78f1febad66e62b993626df726cb1949afebec8d959ea7de85fea2ea5775",signature="8d3d7ef3b78eba3106f656bf4d6b433d71c50622e588d83e83a702c4c060bbb3cd785dd0e44f693b6333837a3be57e3a6e06240652210e47eaa88e27b1d44105""#;

    // mock trust verification
    impl Verifier for HttpSigner {
        fn verify_trust(
            &self,
            _sig_chain: Vec<u8>,
            _signer_certificate_id: String,
            _message: String,
            _signature: String,
        ) -> anyhow::Result<()> {
            // it just returns `Ok`
            Ok(())
        }
    }

    #[test]
    fn test_parse_auth_header() -> Result<(), ring::error::Unspecified> {
        let AuthHeader { key_id, .. } = AuthHeader::parse(HEADER_VALUE);
        assert_eq!(
            "71b6b30005df16ff6a5f6eaa3f09e7285b7c1765f5e47849e3cacfdf3ed601c2",
            key_id
        );

        Ok(())
    }

    #[test]
    fn get_signing_key_pair() -> anyhow::Result<()> {
        std::env::set_var(
            ENV_SIGNING_KEY,
            "ledger-node-http-digital-signature.priv.pem",
        );
        std::env::set_var(
            ENV_SIGNING_KEY_PUB,
            "ledger-node-http-digital-signature.crt.pem",
        );
        let key_pair = HttpSigner::get_signing_key_pair();
        assert!(key_pair.is_ok());

        Ok(())
    }

    #[test]
    fn get_signing_cert_chain() -> anyhow::Result<()> {
        // tests that we can access the certificate chain
        // and that the certificate chain is  valid
        std::env::set_var(ENV_SIGNING_CERT_CHAIN, CERT_CHAIN_TEST);
        let cert_chain = HttpSigner::get_signing_cert_chain();
        assert!(cert_chain.is_ok());
        assert_eq!(cert_chain.unwrap().len(), 3);

        Ok(())
    }

    #[test]
    fn test_sign_example() -> Result<(), ring::error::Unspecified> {
        // round trip sign/verify (for reference)
        let rng = SystemRandom::new();
        // Generate a key pair in PKCS#8 (v2) format.
        let pkcs8_bytes = EcdsaKeyPair::generate_pkcs8(&ECDSA_P384_SHA384_ASN1_SIGNING, &rng)?;
        // Do the codec dance to simulate a more realistic scenario
        let hex_encode = hex::encode(&pkcs8_bytes);
        let decoded = hex::decode(hex_encode).unwrap();
        let key_pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P384_SHA384_ASN1_SIGNING, decoded.as_ref())?;

        const MESSAGE: &[u8] = b"hello, world";
        // create a nonce
        let nonce = SystemRandom::new();
        let sig = key_pair.sign(&nonce, MESSAGE)?;

        let peer_public_key_bytes = key_pair.public_key().as_ref();
        let peer_public_key =
            UnparsedPublicKey::new(&ECDSA_P384_SHA384_ASN1, peer_public_key_bytes);
        let verified = peer_public_key.verify(MESSAGE, sig.as_ref())?;

        assert_eq!((), verified);

        Ok(())
    }

    #[test]
    fn test_sign_response() -> anyhow::Result<()> {
        std::env::set_var(
            ENV_SIGNING_KEY,
            "ledger-node-http-digital-signature.priv.pem",
        );
        std::env::set_var(
            ENV_SIGNING_KEY_PUB,
            "ledger-node-http-digital-signature.crt.pem",
        );
        std::env::set_var(ENV_SIGNING_CERT_CHAIN, CERT_CHAIN_TEST);
        let http_signer = HttpSigner::new()?;
        // create a response that we can sign
        let response = Response::new("hello world");
        let req_target = format!("{} {}", "get", "state/123456789");
        let (_parts, body) = response.into_parts();
        let headers = http_signer.sign_response(req_target.clone(), &body.as_bytes());

        let d = digest::digest(&digest::SHA256, &body.as_bytes());
        let digest = format!("SHA-256=\"{}\"", base64::encode(d.as_ref()));
        assert_eq!(headers["digest"], digest);
        assert_eq!(headers["date"].is_empty(), false);
        assert_eq!(headers["va-signature-chain"].is_empty(), false);
        assert_eq!(headers["signature"].is_empty(), false);

        let key_pair = &http_signer.signing_key_pair;
        let public_key_bytes = key_pair.public_key().as_ref();
        let sig_header = headers.get("signature").unwrap().to_str().unwrap();

        // split on comma and trim
        let parsed_sig_header: Vec<&str> = sig_header.split(",").map(|s| s.trim()).collect();

        // make sure we got back some correctish data
        assert!(parsed_sig_header[0].contains("keyId="));
        assert_eq!(parsed_sig_header[1], "algorithm=\"ecdsa-sha384\"");
        assert!(parsed_sig_header[2].contains("headers="));
        assert!(parsed_sig_header[2].contains("date"));

        // build sig data to verify
        let sig_data_array: [(&str, &str); 4] = [
            ("(request-target)", req_target.as_str()),
            ("date", headers.get("date").unwrap().to_str().unwrap()),
            ("content-type", "application/json; charset=utf-8"),
            ("digest", digest.as_str()),
        ];
        // we need a string for sigining
        let sig_data = sig_data_array
            .iter()
            .map(|(k, v)| format!("{}:{}", k, v))
            .collect::<Vec<String>>()
            .join(",");

        // pull signature from signature header
        let sig_string =
            parsed_sig_header[3].split("=").collect::<Vec<&str>>()[1].trim_matches('"');

        // verify
        let verified = http_signer.verify_signature(
            sig_data.as_bytes(),
            public_key_bytes,
            &base64::decode(sig_string)?,
        );
        assert_eq!(verified.unwrap(), ());
        Ok(())
    }

    #[test]
    fn test_http_signer_verify_sig() -> Result<(), ring::error::Unspecified> {
        // test http_signer.verify()
        let http_signer = HttpSigner::new().unwrap();
        let rng = SystemRandom::new();

        let pkcs8_bytes = EcdsaKeyPair::generate_pkcs8(&ECDSA_P384_SHA384_ASN1_SIGNING, &rng)?;
        let key_pair =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P384_SHA384_ASN1_SIGNING, pkcs8_bytes.as_ref())?;

        const MESSAGE: &[u8] = b"hello, world";
        let nonce = SystemRandom::new();
        let sig = key_pair.sign(&nonce, MESSAGE)?;

        let public_key_bytes = key_pair.public_key().as_ref();

        let verified = http_signer.verify_signature(MESSAGE, public_key_bytes, sig.as_ref());
        assert_eq!(verified.unwrap(), ());

        Ok(())
    }

    #[test]
    fn gen_pub_key() -> Result<(), ring::error::Unspecified> {
        // This doesn't test any thing. It is just a convenient
        // way to output a public key
        let decoded = hex::decode(SIGNING_KEY).unwrap();
        let key_pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P384_SHA384_ASN1_SIGNING, decoded.as_ref())?;

        assert_eq!(
            "046110553182a17d4070bcb0e84a04782466f6aa580e3d190ccd6d55eaf7dffc8b9e1da3641ebb20781682fc37507550d4d54dd0bded0c97617d0c59a26dd30e0ad7c071be557a156886d88f6a7c0cd10b8e0891c79fa378cbf769e46d4be75970",
            hex::encode(key_pair.public_key().as_ref()));
        Ok(())
    }

    #[ignore]
    #[test]
    fn test_verify_request() -> anyhow::Result<()> {
        std::env::set_var(
            ENV_SIGNING_KEY,
            "ledger-node-http-digital-signature.priv.pem",
        );

        let path = std::path::Path::new("assets").join(CERT_CHAIN_TEST);
        let cert_chain = std::fs::read_to_string(path).unwrap();
        std::env::set_var(ENV_SIGNING_CERT_CHAIN, CERT_CHAIN_TEST);

        let http_signer = HttpSigner::new()?;
        // create a response that we can sign
        let response = Response::new("hello world");
        let req_target = format!("{} {}", "get", "state/123456789");
        let (_parts, body) = response.into_parts();
        // FIXME request and response signing are not symetrical, so
        // we need some logic before passing signed response to request verifier
        let headers = http_signer.sign_response(req_target.clone(), &body.as_bytes());
        let sig_header = headers.get("signature").unwrap().to_str().unwrap();

        let verified =
            http_signer.verify_request(cert_chain.as_bytes().to_vec(), sig_header.to_string())?;
        assert_eq!(verified, ());

        Ok(())
    }
}
