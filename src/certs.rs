use anyhow::{bail, Result};
use ring::digest;
use std::collections::HashMap;
use x509_parser::prelude::*;

#[derive(Debug, Clone)]
pub struct CertStore {
    /// Store is a hashmap of fingerprint (key) and der bytes (value).
    /// We store the der bytes to move ownership to the store which is easier
    /// to reason about than the alternative, storing the parsed X509 view.
    /// It does mean we have to parse certificates on retrieval, but this is a zero-copy
    /// operation so cost is low to nil.
    pub store: HashMap<Vec<u8>, Vec<u8>>,
    /// fingerprint of root certificate
    pub root_fingerprint: Option<Vec<u8>>, // will be set at application startup
    /// fingerprint of intermediate certificate
    pub inter_fingerprint: Option<Vec<u8>>, // will be set at application startup
}
/// public key of signer is public key on issuer cert
/// 1. load cert
/// 2. validate cert (structure/date/etc)
/// 3. if self signed, -> ?
/// 4. else iterate store to find issuer
/// 5. verify cert against issuer pub key
impl CertStore {
    pub fn new() -> Result<CertStore> {
        let store = HashMap::new();
        let root_fingerprint = None;
        let inter_fingerprint = None;

        Ok(CertStore {
            store,
            root_fingerprint,
            inter_fingerprint,
        })
    }
    /// Loads certificates into the store. If validation is required and any
    /// certificate does not pass the validation check then the entire operation
    /// is rolled back and an error is thrown. `allow_self_signed` should only be
    /// true when loading root certificate at boot time.
    pub fn load(&mut self, ders: Vec<Vec<u8>>, allow_self_signed: bool) -> Result<()> {
        for der in ders.iter().rev() {
            // parse x509
            let (_rem, cert) = X509Certificate::from_der(der)?;
            // validate structure
            self.validate(&cert)?;
            // get the fingerprint
            let fingerprint = CertStore::get_fingerprint(der, None);
            // if not self-signed, find the issuer
            let issuer = if allow_self_signed && cert.subject() == cert.issuer() {
                cert.clone()
            } else {
                self.get_issuer(cert.issuer())?
            };
            // if we can verify the signature, store the cert
            if CertStore::verify(&cert, issuer.public_key())? {
                self.store.insert(fingerprint, der.to_vec());
            };
        }
        Ok(())
    }
    /// Convenience function to load certs from pem files
    /// It expects a base64 encoded PEM file and calls `load`.
    pub fn load_pem_files(&mut self, chain: Vec<u8>) -> Result<()> {
        let pems: Vec<Vec<u8>> = Pem::iter_from_buffer(&chain)
            .map(|pem| pem.unwrap().contents)
            .collect();
        self.load(pems, true)
    }
    pub fn get(&self, fingerprint: String) -> Result<X509Certificate> {
        let fbytes = &hex::decode(fingerprint)?;
        if let Some(der) = self.store.get(fbytes) {
            let (_, cert) = X509Certificate::from_der(der)?;
            Ok(cert)
        } else {
            bail!("Cert Not Found")
        }
    }
    pub fn get_all(&self) -> Result<Vec<X509Certificate>> {
        self.store
            .values()
            .into_iter()
            .map(|bytes| match X509Certificate::from_der(bytes) {
                Ok((_rem, cert)) => Ok(cert),
                _ => bail!("failed"),
            })
            .collect::<Result<Vec<X509Certificate>>>()
    }
    fn get_issuer(&self, issuer: &X509Name) -> Result<X509Certificate> {
        for (_, item) in self.store.iter() {
            let (_rem, x509) = X509Certificate::from_der(item)?;
            if x509.subject() == issuer {
                return Ok(x509);
            }
        }
        bail!("issuer not found")
    }
    fn validate(&self, cert: &X509Certificate) -> Result<()> {
        // validate date
        if !cert.validity().is_valid() {
            bail!("invalid date");
        }

        let mut logger = VecLogger::default();
        // validate structure
        match X509StructureValidator.validate(cert, &mut logger) {
            true => Ok(()),
            false => bail!("invalid certificate"),
        }
    }
    fn verify(cert: &X509Certificate, issuer_public_key: &SubjectPublicKeyInfo) -> Result<bool> {
        match cert.verify_signature(Some(issuer_public_key)) {
            Ok(()) => Ok(true),
            Err(e) => bail!("signature validation failure: {}", e),
        }
    }
    /// Given DER bytes, calculate a fingerprint. Requires a second argment of
    /// `digest::Algorithm` or None. `None` operates as default case and will return sha256.
    /// Sha1 has has been validated against openssl for correctness. You can check with:
    /// ```
    /// openssl x509 -in assets/certificates/vidaloop-votingapp-dev-root.crt.pem -fingerprint -noout
    /// ```
    /// Note that sha1 is deprecated, but seems to be hard-coded in openssl
    pub fn get_fingerprint(
        der_bytes: &[u8],
        digest_algorithm: Option<&'static digest::Algorithm>,
    ) -> Vec<u8> {
        if let Some(algorithm) = digest_algorithm {
            digest::digest(algorithm, der_bytes).as_ref().to_vec()
        } else {
            digest::digest(&digest::SHA256, der_bytes).as_ref().to_vec()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;
    use x509_parser::num_bigint::BigUint;
    // FIXME tests will fail when certs expire
    // Ideally we would genrate certs on the fly
    static CERT_CHAIN_TEST: &str = "assets/ledger-node-http-digital-signature.chain.pem";
    static CERT_SIG: &str = "assets/ledger-node-http-digital-signature.crt.pem";

    #[test]
    fn test_cert_store_creation() -> Result<()> {
        let cert_store = CertStore::new()?;
        let map = cert_store.store;
        let keys: Vec<Vec<u8>> = map.keys().cloned().collect();
        assert_eq!(keys.len(), 0);
        assert_eq!(map.is_empty(), true);
        Ok(())
    }

    #[test]
    fn test_fingerprint() -> Result<()> {
        let data = std::fs::read(CERT_SIG).expect("Could not read file");
        let pems: Vec<Pem> = Pem::iter_from_buffer(&data)
            .map(|pem| pem.unwrap())
            .collect();
        let expected_hex = "7ec3aad5b87d5055a1ab418df8464bc1204df606";
        let algo = Some(&digest::SHA1_FOR_LEGACY_USE_ONLY);
        let derived: Vec<u8> = CertStore::get_fingerprint(&pems[0].contents, algo);
        assert_eq!(expected_hex, hex::encode(&derived));

        Ok(())
    }

    #[test]
    fn test_cert_store_load_store() -> Result<()> {
        let mut cert_store = CertStore::new()?;

        let data = std::fs::read(CERT_CHAIN_TEST).expect("Could not read file");
        let chain: Vec<Vec<u8>> = Pem::iter_from_buffer(&data)
            .map(|pem| pem.unwrap().contents)
            .collect();

        cert_store.load(chain.clone(), true).unwrap();

        // here we test against hasMap native `values()`
        // next test will use `store.get_all()`
        let stored_certs = cert_store
            .store
            .values()
            .into_iter()
            .map(|der| {
                X509Certificate::from_der(der)
                    .unwrap()
                    .1
                    .tbs_certificate
                    .clone()
            })
            .collect::<Vec<TbsCertificate>>();

        // Certs will not be stored if they cannot be verified
        // so this asserts that certs were validated, verified and stored
        assert_eq!(cert_store.store.is_empty(), false);
        assert_eq!(stored_certs.len(), 3);

        Ok(())
    }

    #[test]
    fn test_cert_store_get() -> Result<()> {
        let mut cert_store = CertStore::new()?;

        let data = std::fs::read(CERT_CHAIN_TEST).expect("Could not read file");
        let ders: Vec<Vec<u8>> = Pem::iter_from_buffer(&data)
            .map(|pem| pem.unwrap().contents)
            .collect();

        cert_store.load(ders.clone(), true).unwrap();
        let x509s: Vec<X509Certificate> = ders
            .iter()
            .map(|bytes| X509Certificate::from_der(bytes).unwrap().1)
            .collect();

        let expected = x509s[0].clone();
        let fingerprint: Vec<u8> = CertStore::get_fingerprint(&ders[0], None);

        let stored_der = cert_store.store.get(&fingerprint).unwrap();
        let (_rem, stored) = X509Certificate::from_der(stored_der).unwrap();

        assert_eq!(cert_store.store.is_empty(), false);
        assert_eq!(stored.serial, expected.serial);
        assert_eq!(stored.issuer, expected.issuer);

        Ok(())
    }

    #[test]
    fn test_cert_store_get_all() -> Result<()> {
        let mut cert_store = CertStore::new()?;

        let data = std::fs::read(CERT_CHAIN_TEST).expect("Could not read file");
        let pem_contents: Vec<Vec<u8>> = Pem::iter_from_buffer(&data)
            .map(|pem| pem.unwrap().contents)
            .collect();

        cert_store.load(pem_contents.clone(), true).unwrap();

        let x509s: Vec<X509Certificate> = pem_contents
            .iter()
            .map(|bytes| X509Certificate::from_der(bytes).unwrap().1)
            .collect();
        let certs = x509s
            .iter()
            .map(|cert| cert.tbs_certificate.clone())
            .collect::<Vec<TbsCertificate>>();

        let stored_certs = cert_store
            .get_all()?
            .iter()
            .map(|cert| cert.tbs_certificate.clone())
            .collect::<Vec<TbsCertificate>>();
        assert_eq!(cert_store.store.is_empty(), false);
        assert_eq!(stored_certs.len(), 3);
        assert_eq!(
            certs
                .iter()
                .map(|cert| cert.clone().serial)
                .collect::<Vec<BigUint>>()
                .sort(),
            stored_certs
                .iter()
                .map(|cert| cert.clone().serial)
                .collect::<Vec<BigUint>>()
                .sort()
        );

        Ok(())
    }

    #[test]
    fn test_cert_store_date_validation() -> Result<()> {
        let cert_store = CertStore::new()?;
        let data = std::fs::read(CERT_SIG).expect("Could not read file");

        let pems: Vec<Pem> = Pem::iter_from_buffer(&data)
            .map(|pem| pem.unwrap())
            .collect();
        let x509s: Vec<X509Certificate> =
            pems.iter().map(|pem| pem.parse_x509().unwrap()).collect();

        // first check valid certificate
        assert_eq!(x509s[0].validity().is_valid(), true);
        assert_eq!(cert_store.validate(&x509s[0]).is_ok(), true);

        // invalidate and check again
        let nov_3_1999: i64 = 921176372;
        let nov_3_2008: i64 = 1205259572;

        let invalid = Validity {
            not_before: ASN1Time::from_timestamp(nov_3_1999).unwrap(),
            not_after: ASN1Time::from_timestamp(nov_3_2008).unwrap(),
        };

        let pems: Vec<Pem> = Pem::iter_from_buffer(&data)
            .map(|pem| pem.unwrap())
            .collect();
        let mut x509s: Vec<X509Certificate> =
            pems.iter().map(|pem| pem.parse_x509().unwrap()).collect();

        x509s[0].tbs_certificate.validity = invalid.clone();

        assert_eq!(x509s[0].tbs_certificate.validity, invalid);
        assert_eq!(x509s[0].tbs_certificate.validity().is_valid(), false);
        assert_eq!(x509s[0].validity, invalid);
        assert_eq!(x509s[0].validity().is_valid(), false);
        assert_eq!(cert_store.validate(&x509s[0]).is_ok(), false);
        assert_eq!(cert_store.validate(&x509s[0]).is_err(), true);

        Ok(())
    }
}
