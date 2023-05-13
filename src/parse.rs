/// struct to hold data parsed from HTTP authentication header
#[derive(Debug, PartialEq, Eq)]
pub struct AuthHeader {
    pub key_id: String,
    // algorithm: String,
    pub message: String,
    pub signature: String,
}
impl AuthHeader {
    /// Given the value of an HTTP authentication header,
    /// parse and return `AuthHeader`.
    ///
    /// Note, there is another unfinished version of this with better
    /// error messages using the `nom` parser but, it is not ready yet.
    pub fn parse(s: &str) -> AuthHeader {
        let parsed_sig_header: Vec<&str> = s.split(',').map(|s| s.trim()).collect();

        let trash = move |s: &str| {
            s.split('=').collect::<Vec<&str>>()[1]
                .trim_matches('"')
                .to_string()
        };

        let signature = trash(parsed_sig_header[5]);
        let key_id = trash(parsed_sig_header[0]);
        let date = parsed_sig_header[2].split(':').collect::<Vec<&str>>()[1..].join(":");
        let body_digest = trash(parsed_sig_header[3]);
        let target = parsed_sig_header[4].split(':').collect::<Vec<&str>>()[1].trim_matches('"');

        // build sig data to verify
        let sig_data_array: [(&str, &str); 3] = [
            ("date", &date),
            ("digest", body_digest.as_str()),
            ("(request-target)", target),
        ];
        // we need a string for sigining
        let message = sig_data_array
            .iter()
            .map(|(k, v)| format!("{}:{}", k, v))
            .collect::<Vec<String>>()
            .join(",");

        AuthHeader {
            key_id,
            message,
            signature,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn test_parse_header() -> anyhow::Result<()> {
        let header_value = r#"signature keyId="71b6b30005df16ff6a5f6eaa3f09e7285b7c1765f5e47849e3cacfdf3ed601c2",algorithm="ecdsa-sha256",headers="date:2022-03-23 18:28:49.131131153 UTC,digest:SHA-256="3fb997211314d8434754b842d4ac2f47dc5a2e5ae8874567376a657296b50fae",(request-target):get state/e24b31896d78f1febad66e62b993626df726cb1949afebec8d959ea7de85fea2ea5775",signature="8d3d7ef3b78eba3106f656bf4d6b433d71c50622e588d83e83a702c4c060bbb3cd785dd0e44f693b6333837a3be57e3a6e06240652210e47eaa88e27b1d44105""#;
        let parsed = AuthHeader::parse(header_value);
        assert_eq!(
            "71b6b30005df16ff6a5f6eaa3f09e7285b7c1765f5e47849e3cacfdf3ed601c2",
            parsed.key_id
        );

        Ok(())
    }
}
