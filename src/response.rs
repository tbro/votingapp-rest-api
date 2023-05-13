use anyhow::{bail, Context, Result};
use serde_derive::{Deserialize, Serialize};
use serde_json::Value;
use std::fmt::Display;

#[derive(Debug, Clone, Deserialize, Serialize)]
struct Paging {
    limit: Option<String>,
    next: Option<String>,
    next_position: Option<String>,
    start: Option<String>,
}
/// Response Item
#[derive(Debug, Deserialize, Serialize)]
struct DownstreamResponseItem {
    address: String,
    data: Value,
}
#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
enum UpstreamDownstream {
    Simple(String),
    Series(Vec<String>),
}
/// Upstream Response Item
#[derive(Debug, Deserialize, Serialize)]
struct ResponseItem {
    address: String,
    data: String,
}
/// Upstream returns data array in the case of query params
/// but in the case of state path param returns string
#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
enum ResponseData {
    Series(Vec<ResponseItem>),
    Simple(String),
}
/// Downstream expect returns data array
#[derive(Debug, Deserialize, Serialize)]
struct DownstreamResponseData {
    data: Vec<DownstreamResponseItem>,
    link: String,
    paging: Option<Paging>,
}
/// Struct to represent response body
#[derive(Debug, Deserialize, Serialize)]
pub struct ResponseBody {
    data: ResponseData,
    head: String,
    link: String,
    paging: Option<Paging>,
}

/// Struct to represent response body
#[derive(Debug, Deserialize, Serialize)]
pub struct DownstreamResponse {
    data: Vec<DownstreamResponseItem>,
    head: String,
    link: String,
    paging: Option<Paging>,
}
#[derive(Debug)]
enum DecodeError {
    Encode(serde_json::Error),
    Base64(base64::DecodeError),
}

impl Display for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DecodeError::Encode(e) => write!(f, "{}", e),
            DecodeError::Base64(e) => write!(f, "{}", e),
        }
    }
}

impl From<serde_json::Error> for DecodeError {
    fn from(err: serde_json::Error) -> Self {
        DecodeError::Encode(err)
    }
}
impl From<base64::DecodeError> for DecodeError {
    fn from(err: base64::DecodeError) -> Self {
        DecodeError::Base64(err)
    }
}
impl std::error::Error for DecodeError {}

impl ResponseBody {
    /// Decode `data` field of upstream response
    ///   * decode base64
    ///   * check for DTT
    ///   * return parsed Value
    pub fn decode_data(body: &str) -> Result<String> {
        let ResponseBody {
            data, link, paging, ..
        } = serde_json::from_str::<ResponseBody>(body)?;
        let data = match data {
            // Simple will never get evoked as long as we stick
            // to `state?address=` queries to the backend
            ResponseData::Simple(s) => {
                let decoded = base64::decode(s).unwrap();
                let x = std::str::from_utf8(&decoded).unwrap().to_string();
                let obj: Value = serde_json::from_str(&x).unwrap();
                let item = DownstreamResponseItem {
                    address: "".to_string(),
                    data: obj,
                };
                vec![item]
            }
            ResponseData::Series(v) => {
                let json: Result<Vec<DownstreamResponseItem>, _> = v
                    .iter()
                    .map(
                        |ResponseItem { address, data }| -> Result<DownstreamResponseItem> {
                            // decode `data object`
                            let data_str = base64::decode(data)?;
                            // stringify byte array
                            let data_str = std::str::from_utf8(&data_str)?;
                            // data coming from mobile clients will only be
                            // base64 encoded (no DTT), so we check that here
                            if let Ok(obj) = ResponseBody::parse_data(data_str) {
                                let d = DownstreamResponseItem {
                                    address: address.clone(),
                                    data: obj,
                                };
                                return Ok(d);
                            }
                            // if we are not data like then we should be a DTT
                            // but bubble up the error just in case
                            let s = data_str.split('.').nth(1).context("oops")?;
                            // Decode payload portion of DTT
                            let decoded = base64::decode(s)?;
                            let data = std::str::from_utf8(&decoded)?;
                            // parse to Value object
                            let obj: Value = serde_json::from_str(data)?;
                            let d = DownstreamResponseItem {
                                address: address.clone(),
                                data: obj,
                            };
                            Ok(d)
                        },
                    )
                    .collect();
                json?
            }
        };
        let json = DownstreamResponseData { data, link, paging };
        let encoded = serde_json::to_string_pretty(&json)?;
        Ok(encoded)
    }

    /// parse a string into Value object
    fn parse_data(s: &str) -> Result<Value> {
        if !s.contains("_version") {
            bail!("no version")
        }
        // if we can pase to Value and it has a version
        // must be data
        let obj: Value = serde_json::from_str(s)?;
        let version = &obj["_version"];
        if version.is_string() {
            Ok(obj)
        } else {
            bail!("not a version")
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;

    const EXPECTED_STATE: &str = "\nd\n\u{1e}sawtooth.identity.allowed_keys\u{12}B0330511061884952157134400c75f8385a516649c5ea504e9c9bb467966d8ca1e4";

    const UPSTREAM_DATA_SIMPLE: &str = r##"{
  "data": "CiwKIXNhd3Rvb3RoLmNvbnNlbnN1cy5hbGdvcml0aG0ubmFtZRIHRGV2bW9kZQ==",
  "head": "1b3b9c784b5c7f0a488a0d84e8ba70562fb0a415454d0c9f5ca704619f272a9a05e14895bd0cd47430330dec8d9f8f0f9f2262bf713b4af04ca3c5c46de37a35",
  "link": "https://localhost:3030/state/000000a87cb5eafdcca6a8c983c585ac3c40d9b1eb2ec8ac9f31ff82a3537ff0dbce7e?head=1b3b9c784b5c7f0a488a0d84e8ba70562fb0a415454d0c9f5ca704619f272a9a05e14895bd0cd47430330dec8d9f8f0f9f2262bf713b4af04ca3c5c46de37a35"
}"##;

    #[test]
    fn response_decode_series_jwt() -> Result<()> {
        let series_data = fs::read_to_string("mocks/state?address=e24b310200.json");
        let series_data = series_data.unwrap();
        let result = ResponseBody::decode_data(&series_data)?;
        // parse string into object so we can inspect its fields
        let obj: Value = serde_json::from_str(&result)?;
        let payload = &obj["data"][0]["data"];
        let address = &obj["data"][0]["address"];
        let head = &obj["head"];
        assert_eq!(
            address,
            "e24b3102004dbd5e30c7e714d230c374b2ad8e5fb3da5551bcd35647bca412b5dd2ad2"
        );
        assert_eq!(payload["_version"], "ElectionList/1.0");
        assert_eq!(head, &Value::Null);

        Ok(())
    }

    #[test]
    fn response_decode_series_simple() -> Result<()> {
        let series_data = fs::read_to_string("mocks/encrypted-ledger-record.json");
        let series_data = series_data.unwrap();
        let result = ResponseBody::decode_data(&series_data)?;
        // parse string into object so we can inspect its fields
        let obj: Value = serde_json::from_str(&result)?;
        let payload = &obj["data"][0]["data"];
        let address = &obj["data"][0]["address"];
        let head = &obj["head"];
        assert_eq!(
            address,
            "e5c1b205007cc853ff2aeb1b582d5fb2c8b8b309ecf85c3b70a1f9d2cabf04ca692835"
        );
        assert_eq!(payload["_version"], "EncryptedLedgerRecord/1.0");
        assert_eq!(head, &Value::Null);

        Ok(())
    }

    // DISABLING as long as we always use state?address= (instead of state/address) we
    // always have an array
    //     #[test]
    //     fn response_decode_simple() -> anyhow::Result<()> {
    //          let result = ResponseBody::decode_data(UPSTREAM_DATA_SIMPLE.to_string());
    //          println!("{}", result);
    //          // parse string into object so we can inspect its fields
    //          let obj: Value = serde_json::from_str(&result)?;
    //          assert_eq!(obj["data"][0]["data"][0], "\n,\n!sawtooth.consensus.algorithm.name\u{12}\u{7}Devmode");
    //
    //          Ok(())
    //     }
}
