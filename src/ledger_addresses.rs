use anyhow::{Result, bail};
use bip32::{ExtendedPublicKey, Prefix, XPub};
use hex::ToHex;
use ring::digest::{digest, SHA256};
use std::collections::HashMap;
use std::fmt;
use std::str::FromStr;
use std::sync::{Arc, Mutex};

/// Enum to hold the transaction processor family names for all of the
/// transaction processors in the system
enum TransactionFamily {
    Management,
    Casting,
}

impl fmt::Display for TransactionFamily {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            TransactionFamily::Management => write!(f, "election-management"),
            TransactionFamily::Casting => write!(f, "election-casting"),
        }
    }
}

pub enum LedgerAddressType {
    Election = 2,
    BallotStyle = 3,
    CastPermission = 4,
    CastVoteRecord = 5,
    VoterReceipt = 6,
    CvrStatus = 7,
    AuthenticationRecord = 8,
    BallotStyleReceipt = 9,
    VoterAutograph = 10,
}

impl LedgerAddressType {
    fn family(&self) -> TransactionFamily {
        match self {
            LedgerAddressType::Election
            | LedgerAddressType::BallotStyle
            | LedgerAddressType::CvrStatus
            | LedgerAddressType::CastPermission
            | LedgerAddressType::AuthenticationRecord => TransactionFamily::Management,
            LedgerAddressType::CastVoteRecord
            | LedgerAddressType::VoterReceipt
            | LedgerAddressType::BallotStyleReceipt
            | LedgerAddressType::VoterAutograph => TransactionFamily::Casting,
        }
    }
    fn encode(self, index: Option<u8>) -> String {
        let index = index.unwrap_or(0x00);
        let byte_array: [u8; 2] = [self as u8, index];
        byte_array.encode_hex::<String>()
    }
}

impl fmt::Display for LedgerAddressType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            LedgerAddressType::CastVoteRecord => write!(f, "cast-vote-record"),
            LedgerAddressType::BallotStyleReceipt => write!(f, "ballot-style-receipt"),
            LedgerAddressType::AuthenticationRecord => write!(f, "authentication-record"),
            LedgerAddressType::CastPermission => write!(f, "cast-permission"),
            LedgerAddressType::VoterReceipt => write!(f, "voter-receipt"),
            LedgerAddressType::VoterAutograph => write!(f, "voter-autograph"),
            LedgerAddressType::Election => write!(f, "election"),
            LedgerAddressType::BallotStyle => write!(f, "ballot-style"),
            LedgerAddressType::CvrStatus => write!(f, "cvr-status"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct LedgerAddress {
    namespaces: Arc<Mutex<HashMap<String, String>>>,
}

impl LedgerAddress {
    pub fn new() -> Self {
        Self {
            namespaces: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn prefix(&mut self, addr_type: LedgerAddressType, scope: Option<&str>) -> Result<String>{
        let scope = scope.unwrap_or("");
        let ns = self.namespace(addr_type.family(), scope.to_string())?;
        let result = ns + &addr_type.encode(None);
        Ok(result)
    }
    /// pull the string from the appropriate place in the route
    /// and return a type. Seems impossible that a non-conformant path could have
    /// evoked this function, but handle the error just in case
    pub fn type_from_path_str(&mut self, path: &str) -> Option<LedgerAddressType> {
        let s = path.split('/').nth(3)?;
        match s {
            "cast-vote-records" => Some(LedgerAddressType::CastVoteRecord),
            "authentication-records" => Some(LedgerAddressType::AuthenticationRecord),
            "ballot-style-lists" => Some(LedgerAddressType::BallotStyle),
            "ballot-style-receipts" => Some(LedgerAddressType::BallotStyleReceipt),
            "cast-permissions" => Some(LedgerAddressType::CastPermission),
            "cast-vote-record-statuses" => Some(LedgerAddressType::CvrStatus),
            "elections" => Some(LedgerAddressType::Election),
            "voter-autographs" => Some(LedgerAddressType::VoterAutograph),
            "voter-receipts" => Some(LedgerAddressType::VoterReceipt),
            _ => None,
        }
    }

    pub fn election(mut self, election_id: &str, scope: Option<&str>) -> Result<String> {
        let prefix = self.prefix(LedgerAddressType::Election, scope)?;
        let hash: [u8; 30] = digest(&SHA256, election_id.as_bytes()).as_ref()[0..30]
            .try_into()?;
        let result = prefix + &hash.encode_hex::<String>();
        Ok(result)
    }

    pub fn ballot_style(mut self, ballot_style_id: &str, scope: Option<&str>) -> Result<String >{
        let prefix = self.prefix(LedgerAddressType::BallotStyle, scope)?;
        let hash: [u8; 30] = digest(&SHA256, ballot_style_id.as_bytes()).as_ref()[0..30]
            .try_into()?;
        let result = prefix + &hash.encode_hex::<String>();
        Ok(result)
    }

    fn namespace(&mut self, family: TransactionFamily, scope: String) -> Result<String> {
        let prefix_key = [family.to_string(), scope].concat();
        let mut lock = self.namespaces.lock().expect("could not unlock cache");
        if let Some(ns) = lock.get(&prefix_key as &str) {
            Ok(ns.to_string())
        } else {
            let hash: [u8; 3] = digest(&SHA256, prefix_key.as_bytes()).as_ref()[0..3]
                .try_into()?;
            let ns = hash.encode_hex::<String>();
            lock.insert(prefix_key, ns.clone());
            Ok(ns)
        }
    }

    pub fn hdap(
        &mut self,
        key_string: &str,
        addr_type: LedgerAddressType,
        scope: Option<&str>,
    ) -> Result<String> {
        log::info!("hdap key_string: {}", &key_string);
        let scope = scope.unwrap_or("");
        if !key_string.starts_with(Prefix::XPUB.as_str()) {
            bail!("not xpub")
        }
        let xpub: XPub = ExtendedPublicKey::from_str(key_string)?;
        let key_index = xpub.attrs().child_number.index();

        let key_sha: [u8; 30] =
            digest(&SHA256, &xpub.public_key().to_bytes()[..])
            .as_ref()[0..30].try_into()?;

        let ns = self.namespace(addr_type.family(), scope.to_string())?;
        let addr = ns + &addr_type.encode(Some(key_index as u8)) + &key_sha.encode_hex::<String>();
        Ok(addr)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    static ELECTION_ADDR: &str =
        "e24b3102001a5b411cb32ba0de6e9a95baddf0eacdbaa6bf6d0a320f4d95f20633f17b";
    static BALLOT_STYLE_ADDR: &str =
        "e24b31030003ac674216f3e15c761ee1a5e255f067953623c8b388b4459e13f978d7c8";

    #[test]
    fn test_to_string() {
        assert_eq!(TransactionFamily::Casting.to_string(), "election-casting");
        assert_eq!(
            TransactionFamily::Management.to_string(),
            "election-management"
        );
    }

    #[test]
    fn test_family() {
        assert_eq!(
            LedgerAddressType::Election.family().to_string(),
            "election-management"
        );
        assert_eq!(
            LedgerAddressType::CastVoteRecord.family().to_string(),
            "election-casting"
        );
    }

    #[test]
    fn test_namespace() -> Result<()> {
        let mut addr = LedgerAddress::new();
        let casting_ns = addr.namespace(TransactionFamily::Casting, "".to_string())?;
        let management_ns = addr.namespace(TransactionFamily::Management, "".to_string())?;
        assert_eq!(casting_ns, "e5c1b2");
        assert_eq!(management_ns, "e24b31");
        Ok(())
    }

    #[test]
    fn test_election_prefix() -> Result<()> {
        let mut ledger_address = LedgerAddress::new();
        let addr = ledger_address.prefix(LedgerAddressType::Election, None)?;
        assert_eq!(addr, &ELECTION_ADDR[..10]);
        Ok(())
    }

    #[test]
    fn test_bs_prefix() {
        let mut ledger_address = LedgerAddress::new();
        let addr = ledger_address.prefix(LedgerAddressType::BallotStyle, None).unwrap();
        assert_eq!(addr, "e24b310300");
    }

    #[test]
    fn test_election() {
        let election_id = "ynKTPBw8Br3-ohWO6kPac";
        let ledger_address = LedgerAddress::new();
        let addr = ledger_address.election(election_id, None).unwrap();
        assert_eq!(addr, ELECTION_ADDR);
    }

    #[test]
    fn test_ballot_style() {
        let ballot_style_id = "1234";

        let ledger_address = LedgerAddress::new();
        let addr = ledger_address.ballot_style(ballot_style_id, None).unwrap();
        assert_eq!(addr, BALLOT_STYLE_ADDR);
    }

    #[test]
    fn test_type_from_path_str() {
        let mut ledger_address = LedgerAddress::new();
        let cvr_path_str = "/elections/123/cast-vote-records/xpub093uroidfj";
        let receipt_path_str = "/elections/123/voter-receipts/323";
        let cvr_type = ledger_address.type_from_path_str(cvr_path_str).unwrap();
        let v_receipt_type = ledger_address.type_from_path_str(receipt_path_str).unwrap();
        assert_eq!(
            cvr_type.to_string(),
            LedgerAddressType::CastVoteRecord.to_string()
        );
        assert_eq!(
            v_receipt_type.to_string(),
            LedgerAddressType::VoterReceipt.to_string()
        );
    }

    #[test]
    fn test_hdap() {
        static BS_RECEIPT_KEY: &str = "xpub69d7o8V7sqmJ2q4yVjtJVAu7vTw3kPhXTgVDGdewqoSkJqDE9SGyzKmtDGqhWC4bSoFfLe8ZNiXgyVW6DzAAFYB5okedWexAJtW96f3Lv99";
        static BS_RECEIPT_ADDRESS: &str =
            "e5c1b20901c221b7302f4328dae2724de5fce7c9c9249ac92339eac563381cfd3d5c5b";
        static CVR_RECEIPT_KEY: &str = "xpub6CCLwTTBwMkNEsD4RuHrQUGVKRfhKFgrZiuvtJf61X8wbnwYALgaQkM7mxscXGH9XuniEqRSRi9BBN5SuW2qx2Z2W8BnPu1UbEQqm4XWKxs";
        static CVR_KEY: &str = "xpub6A8xBrTys98jLevnXUgN2YfjuzX36E5pfjQQT8PfZtJ7JY2noYDXVYQyqtJhUJJS9ezC6uaUZ5iWAJMBddKBHouKa7omUW6BdV4R9g6qLNZ";
        static CVR_ADDR: &str =
            "e5c1b205001d2d07dc874dee62374c677ec0da5d44af907300d48d59b7053eedc74612";
        static CVR_RECEIPT_ADDR: &str =
            "e5c1b206006c1dac01f43b6db745a74148865ad341ea9228fb2a55b79a56561ddd6f14";
        static AUTOGRAPH_KEY: &str = "xpub69d7o8V7sqmJ5ystANTKTTAF9pbeoHPquyPoEZsAyZrBe3mFSSetNxw1MZAt7UURan5No4yDpHPTxCgWuLuQ2etT8ShJ18x7gQi1miyDKpf";
        static AUTOGRAPH_ADDR: &str =
            "e5c1b20a025974acbd6747182a07667239c0f843ef35686bf3a5528f33b918dc3ffb62";

        let mut ledger_address = LedgerAddress::new();
        let bsr_addr =
            ledger_address.hdap(BS_RECEIPT_KEY, LedgerAddressType::BallotStyleReceipt, None);
        let voter_receipt_addr =
            ledger_address.hdap(CVR_RECEIPT_KEY, LedgerAddressType::VoterReceipt, None);
        let cvr_addr = ledger_address.hdap(CVR_KEY, LedgerAddressType::CastVoteRecord, None);
        let autograph_addr =
            ledger_address.hdap(AUTOGRAPH_KEY, LedgerAddressType::VoterAutograph, None);

        assert_eq!(bsr_addr.unwrap(), BS_RECEIPT_ADDRESS);
        assert_eq!(voter_receipt_addr.unwrap(), CVR_RECEIPT_ADDR);
        assert_eq!(cvr_addr.unwrap(), CVR_ADDR);
        assert_eq!(autograph_addr.unwrap(), AUTOGRAPH_ADDR);
    }
}
