use crate::ledger_addresses::{LedgerAddress, LedgerAddressType};
use warp::path::FullPath;
use warp::Rejection;

/// Handle GET request for /elections
pub async fn get_elections(mut addr: LedgerAddress) -> Result<String, Rejection> {
    if let Ok(prefix) = addr.prefix(LedgerAddressType::Election, None) {
        Ok(prefix)
    } else {
        Err(warp::reject())
    }
}

/// Handle GET request for /elections/:id
pub async fn get_election(election_id: String, addr: LedgerAddress) -> Result<String, Rejection> {
    if let Ok(address) = addr.election(&election_id, None) {
        log::debug!("elections/id: {}", &address);
        Ok(address)
    } else {
        Err(warp::reject())
    }
}

// after updates to client libs election_id will be passed to
// LedgerAddress fns as scope
pub async fn get_ballot_style_lists(
    _election_id: String,
    mut addr: LedgerAddress,
) -> Result<String, Rejection> {
    if let Ok(prefix) = addr.prefix(LedgerAddressType::BallotStyle, None) {
        log::debug!("election/:id/ballot-style-lists: {}", &prefix);
        Ok(prefix)
    } else {
        Err(warp::reject())
    }
}

pub async fn get_ballot_style_list(
    _election_id: String,
    bs_id: String,
    addr: LedgerAddress,
) -> Result<String, Rejection> {
    if let Ok(address) = addr.ballot_style(&bs_id, None) {
        log::info!("election/:id/ballot-style-lists/:id: {}", &address);
        Ok(address)
    } else {
        Err(warp::reject())
    }
}

/// derive address type from request path
/// and use that and the hdap_key to get an address
pub async fn get_cast_many(
    _election_id: String,
    path: FullPath,
    mut addr: LedgerAddress,
) -> Result<String, Rejection> {
    log::info!("get_hdap, request path: {:?}, ", &path);
    let addr_type = if let Some(addr_type) = addr.type_from_path_str(path.as_str()) {
        log::info!("get_hdap, addr_type: {}, ", &addr_type);
        addr_type
    } else {
        return Err(warp::reject());
    };
    if let Ok(prefix) = addr.prefix(addr_type, None) {
        Ok(prefix)
    } else {
        Err(warp::reject())
    }
}

/// derive address type from request path
/// and use that and the hdap_key to get an address
pub async fn get_hdap(
    _election_id: String,
    hdap_key: String,
    path: FullPath,
    mut addr: LedgerAddress,
) -> Result<String, Rejection> {
    log::info!("get_hdap, request path: {:?}, ", &path);
    // get LedgerAddressType from request path
    let addr_type = if let Some(addr_type) = addr.type_from_path_str(path.as_str()) {
        log::info!("get_hdap, addr_type: {}, ", &addr_type);
        addr_type
    } else {
        return Err(warp::reject());
    };
    log::info!("get_hdap LedgerAddressType: {}", &addr_type.to_string());

    // get LedgerAddress from type and key
    // let hdap_key = if let Some(key) = hdap_key {
    //     log::info!("get_hdap, hdap_key: {}, ", &key);
    //     key
    // } else {
    //     return Ok(addr.prefix(addr_type, None))
    // };

    if let Ok(address) = addr.hdap(&hdap_key, addr_type, None) {
        log::info!("get_hdap address: {}", &address);
        Ok(address)
    } else {
        Err(warp::reject())
    }
}
