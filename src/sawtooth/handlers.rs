use crate::http_signer::HttpSigner;
use crate::service::Service;
use std::collections::HashMap;
use warp::path::FullPath;

pub async fn fmt_query_uri(
    path: FullPath,
    query: HashMap<String, String>,
    svc: Service,
) -> Result<String, warp::Rejection> {
    // work around upstream crash on non-hex addresses
    if let Some(address) = query.get("address") {
        if hex::decode(address).is_err() {
            return Err(warp::reject::not_found());
        }
    }

    let query_string = serde_qs::to_string(&query).unwrap();
    log::info!("get path: {:?}", &path);
    let req_uri = format!(
        "{}{}?{}",
        svc.config.backend_url,
        path.as_str(),
        query_string
    );
    log::info!("get req_uri: {:?}", &req_uri);
    Ok(req_uri)
}

/// authenticate
pub async fn authenticate(
    auth: Option<String>,
    chain: Option<String>,
    svc: Service,
    signer: HttpSigner,
) -> Result<String, warp::Rejection> {
    // Check if authentication is enabled in configuration
    // if so, and authentication fails, reject request
    // if auth succeeds, continue
    if svc.config.authenticate {
        // check that both authentication headers are defined
        match auth.zip(chain) {
            Some((auth, chain)) => {
                // reject if auth/verify fails
                if signer
                    .verify_request(chain.as_bytes().to_vec(), auth)
                    .is_err()
                {
                    return Err(warp::reject());
                }
            }
            // reject if either auth or chain headers not defined
            None => return Err(warp::reject()),
        };
    }
    Ok("authed".to_string())
}
