use crate::handlers::{get_spec, get_version, sign};
use crate::http_signer::HttpSigner;
use crate::request::RequestService;
use crate::sawtooth;
use crate::service::Service;
use crate::votingapp;
use std::convert::Infallible;
use warp::{Filter, Rejection, Reply};

/// `api` holds all our filters which finally call respective handlers.
/// `sawtooth` holds pass through filters
/// `votingapp` holds custom endpoints
pub fn api(
    svc: Service,
    signer: HttpSigner,
) -> impl Filter<Extract = (impl Reply,), Error = warp::Rejection> + Clone {
    let req = RequestService::new(svc.clone());
    warp::any()
        .and(version())
        .or(spec())
        .or(sawtooth::filters::posts(
            req.clone(),
            signer.clone(),
            svc.clone(),
        ))
        .or(sawtooth::filters::gets(req.clone(), svc.clone()))
        .or(votingapp::filters::filters(svc, req))
        .with(cors_config())
        .and(warp::path::full())
        .and(warp::method())
        .and(with_signer(signer))
        .and_then(sign)
    // .recover(handle_rejection)
}

/// Matches GET request for /version
fn version() -> impl Filter<Extract = (impl Reply,), Error = Rejection> + Clone {
    warp::get()
        .and(warp::path("version"))
        .and(warp::path::end())
        .and_then(get_version)
}

/// Matches GET request for /spec.yaml
fn spec() -> impl Filter<Extract = (impl Reply,), Error = Rejection> + Clone {
    warp::get()
        .and(warp::path("spec.yaml"))
        .and(warp::path::end())
        .and(warp::fs::file("/assets/votingapp-rest-api_0.1.0.yaml"))
        .and_then(get_spec)
}

/// build cors configuration
pub fn cors_config() -> warp::cors::Builder {
    // TODO: move to config
    warp::cors()
        .allow_any_origin() // TODO: add value from config, but default to *
        .allow_headers(vec![
            "Authorization",
            "Signature",
            "va-signature-chain",
            "digest",
            "Date",
            "Origin",
            "X-Requested-With",
            "Content-Type",
            "Accept",
            "If-None-Match",
            "Cache-Control",
        ]) // TODO: Add to config with these as the defaults
        .expose_headers(vec![
            "Authorization",
            "Signature",
            "va-signature-chain",
            "digest",
            "Date",
            "Content-Type",
        ]) // TODO: Add to config with these as the defaults
        .allow_methods(vec!["GET", "POST"])
}

/// Any rejection will be fall in this bucket be replaced with BAD_REQUEST.
/// Resulting behaviour is that your request either succeeds or you get 400.
/// if we want more elaborate rejection handling:
/// https://github.com/seanmonstar/warp/blob/master/examples/rejections.rs
async fn _handle_rejection(e: Rejection) -> Result<impl Reply, Infallible> {
    log::info!("Upstream error: {:?}", e);
    Ok(warp::reply::with_status(
        warp::reply(),
        warp::http::StatusCode::BAD_REQUEST,
    ))
}

pub fn with_svc(svc: Service) -> impl Filter<Extract = (Service,), Error = Infallible> + Clone {
    warp::any().map(move || svc.clone())
}
pub fn with_signer(
    http_signer: HttpSigner,
) -> impl Filter<Extract = (HttpSigner,), Error = Infallible> + Clone {
    warp::any().map(move || http_signer.clone())
}
pub fn with_req(
    req: RequestService,
) -> impl Filter<Extract = (RequestService,), Error = Infallible> + Clone {
    warp::any().map(move || req.clone())
}
