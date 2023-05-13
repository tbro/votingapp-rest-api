use crate::http_signer::HttpSigner;
use crate::request::RequestService;
use std::convert::Infallible;
use warp::http::Response;
use warp::hyper;
use warp::path::FullPath;
use warp::Reply;

/// get api specification
pub async fn get_spec(reply: warp::filters::fs::File) -> Result<String, Infallible> {
    let (_parts, body) = reply.into_response().into_parts();
    // body here is a stream so we need to gather it up in order
    // to sign the message.
    let bytes = hyper::body::to_bytes(body).await.unwrap();
    let s = String::from_utf8(bytes.into_iter().collect()).unwrap();
    Ok(s)
}

/// get api version
pub async fn get_version() -> Result<String, Infallible> {
    let version = env!("CARGO_PKG_VERSION");
    Ok(version.to_string())
}

/// sign response
pub async fn sign(
    reply: impl Reply,
    path: FullPath,
    method: warp::http::Method,
    signer: HttpSigner,
) -> Result<Response<String>, Infallible> {
    log::info!("sign, full path: {:?}", &path);
    println!("sign, full path: {:?}", &path);
    let response = reply.into_response();

    let (mut parts, body) = response.into_parts();
    let req_target = RequestService::req_target(path.as_str(), Some(method.as_str()));
    let bytes = hyper::body::to_bytes(body).await.unwrap();
    parts
        .headers
        .extend(signer.sign_response(req_target, &bytes));

    let s = String::from_utf8(bytes.into_iter().collect()).unwrap();
    let res = Response::from_parts(parts, s);
    Ok(res)
}

/// fetch from backend
pub async fn fetch(uri: String, req: RequestService) -> Result<impl warp::Reply, warp::Rejection> {
    req.fetch(&uri).await
}

/// post to backend
pub async fn post(
    uri: String,
    body: bytes::Bytes,
    req: RequestService,
) -> Result<impl warp::Reply, warp::Rejection> {
    req.post(&uri, body).await
}
