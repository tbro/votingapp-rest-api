use crate::filters::{with_req, with_signer, with_svc};
use crate::handlers::{fetch, post};
use crate::http_signer::HttpSigner;
use crate::request::RequestService;
use crate::service::Service;
use std::collections::HashMap;
use warp::path::FullPath;
use warp::{Filter, Rejection, Reply};

use super::handlers::{authenticate, fmt_query_uri};

/// all the gets.
pub fn gets(
    req: RequestService,
    svc: Service,
) -> impl Filter<Extract = (impl Reply,), Error = Rejection> + Clone {
    warp::get()
        .and(get_query(svc.clone()))
        .or(get_index(svc))
        .unify()
        .and(with_req(req))
        .and_then(fetch)
}

/// all the posts.
pub fn posts(
    req: RequestService,
    signer: HttpSigner,
    svc: Service,
) -> impl Filter<Extract = (impl Reply,), Error = Rejection> + Clone {
    warp::post()
        .and(status_post(svc.clone()))
        .or(auth(svc, signer))
        .unify()
        .and(warp::body::bytes())
        .and(with_req(req))
        .and_then(post)
}

/// Matches any GET request for path /batch_statuses and passes path param
/// along with Service and HttpSigner to the handler.
fn status_post(svc: Service) -> impl Filter<Extract = (String,), Error = Rejection> + Clone {
    warp::path("batch_statuses").and(query_uri(svc))
}

/// Matches any POST request to path /batches with `authentication`
/// and `va-signature-chain` headers. Passes request body and authentication
/// headers along with Service and HttpSigner to the handler.
fn auth(
    svc: Service,
    signer: HttpSigner,
) -> impl Filter<Extract = (String,), Error = Rejection> + Clone {
    warp::path("batches")
        .and(warp::post())
        .and(warp::header::optional::<String>("authorization"))
        .and(warp::header::optional::<String>("va-signature-chain"))
        .and(with_svc(svc.clone()))
        .and(with_signer(signer))
        .and_then(authenticate)
        .and(warp::path::full())
        .map(move |_: String, path: FullPath| {
            log::info!("post path: {:?}", &path);
            let req_uri = format!("{}{}", svc.config.backend_url, path.as_str());
            log::info!("post req_uri: {:?}", &req_uri);
            req_uri
        })
}

fn query_uri(svc: Service) -> impl Filter<Extract = (String,), Error = Rejection> + Clone {
    warp::any()
        .and(warp::path::full())
        .and(warp::query::<HashMap<String, String>>())
        .and(with_svc(svc))
        .and_then(fmt_query_uri)
}

fn get_query(svc: Service) -> impl Filter<Extract = (String,), Error = Rejection> + Clone {
    warp::path("state")
        .or(warp::path("batch_statuses"))
        .unify()
        .or(warp::path("batches"))
        .unify()
        .or(warp::path("transactions"))
        .unify()
        .and(query_uri(svc))
}

fn get_index(svc: Service) -> impl Filter<Extract = (String,), Error = Rejection> + Clone {
    warp::path("state")
        .or(warp::path("batches"))
        .unify()
        .or(warp::path("transactions"))
        .unify()
        .and(warp::path::full())
        .map(move |path: FullPath| {
            log::debug!("get path: {:?}", &path);
            let endpoint = if let Some(no_slash) = path.as_str().strip_suffix('/') {
                format!("{}{}", svc.config.backend_url, no_slash)
            } else {
                format!("{}{}", svc.config.backend_url, path.as_str())
            };

            endpoint
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    static CVR_ADDR: &str =
        "e5c1b205001d2d07dc874dee62374c677ec0da5d44af907300d48d59b7053eedc74612";

    static CVR_KEY: &str = "xpub6A8xBrTys98jLevnXUgN2YfjuzX36E5pfjQQT8PfZtJ7JY2noYDXVYQyqtJhUJJS9ezC6uaUZ5iWAJMBddKBHouKa7omUW6BdV4R9g6qLNZ";

    const SAWTOOTH_REST_URI: &str = "SAWTOOTH_REST_URI";

    #[tokio::test]
    async fn test_get_state() {
        std::env::set_var(SAWTOOTH_REST_URI, "http://rest-api:8008");
        let svc = Service::new().unwrap();
        let filter = get_query(svc.clone());
        let slash = ["/state/"].concat();
        let no_slash = ["/state"].concat();
        let param = ["/state/123"].concat();
        let bad_root = ["/elections/123"].concat();
        let query = ["/state?", "address=", CVR_ADDR].concat();
        println!("{}", slash);
        let state_value = warp::test::request()
            .path(&query)
            .filter(&filter)
            .await
            .unwrap();
        let expected = [svc.config.backend_url.as_str(), query.as_str()].concat();
        // assert_eq!(state_value.into_response(), expected);
        // Or simply test if a request matches (doesn't reject).
        assert!(warp::test::request().path(&slash).matches(&filter).await);
        assert!(warp::test::request().path(&slash).matches(&filter).await);
        assert!(warp::test::request().path(&no_slash).matches(&filter).await);
        assert!(warp::test::request().path(&param).matches(&filter).await);
        assert!(!warp::test::request().path(&bad_root).matches(&filter).await);
    }
    #[tokio::test]
    async fn test_get_batch_statuses() {
        std::env::set_var(SAWTOOTH_REST_URI, "http://rest-api:8008");
        let svc = Service::new().unwrap();
        let filter = get_query(svc.clone());
        let id = "fe4cce60b3f6d6d6ba898f712eb762184afb2b3f9835408183b687a9cae999672f61c1d1c9ce01db847e54352b42839e7caf44df9c06686a0636836497bd15a5";
        let query = ["/batch_statuses?", "id=", id].concat();
        let batch_statuses = ["/batch_statuses"].concat();
        let batch_statuses_value = warp::test::request()
            .path(&query)
            .filter(&filter)
            .await
            .unwrap();
        let expected = [svc.config.backend_url.as_str(), query.as_str()].concat();
        // assert_eq!(batch_statuses_value.to_string(), expected);
        assert!(
            warp::test::request()
                .path(&batch_statuses)
                .matches(&filter)
                .await
        );
    }

    #[tokio::test]
    async fn test_get_index() {
        std::env::set_var(SAWTOOTH_REST_URI, "http://rest-api:8008");
        let svc = Service::new().unwrap();
        let filter = get_index(svc.clone());
        let slash = ["/state/"].concat();
        let query = ["/state/", CVR_ADDR].concat();
        let state_value = warp::test::request()
            .path(&query)
            .filter(&filter)
            .await
            .unwrap();
        println!("query {}", query);
        let expected = [svc.config.backend_url.as_str(), query.as_str()].concat();
        // assert_eq!(state_value.to_string(), expected);
        assert!(warp::test::request().path(&slash).matches(&filter).await);
    }
}
