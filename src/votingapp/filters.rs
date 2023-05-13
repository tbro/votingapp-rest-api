use crate::filters::with_req;
use crate::handlers::fetch;
use crate::ledger_addresses::LedgerAddress;
use crate::request::RequestService;
use crate::service::Service;
use std::convert::Infallible;
use warp::{Filter, Rejection, Reply};

use crate::votingapp::handlers::{
    get_ballot_style_list, get_ballot_style_lists, get_cast_many, get_election, get_elections,
    get_hdap,
};

pub fn filters(
    svc: Service,
    req: RequestService,
) -> impl Filter<Extract = (impl Reply,), Error = Rejection> + Clone {
    let addr = LedgerAddress::new();

    let election_filters = cast_by_hdap(addr.clone())
        .or(cast_many(addr.clone()))
        .unify()
        .or(all_elections(addr.clone()))
        .unify()
        .or(election(addr.clone()))
        .unify()
        .or(all_ballot_style_lists(addr.clone()))
        .unify()
        .or(ballot_style_list(addr))
        .unify()
        .map(move |address: String| {
            let req_uri = format!("{}/state?address={}", svc.config.backend_url, address);
            log::info!("backend request_uri: {}", &req_uri);
            req_uri
        })
        .and(with_req(req))
        .and_then(fetch)
        .and_then(RequestService::decode);

    warp::get().and(election_filters)
}

/// handle requests for data from mobile clients
fn cast_by_hdap(
    addr: LedgerAddress,
) -> impl Filter<Extract = (String,), Error = Rejection> + Clone {
    let casted = warp::path("cast-vote-records")
        .or(warp::path("authentication-records"))
        .unify()
        .or(warp::path("cast-permissions"))
        .unify()
        .or(warp::path("ballot-style-receipts"))
        .unify()
        .or(warp::path("cast-vote-record-statuses"))
        .unify()
        .or(warp::path("voter-autographs"))
        .unify()
        .or(warp::path("voter-receipts"))
        .unify();

    warp::path("elections")
        .and(warp::path::param::<String>())
        .and(casted)
        .and(warp::path::param::<String>())
        .and(warp::path::full())
        .and(with_addr(addr))
        .and_then(get_hdap)
}

/// handle requests for data from mobile clients
fn cast_many(addr: LedgerAddress) -> impl Filter<Extract = (String,), Error = Rejection> + Clone {
    let casted = warp::path("cast-vote-records")
        .or(warp::path("authentication-records"))
        .unify()
        .or(warp::path("cast-permissions"))
        .unify()
        .or(warp::path("ballot-style-receipts"))
        .unify()
        .or(warp::path("cast-vote-record-statuses"))
        .unify()
        .or(warp::path("voter-autographs"))
        .unify()
        .or(warp::path("voter-receipts"))
        .unify();

    warp::path("elections")
        .and(warp::path::param::<String>())
        .and(casted)
        .and(warp::path::end())
        .and(warp::path::full())
        .and(with_addr(addr))
        .and_then(get_cast_many)
}

/// Matches any GET request for /elections/:id/ballot-style-lists
fn all_ballot_style_lists(
    addr: LedgerAddress,
) -> impl Filter<Extract = (String,), Error = Rejection> + Clone {
    warp::path("elections")
        .and(warp::path::param::<String>())
        .and(warp::path("ballot-style-lists"))
        .and(warp::path::end())
        .and(with_addr(addr))
        .and_then(get_ballot_style_lists)
}

/// Matches any GET request for /elections/:id/ballot-style-lists
fn ballot_style_list(
    addr: LedgerAddress,
) -> impl Filter<Extract = (String,), Error = Rejection> + Clone {
    warp::path("elections")
        .and(warp::path::param::<String>())
        .and(warp::path("ballot-style-lists"))
        .and(warp::path::param::<String>())
        .and(warp::path::end())
        .and(with_addr(addr))
        .and_then(get_ballot_style_list)
}

/// Matches any GET request for /elections
fn all_elections(
    addr: LedgerAddress,
) -> impl Filter<Extract = (String,), Error = Rejection> + Clone {
    warp::path("elections")
        .and(warp::path::end())
        .and(with_addr(addr))
        .and_then(get_elections)
}

/// Matches any GET request for /elections/:id
fn election(addr: LedgerAddress) -> impl Filter<Extract = (String,), Error = Rejection> + Clone {
    warp::path("elections")
        .and(warp::path::param::<String>())
        .and(warp::path::end())
        .and(with_addr(addr))
        .and_then(get_election)
}

fn with_addr(
    addr: LedgerAddress,
) -> impl Filter<Extract = (LedgerAddress,), Error = Infallible> + Clone {
    warp::any().map(move || addr.clone())
}

#[cfg(test)]
mod tests {
    use super::*;

    static CVR_ADDR: &str =
        "e5c1b205001d2d07dc874dee62374c677ec0da5d44af907300d48d59b7053eedc74612";

    static CVR_KEY: &str = "xpub6A8xBrTys98jLevnXUgN2YfjuzX36E5pfjQQT8PfZtJ7JY2noYDXVYQyqtJhUJJS9ezC6uaUZ5iWAJMBddKBHouKa7omUW6BdV4R9g6qLNZ";

    #[tokio::test]
    async fn test_hdap() {
        let addr = LedgerAddress::new();
        let filter = cast_by_hdap(addr);
        let p = ["/elections/123/cast-vote-records/", CVR_KEY].concat();
        println!("{}", p);
        let value = warp::test::request()
            .path(&p)
            .filter(&filter)
            .await
            .unwrap();
        // println!("{:}", value);
        assert_eq!(value, CVR_ADDR);

        // Or simply test if a request matches (doesn't reject).
        assert!(warp::test::request().path(&p).matches(&filter).await);
    }
}
