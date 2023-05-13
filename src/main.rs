use anyhow::Result;
use warp::Filter;
mod certs;
mod config;
mod filters;
mod handlers;
mod http_signer;
mod ledger_addresses;
mod parse;
mod request;
mod response;
mod sawtooth;
mod service;
mod votingapp;

use http_signer::HttpSigner;
use service::Service;

#[macro_use]
extern crate log;

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();
    info!("starting up");

    let service = Service::new()?;
    let http_signer = HttpSigner::new()?;

    let api = filters::api(service.clone(), http_signer);

    let routes = api.with(warp::log("http"));

    info!("starting server on: 0.0.0.0:{}", service.config.port);
    let (_addr, server) = warp::serve(routes)
        .tls()
        .cert_path("tls/cert.pem")
        .key_path("tls/key.rsa")
        .bind_with_graceful_shutdown(([0, 0, 0, 0], service.config.port), async {
            tokio::signal::ctrl_c()
                .await
                .expect("Failed to listen for CRTL+c");
            log::info!("Shutting down server");
        });

    server.await;

    Ok(())
}
