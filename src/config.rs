use anyhow::{Error, Result};

#[derive(Clone, Debug)]
pub struct Config {
    pub port: u16,
    pub backend_url: String,
    pub forwarded_for: String,
    pub authenticate: bool,
    /// CORS allow origin setting
    pub allow_origin: Option<String>,
}

const ENV_BACKEND_URL: &str = "SAWTOOTH_REST_URI";
const ENV_PORT: &str = "PORT";
const ENV_HOST: &str = "HOST";
const ENV_AUTHENTICATE: &str = "AUTHENTICATE";
const ENV_ALLOW_ORIGIN: &str = "ACCESS_CONTROL_ALLOW_ORIGIN";
const DEFAULT_PORT: u16 = 3030;
const DEFAULT_HOST: &str = "localhost";

impl Config {
    pub fn new() -> Result<Config> {
        let port = std::env::var(ENV_PORT)
            .ok()
            .map_or(Ok(DEFAULT_PORT), |env_val| env_val.parse::<u16>())?;

        let host = std::env::var(ENV_HOST)
            .ok()
            .map_or(Ok(DEFAULT_HOST.to_string()), Ok)
            .map_err(|_: &str| env_not_found(ENV_HOST))?;

        let backend_url =
            std::env::var(ENV_BACKEND_URL).map_err(|_| env_not_found(ENV_BACKEND_URL))?;

        let allow_origin = std::env::var(ENV_ALLOW_ORIGIN).ok();

        let authenticate = std::env::var(ENV_AUTHENTICATE)
            .ok()
            .map_or(Ok(true), |env_val| env_val.parse::<bool>())?;

        let forwarded_for = host;
        Ok(Config {
            port,
            backend_url,
            forwarded_for,
            authenticate,
            allow_origin,
        })
    }
}

fn env_not_found(var: &str) -> Error {
    panic!("config: {} env var not found", var)
}
