use anyhow::Result;
use std::{sync::Arc, time::Duration};
use ureq::Agent;

use crate::config::Config;

#[derive(Debug, Clone)]
pub struct Service {
    pub config: Arc<Config>,
    pub agent: Agent,
}

impl Service {
    pub fn new() -> Result<Service> {
        // wrap Config in Arc for safe reference sharing across threads
        // instead of piling duplicates on the heap
        let config = Arc::new(Config::new()?);
        info!("backend at: {}", config.backend_url);
        // Note that Agent uses Arc internally so it will safely
        // be shared between threads
        let agent: Agent = ureq::AgentBuilder::new()
            .timeout_read(Duration::from_secs(5))
            .timeout_write(Duration::from_secs(5))
            .build();

        Ok(Service { agent, config })
    }
}
