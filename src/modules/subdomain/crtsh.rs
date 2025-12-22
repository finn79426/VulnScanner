use crate::modules::Module;
use crate::modules::SubdomainModule;
use crate::modules::async_trait;
use anyhow::Result;
use anyhow::anyhow;
use anyhow::bail;
use reqwest::Client;
use serde::Deserialize;
use std::collections::HashSet;
use std::time::Duration;

pub struct CrtSh;

impl CrtSh {
    pub fn new() -> Self {
        CrtSh
    }
}

impl Module for CrtSh {
    fn name(&self) -> String {
        String::from("subdomain/crtsh")
    }

    fn description(&self) -> String {
        String::from("Use crt.sh to enumerate subdomains")
    }
}

#[async_trait]
impl SubdomainModule for CrtSh {
    async fn enumerate(&self, domain: &str) -> Result<Vec<String>> {
        // Declare needed API response fields
        #[derive(Debug, Deserialize)]
        struct CrtShEntry {
            name_value: String,
        }

        // Query crt.sh for Certificate Transparency (CT) log entries
        let url = format!("https://crt.sh/?q=%25.{}&output=json", domain);
        let http_client = Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .unwrap();

        let resp = http_client
            .get(&url)
            .send()
            .await
            .map_err(|e| anyhow!("crt.sh connection failed (likely timeout): {}", e))?;

        if !resp.status().is_success() {
            bail!("Failed to get crt.sh entries: {}", resp.status());
        }

        // Parse CT log entries to get subdomains set
        let entries: Vec<CrtShEntry> = match resp.json().await {
            Ok(entries) => entries,
            Err(e) => bail!("Failed to parse crt.sh entries: {}", e),
        };

        let mut subdomains: HashSet<String> = entries
            .into_iter()
            .flat_map(|entry| {
                entry
                    .name_value
                    .split("\n")
                    .map(|subdomain| subdomain.trim().to_lowercase())
                    .collect::<Vec<String>>()
            })
            .filter(|subdomain| !subdomain.contains("*")) // Remove wildcard subdomains
            .collect();

        // Ensure the parent domain `domain` is not in subdomains (purify)
        subdomains.remove(domain);

        // Cast subdomains `HashSet` to `Vec<String>`
        let mut subdomains: Vec<String> = subdomains.into_iter().collect();

        subdomains.sort_unstable();

        log::info!("{}: Found {} subdomains", self.name(), subdomains.len());

        Ok(subdomains)
    }
}
