use crate::modules::Module;
use crate::modules::SubdomainModule;
use async_trait::async_trait;

use anyhow::Result;
use anyhow::bail;
use reqwest::Client;
use reqwest::Url;
use serde::Deserialize;
use std::collections::HashSet;
use std::time::Duration;

pub struct WebArchive;

impl WebArchive {
    pub fn new() -> Self {
        WebArchive
    }
}

impl Module for WebArchive {
    fn name(&self) -> String {
        String::from("subdomain/webarchive")
    }

    fn description(&self) -> String {
        String::from("Use web.archive.org to enumerate subdomains")
    }
}

#[async_trait]
impl SubdomainModule for WebArchive {
    async fn enumerate(&self, domain: &str) -> Result<Vec<String>> {
        // Declare needed API response fields
        #[derive(Debug, Deserialize)]
        struct CDXResponse(Vec<Vec<String>>);

        // Query archived URLs from web.archive.org
        let http_client = Client::builder()
        .user_agent("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36")
        .timeout(Duration::from_secs(30)).build()?;
        let url = format!(
            "https://web.archive.org/cdx/search/cdx?matchType=domain&fl=original&output=json&collapse=urlkey&url={}",
            domain
        );
        let resp = http_client.get(url).send().await?;

        if !resp.status().is_success() {
            bail!(
                "Unexpected status code from web.archive.org: {}",
                resp.status()
            );
        }

        let mut entries: CDXResponse = match resp.json().await {
            Ok(entries) => entries,
            Err(e) => bail!("Failed to parse web.archive.org entries: {}", e),
        };

        // Remove the first entry: [["original"]]
        if !entries.0.is_empty() {
            entries.0.remove(0);
        }

        // Get subdomains by parsing CDX Response
        let mut subdomains: HashSet<String> = entries
            .0
            .into_iter()
            .flatten()
            .filter_map(|url| {
                Url::parse(&url)
                    .inspect_err(|_| {
                        log::error!("{} error parsing url: {}", self.name(), url);
                    })
                    .ok()
            })
            .filter_map(|url| url.host_str().map(|host| host.to_lowercase()))
            .collect();

        // Ensure parent domain `domain` is not in subdomains
        subdomains.remove(domain);

        let mut subdomains: Vec<String> = subdomains.into_iter().collect();

        subdomains.sort_unstable();

        Ok(subdomains)
    }
}
