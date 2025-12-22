use crate::modules::HttpModule;
use crate::modules::Module;
use crate::modules::http::HttpFindings;
use async_trait::async_trait;

use anyhow::Result;
use once_cell::sync::Lazy;
use regex::RegexSet;
use reqwest::Client;

pub struct DirectoryListing;

static VULNERABLE_PATTERN: Lazy<RegexSet> = Lazy::new(|| {
    RegexSet::new([
        r"(?i)Index of /.*",                                      // Apache/Nginx
        r"(?i)directory listing - /.*",                           // Microsoft IIS
        r"(?i)Directory Listing For /.*",                         // Apache Tomcat
        r"(?i)Parent Directory",                                  // HTML Link
        r#"(?i)<A HREF=["']?/[^>]*>\[To Parent Directory\]</A>"#, // Old IIS
    ])
    .expect("Failed to compile regex patterns, please check the syntax")
});

impl DirectoryListing {
    pub fn new() -> Self {
        DirectoryListing
    }
}

impl Module for DirectoryListing {
    fn name(&self) -> String {
        String::from("http/directory_listing")
    }

    fn description(&self) -> String {
        String::from("Check if directory listing is publicly accessible")
    }
}

#[async_trait]
impl HttpModule for DirectoryListing {
    async fn scan(&self, http_client: &Client, endpoint: &str) -> Result<Option<HttpFindings>> {
        let checker = |url: String| async {
            let client = http_client.clone();
            let resp = client.get(&url).send().await.ok()?;

            if !resp.status().is_success() {
                return None;
            }

            let body = resp.text().await.ok()?;

            let is_vulnerable =
                tokio::task::spawn_blocking(move || VULNERABLE_PATTERN.is_match(&body))
                    .await
                    .ok()?;

            if is_vulnerable {
                return Some(HttpFindings::DirectoryListing(url));
            }

            None
        };

        // Send HTTPS and HTTP requests to check if .env is accessible
        for schema in ["https", "http"] {
            let url = format!("{}://{}/", schema, endpoint);
            if let Some(finding) = checker(url).await {
                return Ok(Some(finding));
            }
        }

        Ok(None)
    }
}

mod tests {
    use super::*;
    use httpmock::prelude::*;

    #[tokio::test]
    async fn test_scan_should_return_some_when_pattern_matched() {
        // Set up mock target HTTP server and its response
        let mock_server = MockServer::start_async().await;

        mock_server
            .mock_async(|when, then| {
                when.method(GET).path("/");
                then.status(200)
                    .body("<html><body>Index of /</body></html>");
            })
            .await;

        // Set up input arguments
        let module = DirectoryListing::new();
        let client = Client::builder()
            .danger_accept_invalid_certs(true)
            .build()
            .unwrap();
        let endpoint = format!("{}:{}", mock_server.host(), mock_server.port());

        // Run scan
        let result = module.scan(&client, &endpoint).await.unwrap();

        // Check result
        assert!(result.is_some());

        if let Some(HttpFindings::DirectoryListing(url)) = result {
            assert_eq!(url, format!("https://{}/", endpoint));
        }
    }

    #[tokio::test]
    async fn test_scan_should_return_none_when_pattern_unmatched() {
        // Set up mock target HTTP server
        let mock_server = MockServer::start_async().await;

        // Set up input arguments
        let module = DirectoryListing::new();
        let client = Client::builder()
            .danger_accept_invalid_certs(true)
            .build()
            .unwrap();
        let endpoint = format!("{}:{}", mock_server.host(), mock_server.port());

        // --- Case A: 404 not found ---
        mock_server
            .mock_async(|when, then| {
                when.method(GET).path("/");
                then.status(404);
            })
            .await;
        let result = module.scan(&client, &endpoint).await.unwrap();
        assert!(
            result.is_none(),
            "Should return None when server returns 404"
        );

        // --- Case B: No directory listing ---
        mock_server
            .mock_async(|when, then| {
                when.method(GET).path("/");
                then.status(200).body("Any response body");
            })
            .await;
        let result = module.scan(&client, &endpoint).await.unwrap();
        assert!(
            result.is_none(),
            "Should return None when response body doesn't contain directory listing"
        );
    }
}
