use crate::modules::HttpModule;
use crate::modules::Module;
use crate::modules::http::HttpFindings;
use async_trait::async_trait;

use anyhow::Result;
use once_cell::sync::Lazy;
use regex::RegexSet;
use reqwest::Client;

pub struct GitConfigLeakage;

static VULNERABLE_PATTERN: Lazy<RegexSet> = Lazy::new(|| {
    RegexSet::new([r#"\[branch\s+"[^"]+"\]"#]).expect("Failed to compile regex patterns")
});

impl GitConfigLeakage {
    pub fn new() -> Self {
        GitConfigLeakage
    }
}

impl Module for GitConfigLeakage {
    fn name(&self) -> String {
        String::from("http/git_config_leakage")
    }

    fn description(&self) -> String {
        String::from("Check if .git/config is publicly accessible")
    }
}

#[async_trait]
impl HttpModule for GitConfigLeakage {
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
                return Some(HttpFindings::GitConfigLeakage(url));
            }

            None
        };

        // Send HTTPS and HTTP requests to check if .env is accessible
        for schema in ["https", "http"] {
            let url = format!("{}://{}/.git/config", schema, endpoint);
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
                when.method(GET).path("/.git/config");
                then.status(200).body(r#"
                    [core]
                        bare = false
                        repositoryformatversion = 0
                        filemode = true
                        ignorecase = true
                        precomposeunicode = true
                        logallrefupdates = true
                    [branch "master"]
                        gk-last-accessed = 2025-12-17T02:06:48.391Z"#,
                );
            })
            .await;

        // Set up input arguments
        let module = GitConfigLeakage::new();
        let client = Client::builder().danger_accept_invalid_certs(true).build().unwrap();
        let endpoint = format!("{}:{}", mock_server.host(), mock_server.port());

        // Run scan
        let result = module.scan(&client, &endpoint).await.unwrap();

        // Check result
        assert!(result.is_some(), "Should return Some when pattern matched");

        if let Some(HttpFindings::GitConfigLeakage(url)) = result {
            assert_eq!(url, format!("https://{}/.git/config", endpoint));
        }
    }

    #[tokio::test]
    async fn test_scan_should_return_none_when_pattern_unmatched() {
        // Set up mock target HTTP server
        let mock_server = MockServer::start_async().await;

        // Set up input arguments
        let module = GitConfigLeakage::new();
        let client = Client::builder().danger_accept_invalid_certs(true).build().unwrap();
        let endpoint = format!("{}:{}", mock_server.host(), mock_server.port());

        // --- Case A: 404 not found ---
        mock_server.mock_async(|when, then| {
            when.method(GET).path("/.git/config");
            then.status(404);
        }).await;

        let result = module.scan(&client, &endpoint).await.unwrap();
        assert!(result.is_none(), "Should return None when server returns 404");

        // --- Case B: Soft 404 (unrelated response body) ---
        mock_server.mock_async(|when, then| {
            when.method(GET).path("/.git/config");
            then.status(200)
                .body("<html><body>Page Not Found but 200 OK</body></html>");
        }).await;

        let result = module.scan(&client, &endpoint).await.unwrap();
        assert!(result.is_none(), "Should return None when server returns 2xx with wrong response body");

    }
}
