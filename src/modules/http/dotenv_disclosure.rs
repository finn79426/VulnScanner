use crate::modules::HttpModule;
use crate::modules::Module;
use crate::modules::http::HttpFindings;
use async_trait::async_trait;

use anyhow::Result;
use reqwest::Client;
use reqwest::header::CONTENT_TYPE;

pub struct DotEnvDisclosure;

impl DotEnvDisclosure {
    pub fn new() -> Self {
        DotEnvDisclosure
    }
}

impl Module for DotEnvDisclosure {
    fn name(&self) -> String {
        String::from("http/dotenv_disclosure")
    }

    fn description(&self) -> String {
        String::from("Check if .env is publicly accessible")
    }
}

#[async_trait]
impl HttpModule for DotEnvDisclosure {
    async fn scan(&self, http_client: &Client, endpoint: &str) -> Result<Option<HttpFindings>> {
        // A checker function:
        // Return `HttpFindings(url)` if the following conditions are ALL met:
        //   HTTP 2xx
        //   Response size < 10KB
        //   Content-Type == text/plain
        let checker = |url: String| async {
            let resp = &http_client.get(&url).send().await.ok()?;

            if !resp.status().is_success() {
                return None;
            }

            if resp.content_length().unwrap_or(0) > 10_000 {
                return None;
            }

            if let Some(content_type) = resp.headers().get(CONTENT_TYPE) && content_type.to_str().unwrap_or("") != "text/plain" {
                return None;
            }

            Some(HttpFindings::DotEnvDisclosure(url))
        };

        // Send HTTPS and HTTP requests to check if .env is accessible
        for schema in ["https", "http"] {
            let url = format!("{}://{}/.env", schema, endpoint);
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
                when.method(GET).path("/.env");
                then.status(200)
                    .header("Content-Type", "text/plain")
                    .body("DB_PASSWORD=123456");
            })
            .await;

        // Set up input arguments
        let module = DotEnvDisclosure::new();
        let client = Client::builder()
            .danger_accept_invalid_certs(true)
            .build()
            .unwrap();
        let endpoint = format!("{}:{}", mock_server.host(), mock_server.port());

        // Run scan
        let result = module.scan(&client, &endpoint).await.unwrap();

        // Check result
        assert!(result.is_some(), "Should return Some when pattern matched");

        if let Some(HttpFindings::DotEnvDisclosure(url)) = result {
            assert_eq!(url, format!("https://{}/.env", endpoint));
        }
    }

    #[tokio::test]
    async fn test_scan_should_return_none_when_pattern_unmatched() {
        // Set up mock target HTTP server
        let mock_server = MockServer::start_async().await;

        // Set up input arguments
        let module = DotEnvDisclosure::new();
        let client = Client::builder()
            .danger_accept_invalid_certs(true)
            .build()
            .unwrap();
        let endpoint = format!("{}:{}", mock_server.host(), mock_server.port());

        // --- Case A: 404 not found ---
        mock_server
            .mock_async(|when, then| {
                when.method(GET).path("/.env");
                then.status(404);
            })
            .await;

        let result = module.scan(&client, &endpoint).await.unwrap();
        assert!(
            result.is_none(),
            "Should return None when server returns 404"
        );

        // --- Case B: Soft 404 (MIME Type unmatched) ---
        mock_server
            .mock_async(|when, then| {
                when.method(GET).path("/.env");
                then.status(200)
                    .header("Content-Type", "text/html")
                    .body("<html><body>Page Not Found but 200 OK</body></html>");
            })
            .await;

        let result = module.scan(&client, &endpoint).await.unwrap();
        assert!(
            result.is_none(),
            "Should return None when server returns 2xx with wrong MIME Type"
        );

        // --- Case C: Response body oversized ---
        mock_server
            .mock_async(|when, then| {
                when.method(GET).path("/.env");
                then.status(200)
                    .header("Content-Type", "text/plain")
                    .body("Honeypot".repeat(2000));
            })
            .await;

        let result = module.scan(&client, &endpoint).await.unwrap();
        assert!(
            result.is_none(),
            "Should return None when server returns 2xx with large response body"
        );
    }
}
