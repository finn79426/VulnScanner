pub mod http;
mod subdomain;

use std::vec;

use crate::modules::http::HttpFindings;
use anyhow::Result;
use async_trait::async_trait;
use reqwest::Client;

pub trait Module {
    fn name(&self) -> String;
    fn description(&self) -> String;
}

#[async_trait]
pub trait HttpModule: Module {
    async fn scan(&self, http_client: &Client, endpoint: &str) -> Result<Option<HttpFindings>>;
}

#[async_trait]
pub trait SubdomainModule: Module {
    async fn enumerate(&self, domain: &str) -> Result<Vec<String>>;
}

pub fn http_modules() -> Vec<Box<dyn HttpModule>> {
    vec![
        Box::new(http::DirectoryListing::new()),
        Box::new(http::DotEnvDisclosure::new()),
        Box::new(http::GitConfigLeakage::new()),
        Box::new(http::GitHeadLeakage::new()),
    ]
}

pub fn subdomain_modules() -> Vec<Box<dyn SubdomainModule>> {
    vec![
        Box::new(subdomain::CrtSh::new()),
        Box::new(subdomain::WebArchive::new()),
    ]
}
