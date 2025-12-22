mod directory_listing;
mod dotenv_disclosure;
mod git_config_leakage;
mod git_head_leakage;
pub use directory_listing::DirectoryListing;
pub use dotenv_disclosure::DotEnvDisclosure;
pub use git_config_leakage::GitConfigLeakage;
pub use git_head_leakage::GitHeadLeakage;

#[derive(Debug)]
pub enum HttpFindings {
    DotEnvDisclosure(String),
    DirectoryListing(String),
    GitConfigLeakage(String),
    GitHeadLeakage(String),
}
