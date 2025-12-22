use crate::modules::http_modules;
use crate::modules::{self, subdomain_modules};

use anyhow::Result;
use futures::StreamExt;
use futures::future;
use futures::stream;
use hickory_resolver::TokioResolver;
use hickory_resolver::config::ResolverConfig;
use hickory_resolver::name_server::TokioConnectionProvider;
use reqwest::Client;
use std::collections::HashSet;
use std::net::SocketAddr;
use std::time::Duration;
use std::time::Instant;
use tokio::net::TcpStream;
use tokio::net::lookup_host;

const SUBDOMAIN_CONCURRENCY: usize = 20;
const DNS_CONCURRENCY: usize = 100;
const PORT_CONCURRENCY: usize = 256;
const VULNERABILITY_CONCURRENCY: usize = 100;

/// Scan a target domain
/// - Enumerate subdomains
/// - Resolve subdomains
/// - Probe open ports on resolved subdomains
/// - Scan open ports for vulnerabilities
/// - Report findings
///
/// # Arguments
/// * `target` - The domain to scan
pub fn scan(target: &str) -> Result<()> {
    struct Domain {
        name: String,
        open_ports: Vec<u16>,
    }

    log::info!("Starting scan for {}", target);

    // Build tokio runtime
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("Failed to build Tokio runtime");

    // Start a timer
    let scan_start = Instant::now();

    // Run the scan
    runtime.block_on(async {
        // Passive subdomain enumeration
        log::trace!("Trying to enumerate subdomains for {}", target);

        let subdomains: HashSet<String> = stream::iter(subdomain_modules().into_iter())
            .map(|module| async move {
                match module.enumerate(target).await {
                    Ok(new_subdomains) => Some(new_subdomains),
                    Err(e) => {
                        log::error!("Failed to enumerate subdomains with: {}", e);
                        None
                    }
                }
            })
            .buffer_unordered(SUBDOMAIN_CONCURRENCY)
            .filter_map(future::ready)
            .collect::<Vec<Vec<String>>>()
            .await
            .into_iter()
            .flatten()
            .collect();

        println!(
            "{} subdomains were found during the enumeration stage",
            subdomains.len()
        );

        // Check if subdomains are resolvable
        log::trace!("Trying to resolve discovered subdomains");

        let resolver = TokioResolver::builder_with_config(
            ResolverConfig::default(),
            TokioConnectionProvider::default(),
        )
        .build();

        let subdomains: Vec<String> = stream::iter(subdomains.into_iter())
            .map(|domain| async {
                if is_resolvable(&resolver, &domain).await {
                    Some(domain)
                } else {
                    None
                }
            })
            .buffer_unordered(DNS_CONCURRENCY)
            .filter_map(future::ready)
            .collect()
            .await;

        println!("{} subdomains were successfully resolved", subdomains.len());

        // Port scanning on resolved subdomains
        log::trace!("Trying to probe open ports on successfully resolved subdomains");

        let subdomains: Vec<Domain> = stream::iter(subdomains.into_iter())
            .map(|domain| async {
                let open_ports = scan_top100_ports(&domain).await;
                Some(Domain {
                    name: domain,
                    open_ports,
                })
            })
            .buffer_unordered(PORT_CONCURRENCY)
            .filter_map(future::ready)
            .collect()
            .await;

        log::trace!("Port scanning finished");

        for subdomain in &subdomains {
            println!("{}", subdomain.name);
            for port in &subdomain.open_ports {
                println!("\t{}", port);
            }
        }

        // Web vulnerability scanning on resolved subdomains
        log::info!("Starting Web vulnerability scanning");

        let modules = http_modules();
        let http_client = Client::builder()
            .timeout(Duration::from_secs(30))
            .danger_accept_invalid_certs(true)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("Failed to build HTTP client");

        // Prepare scan parameters (Lazy Iterator: (Module + Endpoint))
        let tasks_iter = subdomains
            .iter()
            .flat_map(|subdomain| {
                subdomain
                    .open_ports
                    .iter()
                    .map(move |port| (subdomain, port))
            })
            .flat_map(|(subdomain, port)| {
                modules.iter().map(move |module| {
                    let endpoint = format!("{}:{}", subdomain.name, port);
                    (module, endpoint)
                })
            });

        // Execute scanning tasks concurrently
        let findings: Vec<_> = stream::iter(tasks_iter)
            .map(|(module, url)| {
                let http_client = http_client.clone();
                async move { module.scan(&http_client, &url).await }
            })
            .buffer_unordered(VULNERABILITY_CONCURRENCY)
            .filter_map(|scan_result| async move {
                match scan_result {
                    Ok(Some(finding)) => Some(finding),
                    Ok(None) => None,
                    Err(err) => {
                        log::debug!("Error: {}", err);
                        None
                    }
                }
            })
            .collect()
            .await;

        log::info!("Web vulnerability scanning finished");

        for finding in findings {
            println!("{:?}", finding);
        }
    });

    // Stop the timer
    let scan_duration = scan_start.elapsed();
    println!("Scan completed in {} seconds", scan_duration.as_secs_f32());

    Ok(())
}

/// List available modules
pub fn modules() {
    let subdomain_mods = modules::subdomain_modules();
    let http_mods = modules::http_modules();

    println!("Subdomain Modules");

    for module in subdomain_mods {
        println!("\t{}: {}", module.name(), module.description());
    }

    println!("HTTP Modules");

    for module in http_mods {
        println!("\t{}: {}", module.name(), module.description());
    }
}

async fn is_resolvable(resolver: &TokioResolver, domain: &str) -> bool {
    resolver.lookup_ip(domain).await.is_ok()
}

async fn scan_top100_ports(domain: &str) -> Vec<u16> {
    // const TOP_100_PORTS: &[u16] = &[
    //     80, 23, 443, 21, 22, 25, 3389, 110, 445, 139, 143, 53, 135, 3306, 8080, 1723, 111, 995,
    //     993, 5900, 1025, 587, 8888, 199, 1720, 465, 548, 113, 81, 6001, 10000, 514, 5060, 179,
    //     1026, 2000, 8443, 8000, 32768, 554, 26, 1433, 49152, 2001, 515, 8008, 49154, 1027, 5666,
    //     646, 5000, 5631, 631, 49153, 8081, 2049, 88, 79, 5800, 106, 2121, 1110, 49155, 6000, 513,
    //     990, 5357, 427, 49156, 543, 544, 5101, 144, 7, 389, 8009, 3128, 444, 9999, 5009, 7070,
    //     5190, 3000, 5432, 1900, 3986, 13, 1029, 9, 5051, 6646, 49157, 1028, 873, 1755, 2717, 4899,
    //     9100, 119, 37,
    // ];

    const TOP_100_PORTS: &[u16] = &[
        80, 443
    ];

    async fn is_port_open(socket_addr: SocketAddr) -> bool {
        let timeout = Duration::from_secs(3);
        let connection = tokio::time::timeout(timeout, TcpStream::connect(&socket_addr));
        matches!(connection.await, Ok(Ok(_stream)))
    }

    // Resolve domain to socket address
    // - Port 1337 is a dummy port in order to satisfy the `SocketAddr` type
    let socket_addr = lookup_host(format!("{}:1337", domain))
        .await
        .expect("DNS lookup failed")
        .next()
        .expect("No IP address resolved");

    // Probe top 100 ports
    let mut open_ports: Vec<u16> = stream::iter(TOP_100_PORTS.iter().copied())
        .map(|port| {
            let socket_addr = SocketAddr::new(socket_addr.ip(), port);
            async move {
                let is_open = is_port_open(socket_addr).await;
                if is_open { Some(port) } else { None }
            }
        })
        .buffer_unordered(1)
        .filter_map(future::ready) // drop None values
        .collect()
        .await;

    open_ports.sort_unstable();

    open_ports
}
