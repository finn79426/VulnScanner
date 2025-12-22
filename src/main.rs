mod action;
mod modules;
use anyhow::Result;
use clap::{Parser, Subcommand};
use env_logger::Env;

#[derive(Parser)]
#[command(arg_required_else_help = true)]
struct Cli {
    #[command(subcommand)]
    subcommand: SubCommand,
}

#[derive(Subcommand)]
enum SubCommand {
    Modules,
    Scan {
        #[arg(
            help = "The domain to scan",
            value_parser = |s: &str| Ok::<String, String>(s.to_lowercase())
        )]
        target: String,
    },
}

fn main() -> Result<()> {
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();

    let cli = Cli::parse();

    match &cli.subcommand {
        SubCommand::Modules => action::modules(),
        SubCommand::Scan { target } => action::scan(target)?,
    }

    Ok(())
}
