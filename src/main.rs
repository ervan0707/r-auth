//! R-Auth: A TOTP Authentication Implementation
//!
//! This crate implements the following RFCs:
//! - [RFC 6238](https://datatracker.ietf.org/doc/html/rfc6238) - TOTP: Time-Based One-Time Password Algorithm
//! - [RFC 4226](https://datatracker.ietf.org/doc/html/rfc4226) - HOTP: HMAC-Based One-Time Password Algorithm
//! - [RFC 4648](https://datatracker.ietf.org/doc/html/rfc4648) - Base-N Encodings

use clap::{Parser, Subcommand};

mod authenticator;
mod crypto;
mod error;
mod totp;
use std::io::{stdin, stdout, Write};

use crate::error::Result;

#[derive(Parser)]
#[command(
    name = env!("CARGO_PKG_NAME"),
    author = env!("CARGO_PKG_AUTHORS"),
    version = env!("CARGO_PKG_VERSION"),
    about = env!("CARGO_PKG_DESCRIPTION"),
    long_about = None,
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize the authenticator with a new encryption key
    Init,
    /// Add a new account
    Add {
        name: String,
        #[arg(required = false)]
        secret: Option<String>,
    },
    /// Remove an account
    Remove { name: String },
    /// List all accounts
    List,
    /// Show live TOTP codes
    Show,
    /// Get code for a specific account
    Code { name: String },
    /// Reset everything - removes encryption key and all accounts (dangerous!)
    Reset,
}

fn confirm_reset() -> bool {
    print!("WARNING: This will delete all accounts and the encryption key.\nThis action cannot be undone. Are you sure? (y/N): ");
    stdout().flush().unwrap();

    let mut input = String::new();
    stdin().read_line(&mut input).unwrap();

    input.trim().eq_ignore_ascii_case("y")
}

fn main() {
    let cli = Cli::parse();
    if let Err(e) = run(cli) {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}

fn run(cli: Cli) -> Result<()> {
    match cli.command {
        Commands::Init => {
            let crypto = crypto::Crypto::new()?;
            crypto.init()?;
            println!("Initialization complete - encryption key generated successfully");
            Ok(())
        }
        _ => {
            let mut authenticator = authenticator::TOTPAuthenticator::new("accounts.json")?;

            match cli.command {
                Commands::Init => unreachable!(),
                Commands::Add { name, secret } => {
                    authenticator.add_account(&name, secret.as_deref())?;
                    println!("Account '{}' added successfully!", name);
                    Ok(())
                }
                Commands::Remove { name } => {
                    if authenticator.remove_account(&name) {
                        println!("Account '{}' removed successfully", name);
                    } else {
                        println!("Account '{}' not found", name);
                    }
                    Ok(())
                }
                Commands::List => {
                    let accounts = authenticator.list_accounts();
                    if accounts.is_empty() {
                        println!("No accounts registered");
                    } else {
                        println!("\nRegistered accounts:");
                        for account in accounts {
                            println!("- {}", account);
                        }
                    }
                    Ok(())
                }
                Commands::Show => {
                    println!("Press Ctrl+C to exit");
                    authenticator.show_codes()
                }
                Commands::Code { name } => {
                    match authenticator.get_code(&name) {
                        Some(code) => println!("Code for {}: {}", name, code),
                        None => println!("Account '{}' not found", name),
                    }
                    Ok(())
                }

                Commands::Reset => {
                    if !confirm_reset() {
                        println!("Reset cancelled");
                        return Ok(());
                    }

                    // Create authenticator instance to get storage path
                    if let Ok(authenticator) =
                        authenticator::TOTPAuthenticator::new("accounts.json")
                    {
                        authenticator.reset()?;
                    }

                    // Reset crypto key
                    let crypto = crypto::Crypto::new()?;
                    if crypto.key_exists()? {
                        crypto.reset()?;
                    }

                    println!("Reset complete - all data has been cleared");
                    Ok(())
                }
            }
        }
    }
}
