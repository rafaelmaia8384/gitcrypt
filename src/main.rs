use clap::{Parser, Subcommand};
use std::path::PathBuf;

mod crypto;
mod errors;
mod file_utils;

use crate::crypto::GitCrypt;
use crate::errors::GitCryptError;

#[derive(Parser)]
#[command(name = "gitcrypt")]
#[command(about = "Tool to recursively encrypt/decrypt files and folders for Git repositories")]
#[command(version = "0.1.0")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Encrypt files and folders
    Encrypt {
        /// Source directory to encrypt
        #[arg(short, long)]
        source: PathBuf,
        /// Destination directory for encrypted files
        #[arg(short, long)]
        destination: PathBuf,
    },
    /// Decrypt files and folders
    Decrypt {
        /// Source directory with encrypted files
        #[arg(short, long)]
        source: PathBuf,
        /// Destination directory for decrypted files
        #[arg(short, long)]
        destination: PathBuf,
    },
}

fn main() -> Result<(), GitCryptError> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Encrypt {
            source,
            destination,
        } => {
            println!("Starting encryption process...");

            // Prompt for password
            let password = rpassword::prompt_password("Enter encryption password: ")
                .map_err(|e| GitCryptError::IoError(e.to_string()))?;

            if password.is_empty() {
                return Err(GitCryptError::InvalidPassword(
                    "Password cannot be empty".to_string(),
                ));
            }

            let gitcrypt = GitCrypt::new(&password)?;
            gitcrypt.encrypt_directory(&source, &destination)?;

            println!("Encryption completed successfully!");
        }
        Commands::Decrypt {
            source,
            destination,
        } => {
            println!("Starting decryption process...");

            // Prompt for password
            let password = rpassword::prompt_password("Enter decryption password: ")
                .map_err(|e| GitCryptError::IoError(e.to_string()))?;

            if password.is_empty() {
                return Err(GitCryptError::InvalidPassword(
                    "Password cannot be empty".to_string(),
                ));
            }

            let gitcrypt = GitCrypt::new(&password)?;
            gitcrypt.decrypt_directory(&source, &destination)?;

            println!("Decryption completed successfully!");
        }
    }

    Ok(())
}
