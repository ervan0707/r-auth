use crossterm::{
    cursor, execute,
    terminal::{Clear, ClearType},
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::stdout;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::error::{AuthError, Result};
use crate::totp::TOTP;

use crate::crypto::Crypto;

#[derive(Serialize, Deserialize)]
pub struct TOTPAuthenticator {
    storage_file: String,
    accounts: HashMap<String, String>,
    #[serde(skip)]
    crypto: Crypto,
}

impl TOTPAuthenticator {
    fn get_storage_path(filename: &str) -> Result<PathBuf> {
        let mut storage_path = dirs::config_dir().ok_or(AuthError::ConfigDir)?;
        storage_path.push("r-auth");
        std::fs::create_dir_all(&storage_path).map_err(|e| {
            AuthError::StorageFile(format!("Failed to create config directory: {}", e))
        })?;
        storage_path.push(filename);
        Ok(storage_path)
    }

    pub fn new(filename: &str) -> Result<Self> {
        let crypto = Crypto::new()?;

        if !crypto.key_exists()? {
            return Err(AuthError::KeyNotFound);
        }

        let storage_path = Self::get_storage_path(filename)?;
        let storage_file = storage_path
            .to_str()
            .ok_or_else(|| AuthError::StorageFile("Invalid path for storage file".to_string()))?
            .to_string();

        let accounts = Self::load_accounts(&storage_file, &crypto)?;
        Ok(Self {
            storage_file,
            accounts,
            crypto,
        })
    }

    fn load_accounts(storage_file: &str, crypto: &Crypto) -> Result<HashMap<String, String>> {
        match File::open(storage_file) {
            Ok(mut file) => {
                let mut encrypted = Vec::new();
                file.read_to_end(&mut encrypted).map_err(|e| {
                    AuthError::StorageFile(format!("Failed to read storage: {}", e))
                })?;

                if encrypted.is_empty() {
                    return Ok(HashMap::new());
                }

                let decrypted = crypto.decrypt(&encrypted)?;
                let contents = String::from_utf8(decrypted)
                    .map_err(|e| AuthError::InvalidStorage(format!("Invalid UTF-8: {}", e)))?;

                serde_json::from_str(&contents)
                    .map_err(|e| AuthError::InvalidStorage(format!("Invalid JSON: {}", e)))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(HashMap::new()),
            Err(e) => Err(AuthError::StorageFile(format!(
                "Failed to open storage: {}",
                e
            ))),
        }
    }

    fn save_accounts(&self) -> Result<()> {
        let contents = serde_json::to_string_pretty(&self.accounts)
            .map_err(|e| AuthError::InvalidStorage(format!("Failed to serialize: {}", e)))?;

        let encrypted = self.crypto.encrypt(contents.as_bytes())?;

        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&self.storage_file)
            .map_err(|e| AuthError::StorageFile(format!("Failed to open for writing: {}", e)))?;

        file.write_all(&encrypted)
            .map_err(|e| AuthError::StorageFile(format!("Failed to write: {}", e)))?;

        Ok(())
    }

    pub fn add_account(&mut self, name: &str, secret: Option<&str>) -> Result<String> {
        // Validate name is not empty
        if name.trim().is_empty() {
            return Err(AuthError::InvalidSecret(
                "Account name cannot be empty".into(),
            ));
        }

        let secret = secret
            .map(String::from)
            .unwrap_or_else(Self::generate_secret);

        // Validate secret by attempting to create TOTP
        let totp = TOTP::new(&secret)?;
        totp.now()?;

        self.accounts.insert(name.to_string(), secret.clone());
        self.save_accounts()?;

        // Generate QR code
        let uri = totp.provisioning_uri(name, "CLI Authenticator");
        qr2term::print_qr(uri.as_bytes()).map_err(|e| AuthError::QrCode(e.to_string()))?;

        Ok(secret)
    }

    /// Generates a random secret key
    /// The secret is encoded using Base32 as specified in [RFC 4648](https://datatracker.ietf.org/doc/html/rfc4648#section-6)
    fn generate_secret() -> String {
        let mut rng = rand::thread_rng();
        let mut bytes = [0u8; 20];
        rng.fill_bytes(&mut bytes);
        base32::encode(base32::Alphabet::RFC4648 { padding: true }, &bytes)
    }

    pub fn remove_account(&mut self, name: &str) -> bool {
        if self.accounts.remove(name).is_some() {
            self.save_accounts().unwrap_or(());
            true
        } else {
            false
        }
    }

    pub fn get_code(&self, name: &str) -> Option<String> {
        self.accounts
            .get(name)
            .and_then(|secret| TOTP::new(secret).and_then(|totp| totp.now()).ok())
    }

    pub fn list_accounts(&self) -> Vec<String> {
        self.accounts.keys().cloned().collect()
    }

    pub fn show_codes(&self) -> Result<()> {
        let mut stdout = stdout();

        loop {
            execute!(stdout, Clear(ClearType::All), cursor::MoveTo(0, 0))?;

            println!("Current TOTP Codes:");
            println!("-------------------");

            for name in self.accounts.keys() {
                if let Some(code) = self.get_code(name) {
                    println!("{}: {}", name, code);
                }
            }

            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();
            let remaining = 30 - (now % 30);

            println!("\nRefreshing in {} seconds... (Ctrl+C to exit)", remaining);

            thread::sleep(Duration::from_secs(1));
        }
    }

    pub fn reset(&self) -> Result<()> {
        // Delete the storage file
        if std::path::Path::new(&self.storage_file).exists() {
            std::fs::remove_file(&self.storage_file).map_err(|e| {
                AuthError::StorageFile(format!("Failed to delete storage file: {}", e))
            })?;
        }
        Ok(())
    }
}
