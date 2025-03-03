use age::{x25519::Identity, Decryptor, Encryptor};
use keyring::Entry;
use secrecy::ExposeSecret;
use std::fs;
use std::io::{Read, Write};

use crate::error::{AuthError, Result};

const SERVICE_NAME: &str = "r-auth";
const USERNAME: &str = "encryption_key";

#[derive(Default)]
pub struct Crypto;

impl Crypto {
    fn get_keyring_entry() -> Result<Entry> {
        Entry::new(SERVICE_NAME, USERNAME).map_err(|e| AuthError::Keyring(e.to_string()))
    }

    pub fn key_exists(&self) -> Result<bool> {
        let entry = Self::get_keyring_entry()?;
        Ok(entry.get_password().is_ok())
    }

    pub fn new() -> Result<Self> {
        let mut accounts_path = dirs::config_dir().ok_or(AuthError::ConfigDir)?;
        accounts_path.push("r-auth");
        fs::create_dir_all(&accounts_path).map_err(|e| {
            AuthError::StorageFile(format!("Failed to create config directory: {}", e))
        })?;

        Ok(Self)
    }

    pub fn init(&self) -> Result<()> {
        let entry = Self::get_keyring_entry()?;

        // Check if key already exists
        if entry.get_password().is_ok() {
            return Err(AuthError::KeyExists);
        }

        // Generate new key
        let key = Identity::generate();
        entry
            .set_password(key.to_string().expose_secret())
            .map_err(|e| AuthError::Keyring(e.to_string()))?;

        println!("Encryption key generated and stored securely in system keyring");
        Ok(())
    }

    fn load_key(&self) -> Result<Identity> {
        let entry = Self::get_keyring_entry()?;
        let key_data = entry
            .get_password()
            .map_err(|e| AuthError::Keyring(e.to_string()))?;

        key_data
            .parse::<Identity>()
            .map_err(|e| AuthError::KeyParse(e.to_string()))
    }

    pub fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        let key = self.load_key()?;
        let recipient = key.to_public();

        let mut encrypted = vec![];
        let encryptor = Encryptor::with_recipients(vec![Box::new(recipient)])
            .expect("Failed to create encryptor");

        let mut writer = encryptor
            .wrap_output(Box::new(&mut encrypted))
            .map_err(|e| AuthError::Encryption(e.to_string()))?;

        writer.write_all(data)?;
        writer.finish()?;

        Ok(encrypted)
    }

    pub fn decrypt(&self, encrypted_data: &[u8]) -> Result<Vec<u8>> {
        let key = self.load_key()?;

        let decryptor = match Decryptor::new(encrypted_data)? {
            Decryptor::Recipients(d) => d,
            _ => return Err(AuthError::Decryption("Invalid decryptor type".into())),
        };

        let mut decrypted = vec![];
        let mut reader = decryptor
            .decrypt(std::iter::once(&key as &dyn age::Identity))
            .map_err(|e| AuthError::Decryption(e.to_string()))?;

        reader.read_to_end(&mut decrypted)?;
        Ok(decrypted)
    }

    pub fn reset(&self) -> Result<()> {
        let entry = Self::get_keyring_entry()?;
        entry
            .delete_credential()
            .map_err(|e| AuthError::Keyring(e.to_string()))
    }
}
