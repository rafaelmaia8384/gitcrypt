use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Key, Nonce,
};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

use crate::errors::GitCryptError;
use crate::file_utils::{create_directories, decode_filename, encode_filename, get_file_extension};

pub struct GitCrypt {
    cipher: Aes256Gcm,
    password_hash: Vec<u8>,
}

impl GitCrypt {
    /// Create a new GitCrypt instance with password-derived key
    pub fn new(password: &str) -> Result<Self, GitCryptError> {
        // Derive key from password using SHA-256
        let mut hasher = Sha256::new();
        hasher.update(password.as_bytes());
        let key_bytes = hasher.finalize();

        let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
        let cipher = Aes256Gcm::new(key);

        // Store password hash for verification
        let password_hash = key_bytes.to_vec();

        Ok(GitCrypt {
            cipher,
            password_hash,
        })
    }

    /// Create a .gitcrypt verification file in the destination directory
    fn create_verification_file(&self, dest_dir: &Path) -> Result<(), GitCryptError> {
        let verification_path = dest_dir.join(".gitcrypt");

        // Create a verification string with the password hash
        let verification_content =
            format!("gitcrypt-verification:{}", hex::encode(&self.password_hash));

        fs::write(verification_path, verification_content.as_bytes())?;
        Ok(())
    }

    /// Verify password against .gitcrypt file in the source directory
    fn verify_password(&self, source_dir: &Path) -> Result<bool, GitCryptError> {
        let verification_path = source_dir.join(".gitcrypt");

        if !verification_path.exists() {
            return Err(GitCryptError::FileNotFound(
                "Verification file .gitcrypt not found. This directory may not be encrypted with gitcrypt.".to_string()
            ));
        }

        let verification_content = fs::read_to_string(verification_path)?;

        if !verification_content.starts_with("gitcrypt-verification:") {
            return Err(GitCryptError::DecryptionError(
                "Invalid .gitcrypt file format".to_string(),
            ));
        }

        let stored_hash = verification_content
            .strip_prefix("gitcrypt-verification:")
            .ok_or_else(|| {
                GitCryptError::DecryptionError("Invalid .gitcrypt file format".to_string())
            })?;

        let current_hash = hex::encode(&self.password_hash);

        Ok(stored_hash == current_hash)
    }

    /// Encrypt a single file
    pub fn encrypt_file(&self, source_path: &Path, dest_path: &Path) -> Result<(), GitCryptError> {
        // Read source file
        let plaintext = fs::read(source_path)?;

        // Generate random nonce
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

        // Encrypt the data
        let ciphertext = self
            .cipher
            .encrypt(&nonce, plaintext.as_ref())
            .map_err(|e| GitCryptError::EncryptionError(e.to_string()))?;

        // Combine nonce and ciphertext
        let mut encrypted_data = nonce.to_vec();
        encrypted_data.extend_from_slice(&ciphertext);

        // Write encrypted data to destination
        fs::write(dest_path, encrypted_data)?;

        Ok(())
    }

    /// Decrypt a single file
    pub fn decrypt_file(&self, source_path: &Path, dest_path: &Path) -> Result<(), GitCryptError> {
        // Read encrypted file
        let encrypted_data = fs::read(source_path)?;

        if encrypted_data.len() < 12 {
            return Err(GitCryptError::DecryptionError(
                "File too small to contain valid encrypted data".to_string(),
            ));
        }

        // Extract nonce and ciphertext
        let (nonce_bytes, ciphertext) = encrypted_data.split_at(12);
        let nonce = Nonce::from_slice(nonce_bytes);

        // Decrypt the data
        let plaintext = self
            .cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| GitCryptError::DecryptionError(e.to_string()))?;

        // Write decrypted data to destination
        fs::write(dest_path, plaintext)?;

        Ok(())
    }

    /// Check if a file should be skipped (e.g., .git directory or .gitcrypt file)
    fn should_skip_path(path: &Path) -> bool {
        path.components().any(|component| {
            if let std::path::Component::Normal(name) = component {
                name == ".git"
            } else {
                false
            }
        }) || path.file_name().and_then(|name| name.to_str()) == Some(".gitcrypt")
    }

    /// Check if source file is newer than destination file (for incremental encryption)
    fn is_source_newer(source: &Path, dest: &Path) -> Result<bool, GitCryptError> {
        if !dest.exists() {
            return Ok(true);
        }

        let source_modified = fs::metadata(source)?.modified()?;
        let dest_modified = fs::metadata(dest)?.modified()?;

        Ok(source_modified > dest_modified)
    }

    /// Encrypt entire directory recursively
    pub fn encrypt_directory(
        &self,
        source_dir: &Path,
        dest_dir: &Path,
    ) -> Result<(), GitCryptError> {
        if !source_dir.exists() {
            return Err(GitCryptError::FileNotFound(
                source_dir.display().to_string(),
            ));
        }

        // Create destination directory if it doesn't exist
        create_directories(dest_dir)?;

        // Check if destination already has a .gitcrypt file and verify password
        let verification_path = dest_dir.join(".gitcrypt");
        if verification_path.exists() {
            println!(
                "Found existing .gitcrypt file in destination directory. Verifying password..."
            );
            if !self.verify_password(dest_dir)? {
                return Err(GitCryptError::InvalidPassword(
                    "Incorrect password. The provided password does not match the one used for encryption in the destination directory.".to_string(),
                ));
            }
            println!("Password verified successfully!");
        } else {
            // Create verification file for new encryption
            self.create_verification_file(dest_dir)?;
        }

        let walker = WalkDir::new(source_dir).into_iter();

        for entry in walker {
            let entry = entry.map_err(|e| GitCryptError::IoError(e.to_string()))?;
            let source_path = entry.path();

            // Skip .git directories and .gitcrypt files
            if Self::should_skip_path(source_path) {
                continue;
            }

            // Calculate relative path from source directory
            let relative_path = source_path
                .strip_prefix(source_dir)
                .map_err(|e| GitCryptError::PathError(e.to_string()))?;

            if source_path.is_file() {
                // Get original extension
                let extension = get_file_extension(source_path);

                // Encode filename and path components
                let mut encoded_path = PathBuf::new();
                for component in relative_path.components() {
                    if let std::path::Component::Normal(name) = component {
                        let name_str = name.to_string_lossy();

                        // If this is a file (the last component), encode only the stem
                        if component == relative_path.components().last().unwrap()
                            && source_path.is_file()
                        {
                            // Get the file stem (name without extension) and encode it
                            let file_stem =
                                if let Some(stem) = Path::new(&name_str.to_string()).file_stem() {
                                    stem.to_string_lossy().to_string()
                                } else {
                                    name_str.to_string()
                                };
                            let encoded_name = encode_filename(&file_stem)?;
                            encoded_path.push(encoded_name);
                        } else {
                            // For directories, encode the full name
                            let encoded_name = encode_filename(&name_str.to_string())?;
                            encoded_path.push(encoded_name);
                        }
                    }
                }

                // Add original extension to encoded filename
                if let Some(ext) = extension {
                    if let Some(file_stem) = encoded_path.file_stem() {
                        let new_filename = format!("{}.{}", file_stem.to_string_lossy(), ext);
                        encoded_path.set_file_name(new_filename);
                    }
                }

                let dest_path = dest_dir.join(&encoded_path);

                // Create parent directories
                if let Some(parent) = dest_path.parent() {
                    create_directories(parent)?;
                }

                // Check if file needs updating (incremental encryption)
                if Self::is_source_newer(source_path, &dest_path)? {
                    println!("Encrypting: {}", relative_path.display());
                    self.encrypt_file(source_path, &dest_path)?;
                } else {
                    println!("Skipping (up to date): {}", relative_path.display());
                }
            }
        }

        Ok(())
    }

    /// Decrypt entire directory recursively
    pub fn decrypt_directory(
        &self,
        source_dir: &Path,
        dest_dir: &Path,
    ) -> Result<(), GitCryptError> {
        if !source_dir.exists() {
            return Err(GitCryptError::FileNotFound(
                source_dir.display().to_string(),
            ));
        }

        // Verify password before creating destination directory
        if !self.verify_password(source_dir)? {
            return Err(GitCryptError::InvalidPassword(
                "Incorrect password. The provided password does not match the one used for encryption.".to_string(),
            ));
        }

        // Create destination directory only after password verification
        create_directories(dest_dir)?;

        let walker = WalkDir::new(source_dir).into_iter();

        for entry in walker {
            let entry = entry.map_err(|e| GitCryptError::IoError(e.to_string()))?;
            let source_path = entry.path();

            // Skip .git directories and .gitcrypt files
            if Self::should_skip_path(source_path) {
                continue;
            }

            // Calculate relative path from source directory
            let relative_path = source_path
                .strip_prefix(source_dir)
                .map_err(|e| GitCryptError::PathError(e.to_string()))?;

            if source_path.is_file() {
                // Decode filename and path components
                let mut decoded_path = PathBuf::new();
                for component in relative_path.components() {
                    if let std::path::Component::Normal(name) = component {
                        let name_str = name.to_string_lossy();

                        // Separate extension from encoded name
                        let (encoded_name, extension) = if let Some(dot_pos) = name_str.rfind('.') {
                            let (name_part, ext_part) = name_str.split_at(dot_pos);
                            (name_part, Some(&ext_part[1..]))
                        } else {
                            (name_str.as_ref(), None)
                        };

                        // Decode the filename
                        let decoded_name = decode_filename(encoded_name)?;

                        // Reconstruct filename with extension only if decoded name doesn't already have it
                        let final_name = if let Some(ext) = extension {
                            // Check if decoded name already has the extension
                            if decoded_name.ends_with(&format!(".{}", ext)) {
                                decoded_name
                            } else {
                                format!("{}.{}", decoded_name, ext)
                            }
                        } else {
                            decoded_name
                        };

                        decoded_path.push(final_name);
                    }
                }

                let dest_path = dest_dir.join(&decoded_path);

                // Create parent directories
                if let Some(parent) = dest_path.parent() {
                    create_directories(parent)?;
                }

                // Check if file needs updating (incremental decryption)
                if Self::is_source_newer(source_path, &dest_path)? {
                    println!("Decrypting: {}", decoded_path.display());
                    self.decrypt_file(source_path, &dest_path)?;
                } else {
                    println!("Skipping (up to date): {}", decoded_path.display());
                }
            }
        }

        Ok(())
    }
}
