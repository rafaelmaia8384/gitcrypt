use base58::{FromBase58, ToBase58};
use std::fs;
use std::path::Path;

use crate::errors::GitCryptError;

/// Encode a filename using Base58
pub fn encode_filename(filename: &str) -> Result<String, GitCryptError> {
    let encoded = filename.as_bytes().to_base58();
    Ok(encoded)
}

/// Decode a Base58 encoded filename
pub fn decode_filename(encoded_filename: &str) -> Result<String, GitCryptError> {
    let decoded_bytes = encoded_filename
        .from_base58()
        .map_err(|e| GitCryptError::Base58DecodeError(format!("{:?}", e)))?;

    let decoded_string = String::from_utf8(decoded_bytes)
        .map_err(|e| GitCryptError::Base58DecodeError(format!("Invalid UTF-8: {}", e)))?;

    Ok(decoded_string)
}

/// Get file extension from a path, preserving the original case
pub fn get_file_extension(path: &Path) -> Option<String> {
    path.extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| ext.to_string())
}

/// Create directories recursively if they don't exist
pub fn create_directories(path: &Path) -> Result<(), GitCryptError> {
    if !path.exists() {
        fs::create_dir_all(path).map_err(|e| {
            GitCryptError::DirectoryCreationFailed(format!("{}: {}", path.display(), e))
        })?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode_filename() {
        let original = "test_file.txt";
        let encoded = encode_filename(original).unwrap();
        let decoded = decode_filename(&encoded).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_encode_decode_special_chars() {
        let original = "файл с пробелами и символами!@#$%^&*()";
        let encoded = encode_filename(original).unwrap();
        let decoded = decode_filename(&encoded).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_get_file_extension() {
        let path = Path::new("test.txt");
        assert_eq!(get_file_extension(path), Some("txt".to_string()));

        let path_no_ext = Path::new("test");
        assert_eq!(get_file_extension(path_no_ext), None);

        let path_multiple_dots = Path::new("test.tar.gz");
        assert_eq!(
            get_file_extension(path_multiple_dots),
            Some("gz".to_string())
        );
    }
}
