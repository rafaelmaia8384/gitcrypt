# GitCrypt

A command-line tool to recursively encrypt and decrypt files and folders for secure storage in Git repositories.

## Features

- **AES-256-GCM Encryption**: Industry-standard encryption for maximum security
- **Password-based Key Derivation**: Uses SHA-256 to derive encryption keys from passwords
- **Base58 Filename Encoding**: Encrypts file and folder names while preserving original extensions
- **Incremental Encryption**: Only encrypts files that have been modified since last encryption
- **Git-aware**: Automatically excludes `.git` directories during encryption/decryption
- **Cross-platform**: Works on Windows, macOS, and Linux
- **Comprehensive Error Handling**: Clear error messages for troubleshooting

## Installation

### Prerequisites

- Rust 1.70+ (install from [rustup.rs](https://rustup.rs/))

### Build from Source

```bash
git clone https://github.com/rafaelmaia8384/gitcrypt
cd gitcrypt
cargo build --release
```

The binary will be available at `target/release/gitcrypt`

### Install Globally

```bash
cargo install --path .
```

## Usage

### Encrypt a Directory

```bash
gitcrypt encrypt --source /path/to/source --destination /path/to/encrypted
```

### Decrypt a Directory

```bash
gitcrypt decrypt --source /path/to/encrypted --destination /path/to/decrypted
```

### Example Workflow

1. **Prepare your repository:**
   ```bash
   # Your original repository
   ls my-project/
   # Output: src/ docs/ README.md .git/
   ```

2. **Encrypt for storage:**
   ```bash
   gitcrypt encrypt --source my-project --destination my-project-encrypted
   # Enter encryption password: ********
   # Encrypting: src/main.rs
   # Encrypting: docs/guide.md
   # Encrypting: README.md
   # Encryption completed successfully!
   ```

3. **Check encrypted result:**
   ```bash
   ls my-project-encrypted/
   # Output: 2NEpo7TZRRrLvaT/ 5HueCGU5RFkXJSu/ 7cVDFu8Y9X8Npqy.md
   # (Base58 encoded filenames with original extensions preserved)
   ```

4. **Store encrypted version in Git:**
   ```bash
   cd my-project-encrypted
   git init
   git add .
   git commit -m "Initial encrypted commit"
   git push origin main
   ```

5. **Decrypt when needed:**
   ```bash
   gitcrypt decrypt --source my-project-encrypted --destination my-project-restored
   # Enter decryption password: ********
   # Decrypting: src/main.rs
   # Decrypting: docs/guide.md
   # Decrypting: README.md
   # Decryption completed successfully!
   ```

## How It Works

### Encryption Process

1. **Password-based Key Derivation**: Your password is hashed using SHA-256 to create a 256-bit encryption key
2. **File Encryption**: Each file is encrypted using AES-256-GCM with a random nonce
3. **Filename Encoding**: File and folder names are encoded using Base58 to create Git-safe filenames
4. **Extension Preservation**: Original file extensions are preserved to maintain file type recognition
5. **Incremental Updates**: Only modified files are re-encrypted, saving time and resources

### Security Features

- **AES-256-GCM**: Provides both confidentiality and authenticity
- **Random Nonces**: Each file uses a unique random nonce for encryption
- **Password-based Security**: Strong key derivation from user passwords
- **No Key Storage**: Keys are derived from passwords and never stored

### File Structure

```
Original:                 Encrypted:
my-project/              my-project-encrypted/
├── src/                 ├── 2NEpo7TZRRrLvaT/
│   └── main.rs          │   └── 5HueCGU5RFkXJSu.rs
├── docs/                ├── 3Mf9KLq8XnBvGt2/
│   └── guide.md         │   └── 7cVDFu8Y9X8Npqy.md
└── README.md            └── 9QwErTyUiOpAsDf.md
```

## Command Line Options

### Global Options

- `--help`, `-h`: Show help information
- `--version`, `-V`: Show version information

### Encrypt Command

```bash
gitcrypt encrypt [OPTIONS]

Options:
  -s, --source <SOURCE>          Source directory to encrypt
  -d, --destination <DESTINATION> Destination directory for encrypted files
  -h, --help                     Print help
```

### Decrypt Command

```bash
gitcrypt decrypt [OPTIONS]

Options:
  -s, --source <SOURCE>          Source directory with encrypted files
  -d, --destination <DESTINATION> Destination directory for decrypted files
  -h, --help                     Print help
```

## Error Handling

GitCrypt provides clear error messages for common issues:

- **Invalid Password**: Wrong password during decryption
- **File Not Found**: Source directory or files don't exist
- **Permission Denied**: Insufficient permissions to read/write files
- **Disk Space**: Insufficient disk space for operation
- **Corrupted Data**: Encrypted files have been tampered with

## Best Practices

1. **Use Strong Passwords**: Choose complex passwords for better security
2. **Backup Passwords**: Store passwords securely - lost passwords mean lost data
3. **Regular Updates**: Re-encrypt repositories when files change frequently
4. **Test Decryption**: Regularly test that encrypted data can be decrypted
5. **Secure Storage**: Store encrypted repositories in secure, backed-up locations

## Limitations

- **Password Recovery**: Lost passwords cannot be recovered - all data will be inaccessible
- **Large Files**: Very large files may require significant memory during encryption/decryption
- **Binary Compatibility**: Encrypted files are not readable without decryption

## Development

### Running Tests

```bash
cargo test
```

### Code Coverage

```bash
cargo install cargo-tarpaulin
cargo tarpaulin --out html
```

### Linting

```bash
cargo clippy -- -D warnings
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Ensure all tests pass
6. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Security Notice

This tool is designed for protecting data in Git repositories. While it uses industry-standard encryption (AES-256-GCM), please ensure you:

- Use strong, unique passwords
- Keep passwords secure and backed up
- Regularly update your encryption practices
- Test your backup and recovery procedures

**Note**: The developers are not responsible for data loss due to forgotten passwords or corrupted encrypted data. 