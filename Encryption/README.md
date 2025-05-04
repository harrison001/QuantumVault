# Linux AES-256 Encryption Tools

These tools provide a secure way to encrypt files using AES-256-CBC encryption with PBKDF2 key derivation. They are designed to work in tandem with the DOS AES Decryption Tool, ensuring cross-platform compatibility.

## Table of Contents
- [Overview](#overview)
- [Tools Included](#tools-included)
- [Requirements](#requirements)
- [Compilation](#compilation)
- [Usage](#usage)
- [File Format](#file-format)
- [Security Features](#security-features)
- [DOS Compatibility](#dos-compatibility)
- [Example Workflow](#example-workflow)

## Overview

This encryption toolkit allows you to:
1. Generate strong encryption keys from passwords using PBKDF2-HMAC-SHA256
2. Encrypt files with AES-256-CBC using the generated keys
3. Create encrypted files that can be later decrypted on DOS systems

## Tools Included

- **generate_key.c** - Generates AES-256 encryption keys derived from passwords
- **encrypt_file.c** - Encrypts files using the generated keys

## Requirements

- Linux system (tested on Rocky Linux)
- GCC compiler
- OpenSSL development libraries (`libssl-dev` or equivalent)

## Compilation

```bash
# Compile the key generation tool
gcc -o generate_key generate_key.c -lssl -lcrypto

# Compile the encryption tool
gcc -o encrypt_file encrypt_file.c -lssl -lcrypto
```

## Usage

### Step 1: Generate a Key

```bash
./generate_key "your_secure_password"
```

This will create a file named `aes_key.bin` containing the salt and derived key.

Sample output:
```
Password length: 14 characters
Generated Salt: 3b8a3a7e12653a639021eed902fd6160
Generated Key: 5d104a0f5c7d2eafefad177e547cf91915b3444562fc68851f9002dfe0720a7e
PBKDF2 iterations: 10000
Key successfully generated and saved to aes_key.bin
File format: [Salt(16 bytes)][Key(32 bytes)]
```

### Step 2: Encrypt a File

```bash
./encrypt_file plaintext.txt encrypted.bin
```

This will:
1. Read the previously generated key
2. Generate a random IV
3. Encrypt the file using AES-256-CBC
4. Save the encrypted file with salt and IV in the header
5. Securely delete the key file and original plaintext file

Sample output:
```
Salt: 3b8a3a7e12653a639021eed902fd6160
Key: 5d104a0f5c7d2eafefad177e547cf91915b3444562fc68851f9002dfe0720a7e
IV: a594c4b451ef54f6e8242606b5ce3fe1
Encryption completed successfully.
File format: [Salt(16 bytes)][IV(16 bytes)][Encrypted Data]
```

## File Format

The encrypted files follow this format:
```
[Salt (16 bytes)][IV (16 bytes)][Encrypted data (AES-CBC)]
```

This format is compatible with the DOS decryption tool and ensures that all necessary information for decryption is stored within the encrypted file itself.

## Security Features

- **Strong Key Derivation**: Uses PBKDF2-HMAC-SHA256 with 10,000 iterations
- **Secure Randomness**: Cryptographically secure salt and IV generation using OpenSSL
- **Key Protection**: Securely wipes keys from memory after use
- **File Security**: Automatically deletes the key file and original plaintext after encryption

## DOS Compatibility

The encrypted files are specifically designed to be decrypted using the DOS AES Decryption Tool. The file format and encryption parameters are chosen to ensure compatibility:

- 256-bit AES keys
- 128-bit IVs
- PBKDF2-HMAC-SHA256 with 10,000 iterations
- PKCS#7 padding
- CBC mode

## Example Workflow

1. **On Linux system**:
   ```bash
   # Generate key from password
   ./generate_key "my_secure_password"
   
   # Encrypt the file
   ./encrypt_file confidential.txt encrypted.bin
   
   # Transfer encrypted.bin to DOS system
   ```

2. **On DOS system**:
   ```
   # Decrypt using the same password
   combined_decrypt.exe -p my_secure_password encrypted.bin decrypted.txt
   
   # Or generate a key file on Linux and transfer it
   combined_decrypt.exe -k keyfile.bin encrypted.bin decrypted.txt
   ```

---

**Note**: Always use strong passwords and handle encrypted files securely. These tools are designed for legitimate use cases and should be used responsibly and in compliance with applicable laws and regulations. 