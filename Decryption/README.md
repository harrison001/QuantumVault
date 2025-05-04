# DOS AES Decryption Tool

A powerful and secure AES-256-CBC decryption tool designed for DOS environments. This tool enables recovery of encrypted data using either password-based key derivation or direct key files.

## Table of Contents
- [Features](#features)
- [Requirements](#requirements)
- [File Format](#file-format)
- [Usage](#usage)
- [Security Features](#security-features)
- [Anti-Tampering Protection](#anti-tampering-protection)
- [Example](#example)
- [Key File Generation](#key-file-generation)
- [Troubleshooting](#troubleshooting)
- [Files](#files)

## Features

- **Dual Decryption Methods**:
  - Password-based decryption using PBKDF2-HMAC-SHA256
  - Key file decryption for enhanced security
  
- **Security Features**:
  - Strong AES-256-CBC encryption standard
  - PKCS#7 padding verification
  - Secure memory handling with multi-pass data wiping
  - Automatic system restart after decryption
  
- **Anti-Tampering Protection**:
  - Real-time interrupt vector table monitoring
  - Keyboard hook detection
  - Timer hook detection
  - Automatic termination upon security violation
  
- **User-Friendly**:
  - Clear console output with detailed progress information
  - Option to display decrypted content directly or save to file
  - Customizable restart countdown with cancellation option

- **Self-Contained Design**:
  - Minimal external dependencies
  - Embedded SHA-256 and PBKDF2 implementation
  - Compatible with 16/32-bit DOS environments

## Requirements

- DOS environment with DJGPP compiler
- Minimum 386 processor
- 8MB RAM recommended

## File Format

The tool expects encrypted files in the following format:
```
[Salt (16 bytes)][IV (16 bytes)][Encrypted data (AES-CBC)]
```

## Usage

### Compilation

```
make
```

### Running

#### Password Mode
To decrypt a file using a password:
```
combined_decrypt.exe -p your_password encrypted.bin [output_file]
```

#### Key File Mode
To decrypt a file using a key file (32 bytes):
```
combined_decrypt.exe -k keyfile.bin encrypted.bin [output_file]
```

**Note**: If no output file is specified, decrypted content will be displayed on screen.

## Security Features

- The tool uses PBKDF2-HMAC-SHA256 with 10,000 iterations for key derivation
- All sensitive data is securely wiped from memory after use
- The system automatically reboots 60 seconds after successful decryption
- The memory wiping uses three passes with different patterns (zeros, ones, random)
- No password or key information is stored persistently

## Anti-Tampering Protection

This tool includes advanced anti-tampering protection that provides real-time security monitoring during the decryption process. This feature helps protect sensitive data from interception or theft by malicious software.

### Protection Mechanisms

- **Interrupt Vector Table Monitoring**:
  - Detects modifications to critical system interrupt vectors
  - Prevents hooking of important DOS and BIOS services
  - Monitors up to 48 interrupt vectors (0x00-0x2F)

- **Keyboard Hook Detection**:
  - Monitors both hardware (INT 9h) and BIOS (INT 16h) keyboard interrupts
  - Detects keyloggers and keyboard interceptors
  - Prevents password sniffing during decryption

- **System Timer Protection**:
  - Monitors the system timer interrupt (INT 8h)
  - Detects TSR (Terminate and Stay Resident) programs that might be monitoring system activity

### Security Check Points

The anti-tampering system performs security checks at multiple critical points:

1. **Program Initialization**: Saves the initial state of system vectors
2. **Before Key Processing**: Ensures security before handling sensitive key material
3. **Before Decryption**: Verifies system integrity before starting the decryption
4. **Before Output**: Final check before displaying or saving decrypted content

Upon detecting a security violation, the tool immediately:
1. Displays a specific security error message
2. Securely wipes all sensitive data from memory
3. Aborts the decryption process
4. Returns an error code

## Example

```
combined_decrypt.exe -p mysecretpassword encrypted.bin

===== DOS AES Decryption Tool =====

Mode: Password-based decryption
Input file: encrypted.bin
Output: Screen display
File format: [Salt(16 bytes)][IV(16 bytes)][Encrypted data]
Salt: 3b8a3a7e12653a639021eed902fd6160
IV: a594c4b451ef54f6e8242606b5ce3fe1
Using password: mysecretpassword
Iterations: 10000
Derived key: 5d104a0f5c7d2eafefad177e547cf91915b3444562fc68851f9002dfe0720a7e
Successfully removed padding, final size: 1024 bytes

----- Decrypted Content -----
[Decrypted content appears here]
----------------------------

Decryption successful!

System will restart in 60 seconds...
Press Ctrl+C to cancel restart
```

### Security Violation Example

```
===== DOS AES Decryption Tool =====

Mode: Password-based decryption
Input file: encrypted.bin
Output: Screen display

Security violation detected: Keyboard interrupt (INT 9h) hooked (0x1A3B4C5D != 0x0040FFEE)
Aborting decryption for security reasons.

Decryption failed!
```

## Key File Generation

A key file should be a binary file containing exactly 32 bytes of cryptographically strong random data. You can create one using various methods:

1. Using OpenSSL (on Linux/Unix systems):
   ```
   openssl rand -out keyfile.bin 32
   ```

2. Using a secure key derivation tool to generate a key from a password and then saving it:
   ```
   # Example on Linux (using the password-based mode once and extracting the key)
   dd if=/dev/urandom bs=16 count=1 of=salt.bin
   openssl enc -aes-256-cbc -pass pass:your_strong_password -S 0x$(xxd -p salt.bin) -P | grep key | cut -d = -f 2 | xxd -r -p > keyfile.bin
   ```

Transfer the key file securely to your DOS system for use with this tool.

## Troubleshooting

### Common Issues

1. **"Cannot read salt" or "Cannot read IV"**
   - The input file is not in the expected format
   - Ensure the file has the correct structure with salt and IV

2. **"Error: Invalid padding value"**
   - The decryption was unsuccessful or the file is corrupted
   - Verify that you're using the correct password or key file

3. **"Security violation detected"**
   - A potential tampering attempt was detected
   - Check for TSR programs, keyloggers, or other resident programs
   - Try rebooting the system before decryption

### DJGPP Cross-Compilation

If cross-compiling from a modern system to DOS:

1. Ensure DJGPP is properly installed
2. Use the provided Makefile without modifications
3. Transfer the compiled .exe files to your DOS environment

## Files

- `combined_decrypt.c` - Main program source code
- `aes.c` / `aes.h` - AES implementation files
- `security_check.c` / `security_check.h` - Anti-tampering protection module
- `Makefile` - Build configuration 