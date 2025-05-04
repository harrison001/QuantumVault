# QuantumVault

A military-grade, quantum-resistant cold storage solution designed as a secure alternative to traditional cryptocurrency cold wallets. QuantumVault provides a robust cross-platform security model for protecting your digital assets against both current and future threats.


Encrypted cold storage system with AES-256 + custom DOS bootloader for pre-OS password-based decryption.

Website: [https://harrisonsec.com/projects/](https://harrisonsec.com/projects/)

## Table of Contents
- [Overview](#overview)
- [Key Advantages](#key-advantages)
- [System Architecture](#system-architecture)
- [Quantum Resistance](#quantum-resistance)
- [Security Model](#security-model)
- [SentinelDOS Bootloader Security](#sentineldos-bootloader-security)
- [Getting Started](#getting-started)
- [Future Development](#future-development)
- [Project Structure](#project-structure)
- [Contact](#contact)

## Overview

QuantumVault is a comprehensive security solution for cryptocurrency cold storage that leverages a dual-system approach:
1. **Encryption on Linux**: Secure environment for initial encryption of wallet data
2. **Decryption on DOS**: Air-gapped, network-isolated environment for accessing sensitive data

This separation provides defense-in-depth security while maintaining usability for cryptocurrency holders concerned about both conventional and quantum computing threats.

## Key Advantages

- **Cross-Platform Security Model**: Encryption on Linux with automatic cleanup, decryption on network-isolated DOS
- **Military-Grade Encryption**: AES-256-CBC encryption remains secure even against quantum computing attacks
- **Self-Monitoring Environment**: Real-time security monitoring prevents tampering and unauthorized access
- **Hardware Independence**: No specialized hardware required, works on standard x86 computers
- **Quantum-Resistant Design**: Prepared for the post-quantum cryptography era
- **Extensible Architecture**: Ready for hardware authentication and distributed key storage upgrades

## System Architecture

QuantumVault employs a two-part system architecture:

### Encryption Component (Linux)
- Secure key generation using PBKDF2-HMAC-SHA256 with 10,000 iterations
- AES-256-CBC encryption of wallet data
- Automated secure cleanup of plaintext files and memory
- Structured file format with salt and IV for maximum security

### Decryption Component (DOS)
- Network-isolated environment for maximum security
- Self-contained implementation with minimal dependencies
- Real-time anti-tampering monitoring
- Multi-pass secure memory wiping
- Options for direct display or file output

## Quantum Resistance

While many cryptocurrency systems rely on elliptic curve cryptography (ECC) that may be vulnerable to quantum computing attacks, QuantumVault's use of AES-256 provides robust protection:

- **Post-Quantum Security**: AES-256 is considered quantum-resistant with sufficient key size
- **No Known Quantum Attacks**: Grover's algorithm, the best known quantum attack against symmetric ciphers, only reduces AES-256 security to approximately 128 bits - still well beyond practical attack capabilities
- **Future-Proof Design**: Even if Bitcoin's elliptic curve signatures become vulnerable to quantum computers, your private keys remain secure inside QuantumVault

## Security Model

QuantumVault implements multiple security layers:

- **Cryptographic Security**: AES-256-CBC with PBKDF2 key derivation
- **Air-Gap Security**: DOS-based decryption operates on offline systems
- **Anti-Tampering Protection**:
  - Real-time interrupt vector table monitoring
  - Keyboard hook detection
  - Timer hook detection
  - Runtime memory integrity verification
- **Memory Protection**: Multi-pass secure wiping of sensitive data
- **Physical Security**: System auto-reboot after decryption to clear memory

## SentinelDOS Bootloader Security

The SentinelDOS folder contains assembly code that implements a secure bootloader with password verification:

### Two-Stage Secure Bootloader
- **stage1.asm**: First-stage bootloader that fits in the boot sector (512 bytes)
- **stage2.asm**: Second-stage bootloader with password verification functionality

### Key Security Features
- **Boot-Time Password Protection**: Requires correct password entry before allowing access to DOS
- **Three-Attempt Lockout**: System automatically locks after three incorrect password attempts
- **System Security Verification**: Performs basic integrity checks at boot time

### Additional Assembly Security Components
- **btcrypt.asm**: Basic cryptocurrency-related assembly routines
- **attack.s, guard.s, keysave.s**: Early security verification implementations in assembly
  
These assembly components served as a foundation for security concepts now implemented in the Decryption component using C with inline assembly in a 32-bit environment, which provides enhanced security capabilities.

**Note**: The assembly code in the SentinelDOS directory is provided for reference purposes. The production QuantumVault implementation uses the 32-bit protected mode environment for improved security.

## Getting Started

### Requirements
- For encryption: Any modern Linux system with GCC and OpenSSL
- For decryption: DOS environment with DJGPP (can run on physical machines or emulators)
- Storage media for transferring encrypted files between systems

### Basic Usage

#### Encryption (on Linux)
```bash
cd Encryption
gcc -o generate_key generate_key.c -lssl -lcrypto
gcc -o encrypt_file encrypt_file.c -lssl -lcrypto

# Generate key from password
./generate_key "your_secure_password"

# Encrypt wallet file
./encrypt_file wallet.dat encrypted_wallet.bin
```

#### Decryption (compile on any djgpp-gcc platform, run on DOS)
```
cd Decryption
make

# Decrypt using the same password
combined_decrypt.exe -p your_secure_password encrypted_wallet.bin wallet.dat

# Or decrypt using a key file
combined_decrypt.exe -k keyfile.bin encrypted_wallet.bin wallet.dat
```

For detailed instructions, see the README files in the respective component folders.

## Future Development

The QuantumVault project roadmap includes several advanced security features:

- **Hardware Fingerprinting**: Binding decryption to specific hardware profiles
- **Physical Authentication**: Integration with physical security keys and biometric verification
- **Distributed Key Storage**:
  - Shamir's Secret Sharing for key splitting across multiple locations
  - Individual encryption of each key fragment
  - Redundancy allowing recovery even if some fragments are lost
  - Inclusion of decoy fragments to resist forced disclosure attacks
- **Multi-Cryptocurrency Support**: Expanded support for various cryptocurrency wallet formats
- **Hardware Security Module Integration**: Optional integration with HSMs for enterprise use cases

## Project Structure

```
QuantumVault/
├── Encryption/           # Linux-based encryption tools
│   ├── encrypt_file.c    # File encryption utility
│   ├── generate_key.c    # Key generation utility
│   └── README.md         # Encryption component documentation
├── Decryption/           # DOS-based decryption tools
│   ├── combined_decrypt.c    # Main decryption program with security features
│   ├── security_check.c      # Anti-tampering module with inline assembly
│   ├── aes.c                 # AES implementation
│   └── README.md             # Decryption component documentation
├── SentinelDOS/          # Reference bootloader security code
│   ├── stage1.asm        # First-stage bootloader
│   ├── stage2.asm        # Second-stage bootloader with full password verification
│   ├── btcrypt.asm       # Basic assembly routines
│   ├── attack.s          # Security verification code
│   ├── guard.s           # Security protection routines
│   └── keysave.s         # Key storage functionality
└── README.md             # This file
```

## About

Encrypted cold storage system with AES-256 + custom DOS bootloader for pre-OS password-based decryption.

Website: [https://harrisonsec.com/projects/](https://harrisonsec.com/projects/)

## Contact

For consultations, custom implementations, or questions about QuantumVault for high-security cryptocurrency storage:

Email: consult@harrisonsec.com

---

*QuantumVault is provided as-is without warranty. Users are responsible for their own security practices and key management.* 