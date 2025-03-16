# Encryption Component

This component handles the secure encryption of wallet data using AES-256-CBC encryption with PBKDF2 key derivation.

## Files

- `generate_key.c`: Key generation utility
- `encrypt_file.c`: File encryption utility

## Building

Requires OpenSSL development libraries:

```bash
# Ubuntu/Debian
sudo apt-get install libssl-dev

# CentOS/RHEL
sudo yum install openssl-devel
```

Compile:
```bash
gcc -o generate_key generate_key.c -lssl -lcrypto
gcc -o encrypt_file encrypt_file.c -lssl -lcrypto
```

## Usage

1. Generate a key from password:
```bash
./generate_key "your_secure_password"
```

2. Encrypt a wallet file:
```bash
./encrypt_file wallet.dat encrypted_wallet.bin
```

## Security Notes

- Uses PBKDF2-HMAC-SHA256 with 10,000 iterations
- Implements secure memory wiping
- Includes salt and IV in output file
