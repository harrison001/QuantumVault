# Decryption Component

Secure decryption component designed to run in an air-gapped DOS environment.

## Files

- `combined_decrypt.c`: Main decryption program
- `security_check.c/h`: Anti-tampering protection
- `aes.c/h`: AES implementation
- `Makefile`: Build configuration
- `cleanup.sh`: Secure cleanup script

## Building

Requires DJGPP cross-compiler:

```bash
# Build all components
make

# Clean build files
make clean
```

## Security Features

- Runtime integrity checking
- Anti-debugging protection
- Secure memory wiping
- Hardware-level security checks
