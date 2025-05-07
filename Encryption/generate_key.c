#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#define AES_KEY_SIZE 32    // 256-bit key
#define SALT_SIZE 16       // 128-bit salt
#define PBKDF2_ITERATIONS 10000
#define KEY_FILE "aes_key.bin"

// Secure memory wipe
void clear_memory(uint8_t *data, size_t len) {
    volatile uint8_t *p = data;
    while (len--) *p++ = 0;
}

// Debug function to print hex values
void print_hex(const char *label, const uint8_t *data, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

// Generate a key using PBKDF2 + SHA-256
int generate_key(const char *password) {
    uint8_t salt[SALT_SIZE];
    uint8_t key[AES_KEY_SIZE];

    if (!RAND_bytes(salt, sizeof(salt))) {
        fprintf(stderr, "Failed to generate salt.\n");
        return -1;
    }
    
    print_hex("Generated Salt", salt, SALT_SIZE);

    if (!PKCS5_PBKDF2_HMAC(password, strlen(password), salt, sizeof(salt), PBKDF2_ITERATIONS, EVP_sha256(), AES_KEY_SIZE, key)) {
        fprintf(stderr, "Failed to generate key.\n");
        return -1;
    }
    
    print_hex("Generated Key", key, AES_KEY_SIZE);
    printf("PBKDF2 iterations: %d\n", PBKDF2_ITERATIONS);

    FILE *file = fopen(KEY_FILE, "wb");
    if (!file) {
        fprintf(stderr, "Failed to open key file for writing.\n");
        return -1;
    }

    fwrite(salt, 1, SALT_SIZE, file);
    fwrite(key, 1, AES_KEY_SIZE, file);
    fclose(file);

    clear_memory(key, sizeof(key));  // Wipe key from memory

    printf("Key successfully generated and saved to %s\n", KEY_FILE);
    printf("File format: [Salt(16 bytes)][Key(32 bytes)]\n");
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <password>\n", argv[0]);
        return 1;
    }
    
    printf("Password length: %zu characters\n", strlen(argv[1]));
    return generate_key(argv[1]);
}
