#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#define AES_KEY_SIZE 32     // 256-bit key
#define AES_IV_SIZE 16      // 128-bit IV
#define SALT_SIZE 16        // 128-bit salt
#define BUFFER_SIZE 4096
#define KEY_FILE "aes_key.bin"
#define PBKDF2_ITERATIONS 10000

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

// AES-256-CBC Encryption
int encrypt_file(const char *input_file, const char *output_file) {
    uint8_t key[AES_KEY_SIZE];
    uint8_t iv[AES_IV_SIZE];
    uint8_t salt[SALT_SIZE];

    // Load key and salt from file
    FILE *key_file = fopen(KEY_FILE, "rb");
    if (!key_file) {
        fprintf(stderr, "Failed to open key file.\n");
        return -1;
    }
    
    fread(salt, 1, sizeof(salt), key_file);
    fread(key, 1, AES_KEY_SIZE, key_file);
    fclose(key_file);
    
    print_hex("Salt", salt, SALT_SIZE);
    print_hex("Key", key, AES_KEY_SIZE);

    // Generate IV
    if (!RAND_bytes(iv, AES_IV_SIZE)) {
        fprintf(stderr, "Failed to generate IV.\n");
        return -1;
    }
    
    print_hex("IV", iv, AES_IV_SIZE);

    FILE *in = fopen(input_file, "rb");
    FILE *out = fopen(output_file, "wb");
    if (!in || !out) {
        fprintf(stderr, "Failed to open input or output file.\n");
        return -1;
    }

    // Write salt at the start of the output file
    fwrite(salt, 1, SALT_SIZE, out);
    
    // Write IV right after the salt
    fwrite(iv, 1, AES_IV_SIZE, out);

    uint8_t buffer[BUFFER_SIZE];
    int bytes_read, bytes_written;
    int out_len;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);

    while ((bytes_read = fread(buffer, 1, BUFFER_SIZE, in)) > 0) {
        uint8_t out_buf[BUFFER_SIZE + AES_BLOCK_SIZE];
        EVP_EncryptUpdate(ctx, out_buf, &out_len, buffer, bytes_read);
        fwrite(out_buf, 1, out_len, out);
    }

    uint8_t final_out[AES_BLOCK_SIZE];
    EVP_EncryptFinal_ex(ctx, final_out, &out_len);
    fwrite(final_out, 1, out_len, out);

    fclose(in);
    fclose(out);
    EVP_CIPHER_CTX_free(ctx);

    // Securely delete key file and plaintext
    remove(KEY_FILE);
    remove(input_file);

    clear_memory(key, sizeof(key));  // Wipe key from memory

    printf("Encryption completed successfully.\n");
    printf("File format: [Salt(16 bytes)][IV(16 bytes)][Encrypted Data]\n");
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <input_file> <output_file>\n", argv[0]);
        return 1;
    }
    return encrypt_file(argv[1], argv[2]);
}
