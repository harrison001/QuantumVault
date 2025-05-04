#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* DOS-specific headers - with fallback mechanisms */
#if defined(__DJGPP__) || defined(__MSDOS__)
  #include <dos.h>
  #include <conio.h>
  #define HAS_DOS_FUNCTIONS 1
#else
  /* Fallback for non-DOS environments (for development only) */
  #define HAS_DOS_FUNCTIONS 0
  #include <unistd.h>  /* For sleep() as a fallback */
  
  /* Simple stubbed versions of DOS functions for non-DOS environments */
  #ifndef delay
    #define delay(ms) usleep((ms)*1000)
  #endif
  
  int kbhit(void) { return 0; /* Always return no key pressed */ }
  int getch(void) { return 0; /* Return null character */ }
#endif

#include "aes.h"
#include "security_check.h"

/* Constants */
#define SALT_SIZE 16
#define IV_SIZE 16
#define KEY_SIZE 32
#define BLOCK_SIZE 16
#define DECRYPT_BUFFER_SIZE 4096
#define SHA256_BLOCK_SIZE 64
#define SHA256_DIGEST_SIZE 32
#define PBKDF2_ITERATIONS 10000
#define SECURE_WIPE_PASSES 3 /* Number of passes to wipe sensitive data */
#define RESTART_COUNTDOWN 60 /* Countdown timer in seconds before restart */

/* Structure for SHA-256 context */
typedef struct {
    uint32_t state[8];
    uint64_t bitlen;
    uint8_t data[64];
    uint32_t datalen;
} SA_SHA256_CTX;

/* SHA-256 Constants */
static const uint32_t k[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

/* Helper macros for SHA-256 */
#define ROTRIGHT(a,b) (((a) >> (b)) | ((a) << (32-(b))))
#define CH(x,y,z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x) (ROTRIGHT(x,2) ^ ROTRIGHT(x,13) ^ ROTRIGHT(x,22))
#define EP1(x) (ROTRIGHT(x,6) ^ ROTRIGHT(x,11) ^ ROTRIGHT(x,25))
#define SIG0(x) (ROTRIGHT(x,7) ^ ROTRIGHT(x,18) ^ ((x) >> 3))
#define SIG1(x) (ROTRIGHT(x,17) ^ ROTRIGHT(x,19) ^ ((x) >> 10))

/* Function prototypes */
void print_hex(const char *label, const unsigned char *data, size_t len);
void print_text(const unsigned char *data, size_t len);
void secure_wipe(unsigned char *data, size_t len);
int read_header(FILE *file, unsigned char *salt, unsigned char *iv);
int remove_pkcs7_padding(unsigned char *data, size_t length);
int decrypt_file_with_key(const char *input_file, const char *output_file, const unsigned char *key, int save_to_file);
int decrypt_file_with_password(const char *input_file, const char *output_file, const char *password, int save_to_file);
int hex_to_bin(const char *hex, uint8_t *bin, int len);
void countdown_restart(int seconds);
void final_cleanup(void);
void bios_reboot(void);

/* SHA-256 functions */
void sa_sha256_init(SA_SHA256_CTX *ctx);
void sa_sha256_transform(SA_SHA256_CTX *ctx, const uint8_t data[]);
void sa_sha256_update(SA_SHA256_CTX *ctx, const uint8_t data[], size_t len);
void sa_sha256_final(SA_SHA256_CTX *ctx, uint8_t hash[]);
void sa_sha256(const uint8_t *data, size_t len, uint8_t hash[SHA256_DIGEST_SIZE]);
void sa_hmac_sha256(const uint8_t *key, size_t key_len, const uint8_t *data, size_t data_len, uint8_t *output);
void sa_pbkdf2_hmac_sha256(const char *password, const uint8_t *salt, size_t salt_len, int iterations, uint8_t *output, size_t output_len);

/* Global memory pointers for final cleanup */
void *global_memory_pointers[10] = {NULL};
int global_memory_count = 0;

/* Register memory for final cleanup */
void register_memory(void *ptr) {
    if (global_memory_count < 10) {
        global_memory_pointers[global_memory_count++] = ptr;
    }
}

/* Main function */
int main(int argc, char *argv[]) {
    /* Initialize security checks */
    if (initialize_security_check() != 0) {
        printf("\nSecurity system initialization failed.\n");
        return 1;
    }
    if (argc < 4) {
        printf("DOS AES Decryption Tool\n");
        printf("-------------------------\n");
        printf("Usage (key file mode):   %s -k <key_file> <encrypted_file> [output_file]\n", argv[0]);
        printf("Usage (password mode):   %s -p <password> <encrypted_file> [output_file]\n", argv[0]);
        printf("Note: If output_file is not specified, decrypted content will be displayed on screen\n");
        return 1;
    }
    
    printf("\n===== DOS AES Decryption Tool =====\n\n");
    
    int result = 0;
    int save_to_file = (argc >= 5); /* If output file is provided */
    
    if (strcmp(argv[1], "-k") == 0 && argc >= 4) {
        /* Key file mode */
        printf("Mode: Key file decryption\n");
        printf("Key file: %s\n", argv[2]);
        printf("Input file: %s\n", argv[3]);
        if (save_to_file) {
            printf("Output file: %s\n", argv[4]);
        } else {
            printf("Output: Screen display\n");
        }
        
        /* Read key from file */
        FILE *key_file = fopen(argv[2], "rb");
        if (!key_file) {
            printf("Error: Cannot open key file: %s\n", argv[2]);
            return 1;
        }
        
        unsigned char key[KEY_SIZE];
        if (fread(key, 1, KEY_SIZE, key_file) != KEY_SIZE) {
            printf("Error: Cannot read key from file (should be %d bytes)\n", KEY_SIZE);
            fclose(key_file);
            return 1;
        }
        fclose(key_file);
        
        /* Register key for cleanup */
        register_memory(key);
        
        /* Decrypt file using key */
        result = decrypt_file_with_key(argv[3], (save_to_file ? argv[4] : NULL), key, save_to_file);
        
        /* Clean up key from memory */
        secure_wipe(key, KEY_SIZE);
    }
    else if (strcmp(argv[1], "-p") == 0 && argc >= 4) {
        /* Password mode */
        printf("Mode: Password-based decryption\n");
        printf("Input file: %s\n", argv[3]);
        if (save_to_file) {
            printf("Output file: %s\n", argv[4]);
        } else {
            printf("Output: Screen display\n");
        }
        
        /* Decrypt file using password */
        result = decrypt_file_with_password(argv[3], (save_to_file ? argv[4] : NULL), argv[2], save_to_file);
    }
    else {
        printf("Error: Invalid command format\n");
        return 1;
    }
    
    if (result) {
        printf("\nDecryption successful!\n");
        
        /* Clean up all registered memory before restart */
        final_cleanup();
        
        /* Countdown before restart */
        countdown_restart(RESTART_COUNTDOWN);
        
        return 0;
    } else {
        printf("\nDecryption failed!\n");
        return 1;
    }
}

/* Print hexadecimal values */
void print_hex(const char *label, const unsigned char *data, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

/* Print text content */
void print_text(const unsigned char *data, size_t len) {
    printf("\n----- Decrypted Content -----\n");
    
    /* Display the content as text, handling non-printable characters */
    for (size_t i = 0; i < len; i++) {
        if (data[i] >= 32 && data[i] <= 126) {
            putchar(data[i]);
        } else if (data[i] == '\n' || data[i] == '\r' || data[i] == '\t') {
            putchar(data[i]);
        } else {
            putchar('.');
        }
    }
    
    printf("\n----------------------------\n");
}

/* Securely wipe data from memory with multiple passes */
void secure_wipe(unsigned char *data, size_t len) {
    if (data == NULL || len == 0) return;
    
    volatile unsigned char *p = data;
    
    /* Multiple overwrite passes with different patterns */
    for (int pass = 0; pass < SECURE_WIPE_PASSES; pass++) {
        /* Pass 1: All zeros */
        if (pass == 0) {
            for (size_t i = 0; i < len; i++) p[i] = 0;
        }
        /* Pass 2: All ones */
        else if (pass == 1) {
            for (size_t i = 0; i < len; i++) p[i] = 0xFF;
        }
        /* Pass 3: Random pattern */
        else {
            for (size_t i = 0; i < len; i++) p[i] = rand() & 0xFF;
        }
    }
}

/* Perform final cleanup of all registered memory */
void final_cleanup(void) {
    /* Wipe all registered memory blocks */
    for (int i = 0; i < global_memory_count; i++) {
        if (global_memory_pointers[i] != NULL) {
            /* Assume a reasonable size for memory blocks */
            secure_wipe(global_memory_pointers[i], 4096);
            global_memory_pointers[i] = NULL;
        }
    }
    global_memory_count = 0;
    
    /* Additional system-wide cleanup */
    fflush(NULL); /* Flush all streams */
}

/* Read file header (salt and IV) */
int read_header(FILE *file, unsigned char *salt, unsigned char *iv) {
    if (fread(salt, 1, SALT_SIZE, file) != SALT_SIZE) {
        printf("Error: Cannot read salt\n");
        return 0;
    }
    
    if (fread(iv, 1, IV_SIZE, file) != IV_SIZE) {
        printf("Error: Cannot read IV\n");
        return 0;
    }
    
    printf("File format: [Salt(16 bytes)][IV(16 bytes)][Encrypted data]\n");
    return 1;
}

/* Verify and remove PKCS#7 padding */
int remove_pkcs7_padding(unsigned char *data, size_t length) {
    if (length == 0) return 0;
    
    unsigned char padding_value = data[length - 1];
    
    /* Padding value must be between 1 and 16 */
    if (padding_value == 0 || padding_value > BLOCK_SIZE) {
        printf("Error: Invalid padding value: %d\n", padding_value);
        return -1;
    }
    
    /* Check if all padding bytes are consistent */
    for (size_t i = length - padding_value; i < length; i++) {
        if (data[i] != padding_value) {
            printf("Error: Padding inconsistent at position %zu: value is %d, should be %d\n", 
                   i, data[i], padding_value);
            return -1;
        }
    }
    
    return length - padding_value;
}

/* Decrypt file using provided key */
int decrypt_file_with_key(const char *input_file, const char *output_file, const unsigned char *key, int save_to_file) {
    
    /* Perform security check before decryption */
    if (perform_security_check() != 0) {
        printf("\nSecurity violation detected: %s\n", get_security_error());
        printf("Aborting decryption for security reasons.\n");
        secure_wipe(key, KEY_SIZE);
        return 0; /* Return error */
    }
    FILE *in_file = fopen(input_file, "rb");
    if (!in_file) {
        printf("Error: Cannot open input file: %s\n", input_file);
        return 0;
    }
    
    /* Read salt and IV */
    unsigned char salt[SALT_SIZE];
    unsigned char iv[IV_SIZE];
    
    if (!read_header(in_file, salt, iv)) {
        fclose(in_file);
        return 0;
    }
    
    print_hex("Salt", salt, SALT_SIZE);
    print_hex("IV", iv, IV_SIZE);
    print_hex("Key", key, KEY_SIZE);
    
    /* Create output file if needed */
    FILE *out_file = NULL;
    if (save_to_file) {
        out_file = fopen(output_file, "wb");
        if (!out_file) {
            printf("Error: Cannot create output file: %s\n", output_file);
            fclose(in_file);
            return 0;
        }
    }
    
    /* Initialize AES context */
    struct AES_ctx ctx;
    AES_init_ctx_iv(&ctx, key, iv);
    
    /* Read and decrypt data */
    unsigned char buffer[DECRYPT_BUFFER_SIZE];
    unsigned char decrypted[DECRYPT_BUFFER_SIZE];
    size_t bytes_read;
    size_t total_bytes = 0;
    
    /* Create temporary file for padding processing */
    FILE *temp_file = tmpfile();
    if (!temp_file) {
        printf("Error: Cannot create temporary file\n");
        fclose(in_file);
        if (save_to_file) fclose(out_file);
        return 0;
    }
    
    /* Read and decrypt blocks */
    while ((bytes_read = fread(buffer, 1, DECRYPT_BUFFER_SIZE, in_file)) > 0) {
        /* Ensure data is a multiple of 16 bytes */
        if (bytes_read % BLOCK_SIZE != 0) {
            printf("Warning: Read data is not a multiple of %d bytes\n", BLOCK_SIZE);
            fclose(in_file);
            if (save_to_file) fclose(out_file);
            fclose(temp_file);
            return 0;
        }
        
        /* Copy data for decryption */
        memcpy(decrypted, buffer, bytes_read);
        
        /* Decrypt data */
        AES_CBC_decrypt_buffer(&ctx, decrypted, bytes_read);
        
        /* Write to temporary file */
        fwrite(decrypted, 1, bytes_read, temp_file);
        total_bytes += bytes_read;
    }
    
    /* Reset temporary file pointer */
    fseek(temp_file, 0, SEEK_SET);
    
    /* Read all decrypted data */
    unsigned char *all_decrypted = (unsigned char*)malloc(total_bytes);
    if (!all_decrypted) {
        printf("Error: Memory allocation failed\n");
        fclose(in_file);
        if (save_to_file) fclose(out_file);
        fclose(temp_file);
        return 0;
    }
    
    /* Register allocated memory for cleanup */
    register_memory(all_decrypted);
    
    fread(all_decrypted, 1, total_bytes, temp_file);
    
    /* Remove PKCS#7 padding */
    int final_size = remove_pkcs7_padding(all_decrypted, total_bytes);
    if (final_size < 0) {
        printf("Warning: Padding verification failed, but will still process data\n");
        final_size = total_bytes;
    } else {
        printf("Successfully removed padding, final size: %d bytes\n", final_size);
    }
    /* Final security check before handling decrypted data */
    if (perform_security_check() != 0) {
        printf("\nSecurity violation detected: %s\n", get_security_error());
        printf("Decryption completed but results discarded for security.\n");
        secure_wipe(all_decrypted, total_bytes);
        free(all_decrypted);
        return 0; /* Return error */
    }

    /* Either save to file or display on screen */
    if (save_to_file && out_file) {
        /* Write final decrypted data to file */
        fwrite(all_decrypted, 1, final_size, out_file);
        printf("Decryption complete, output written to: %s\n", output_file);
    } else {
        /* Display to screen */
        print_text(all_decrypted, final_size);
    }
    

    
    /* Clean up */
    secure_wipe(all_decrypted, total_bytes);
    free(all_decrypted);
    fclose(temp_file);
    fclose(in_file);
    if (save_to_file && out_file) fclose(out_file);
    
    return 1;
}

/* Decrypt file using password-derived key */
int decrypt_file_with_password(const char *input_file, const char *output_file, const char *password, int save_to_file) {
    /* Perform security check before decryption */
    if (perform_security_check() != 0) {
        printf("\nSecurity violation detected: %s\n", get_security_error());
        printf("Aborting decryption for security reasons.\n");
        return 0; /* Return error */
    }
    
    FILE *in_file = fopen(input_file, "rb");
    if (!in_file) {
        printf("Error: Cannot open input file: %s\n", input_file);
        return 0;
    }
    
    /* Read salt and IV */
    unsigned char salt[SALT_SIZE];
    unsigned char iv[IV_SIZE];
    
    if (!read_header(in_file, salt, iv)) {
        fclose(in_file);
        return 0;
    }
    
    print_hex("Salt", salt, SALT_SIZE);
    print_hex("IV", iv, IV_SIZE);
    
    /* Derive key from password using PBKDF2 */
    unsigned char key[KEY_SIZE] = {0};
    
    printf("Using password: %s\n", password);
    printf("Iterations: %d\n", PBKDF2_ITERATIONS);
    
    /* Derive key using our PBKDF2 implementation */
    sa_pbkdf2_hmac_sha256(password, salt, SALT_SIZE, PBKDF2_ITERATIONS, key, KEY_SIZE);
    
    print_hex("Derived key", key, KEY_SIZE);
    
    /* Call the key-based decryption function */
    int result = decrypt_file_with_key(input_file, output_file, key, save_to_file);
    
    /* Clean up sensitive data */
    secure_wipe(key, KEY_SIZE);
    
    return result;
}

/* Convert hex string to binary */
int hex_to_bin(const char *hex, uint8_t *bin, int len) {
    for (int i = 0; i < len; i++) {
        if (sscanf(&hex[i*2], "%2hhx", &bin[i]) != 1) {
            return 0;
        }
    }
    return 1;
}

/* Use BIOS to reboot the system directly */
void bios_reboot(void) {
#if HAS_DOS_FUNCTIONS
    /* Clear keyboard buffer */
    while (kbhit()) getch();
    
    printf("\nRebooting system now...\n");
    
    /* Call BIOS reset interrupt (INT 19h) using inline assembly */
    #if defined(__DJGPP__)
        __asm__ __volatile__ (
            "int $0x19"    /* BIOS reboot interrupt */
        );
    #else
        /* Alternative methods for different compilers */
        asm { int 19h }
    #endif
    
    /* This should never be reached, but just in case */
    exit(0);
#else
    printf("\nReboot not supported in this environment\n");
    exit(0);
#endif
}

/* Countdown and restart system */
void countdown_restart(int seconds) {
    printf("\nSystem will restart in %d seconds...\n", seconds);
    printf("Press Ctrl+C to cancel restart\n");
    
    for (int i = seconds; i > 0; i--) {
        printf("\rTime remaining: %d seconds", i);
        fflush(stdout);
        
        /* Use delay function from dos.h (measured in milliseconds) */
        delay(1000);  /* 1000 milliseconds = 1 second */
        
        /* Check for keypress to cancel */
        if (kbhit()) {
            char c = getch();
            if (c == 3) { /* Ctrl+C */
                printf("\nRestart cancelled by user\n");
                return;
            }
        }
    }
    
    /* Use direct BIOS reboot instead of system call */
    bios_reboot();
}

/* SHA-256 initialization */
void sa_sha256_init(SA_SHA256_CTX *ctx) {
    ctx->datalen = 0;
    ctx->bitlen = 0;
    ctx->state[0] = 0x6a09e667;
    ctx->state[1] = 0xbb67ae85;
    ctx->state[2] = 0x3c6ef372;
    ctx->state[3] = 0xa54ff53a;
    ctx->state[4] = 0x510e527f;
    ctx->state[5] = 0x9b05688c;
    ctx->state[6] = 0x1f83d9ab;
    ctx->state[7] = 0x5be0cd19;
}

/* SHA-256 transform */
void sa_sha256_transform(SA_SHA256_CTX *ctx, const uint8_t data[]) {
    uint32_t a, b, c, d, e, f, g, h, i, j, t1, t2, m[64];

    for (i = 0, j = 0; i < 16; ++i, j += 4)
        m[i] = (data[j] << 24) | (data[j + 1] << 16) | (data[j + 2] << 8) | (data[j + 3]);
    for ( ; i < 64; ++i)
        m[i] = SIG1(m[i - 2]) + m[i - 7] + SIG0(m[i - 15]) + m[i - 16];

    a = ctx->state[0];
    b = ctx->state[1];
    c = ctx->state[2];
    d = ctx->state[3];
    e = ctx->state[4];
    f = ctx->state[5];
    g = ctx->state[6];
    h = ctx->state[7];

    for (i = 0; i < 64; ++i) {
        t1 = h + EP1(e) + CH(e, f, g) + k[i] + m[i];
        t2 = EP0(a) + MAJ(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    ctx->state[0] += a;
    ctx->state[1] += b;
    ctx->state[2] += c;
    ctx->state[3] += d;
    ctx->state[4] += e;
    ctx->state[5] += f;
    ctx->state[6] += g;
    ctx->state[7] += h;
}

/* SHA-256 update */
void sa_sha256_update(SA_SHA256_CTX *ctx, const uint8_t data[], size_t len) {
    uint32_t i;

    for (i = 0; i < len; ++i) {
        ctx->data[ctx->datalen] = data[i];
        ctx->datalen++;
        if (ctx->datalen == 64) {
            sa_sha256_transform(ctx, ctx->data);
            ctx->bitlen += 512;
            ctx->datalen = 0;
        }
    }
}

/* SHA-256 finalize */
void sa_sha256_final(SA_SHA256_CTX *ctx, uint8_t hash[]) {
    uint32_t i;

    i = ctx->datalen;

    /* Pad remaining data to block size */
    if (ctx->datalen < 56) {
        ctx->data[i++] = 0x80;
        while (i < 56)
            ctx->data[i++] = 0x00;
    }
    else {
        ctx->data[i++] = 0x80;
        while (i < 64)
            ctx->data[i++] = 0x00;
        sa_sha256_transform(ctx, ctx->data);
        memset(ctx->data, 0, 56);
    }

    /* Append length (bits) */
    ctx->bitlen += ctx->datalen * 8;
    ctx->data[63] = ctx->bitlen;
    ctx->data[62] = ctx->bitlen >> 8;
    ctx->data[61] = ctx->bitlen >> 16;
    ctx->data[60] = ctx->bitlen >> 24;
    ctx->data[59] = ctx->bitlen >> 32;
    ctx->data[58] = ctx->bitlen >> 40;
    ctx->data[57] = ctx->bitlen >> 48;
    ctx->data[56] = ctx->bitlen >> 56;
    sa_sha256_transform(ctx, ctx->data);

    /* Store hash value (big endian) */
    for (i = 0; i < 4; ++i) {
        hash[i]      = (ctx->state[0] >> (24 - i * 8)) & 0x000000ff;
        hash[i + 4]  = (ctx->state[1] >> (24 - i * 8)) & 0x000000ff;
        hash[i + 8]  = (ctx->state[2] >> (24 - i * 8)) & 0x000000ff;
        hash[i + 12] = (ctx->state[3] >> (24 - i * 8)) & 0x000000ff;
        hash[i + 16] = (ctx->state[4] >> (24 - i * 8)) & 0x000000ff;
        hash[i + 20] = (ctx->state[5] >> (24 - i * 8)) & 0x000000ff;
        hash[i + 24] = (ctx->state[6] >> (24 - i * 8)) & 0x000000ff;
        hash[i + 28] = (ctx->state[7] >> (24 - i * 8)) & 0x000000ff;
    }
}

/* One-shot SHA-256 function */
void sa_sha256(const uint8_t *data, size_t len, uint8_t hash[SHA256_DIGEST_SIZE]) {
    SA_SHA256_CTX ctx;
    sa_sha256_init(&ctx);
    sa_sha256_update(&ctx, data, len);
    sa_sha256_final(&ctx, hash);
}

/* HMAC-SHA256 implementation */
void sa_hmac_sha256(const uint8_t *key, size_t key_len, 
                   const uint8_t *data, size_t data_len, 
                   uint8_t *output) {
    /* Prepare key */
    uint8_t k_ipad[64] = {0};
    uint8_t k_opad[64] = {0};
    uint8_t hash[32];
    
    if (key_len > 64) {
        /* If key is longer than 64 bytes, hash it */
        sa_sha256(key, key_len, hash);
        key = hash;
        key_len = 32;
    }
    
    /* XOR key with ipad and opad values */
    for (size_t i = 0; i < key_len; i++) {
        k_ipad[i] = key[i] ^ 0x36;
        k_opad[i] = key[i] ^ 0x5c;
    }
    
    for (size_t i = key_len; i < 64; i++) {
        k_ipad[i] = 0x36;
        k_opad[i] = 0x5c;
    }
    
    /* Inner hash */
    SA_SHA256_CTX ctx;
    sa_sha256_init(&ctx);
    sa_sha256_update(&ctx, k_ipad, 64);
    sa_sha256_update(&ctx, data, data_len);
    sa_sha256_final(&ctx, hash);
    
    /* Outer hash */
    sa_sha256_init(&ctx);
    sa_sha256_update(&ctx, k_opad, 64);
    sa_sha256_update(&ctx, hash, 32);
    sa_sha256_final(&ctx, output);
}

/* PBKDF2-HMAC-SHA256 implementation */
void sa_pbkdf2_hmac_sha256(const char *password, const uint8_t *salt, size_t salt_len,
                          int iterations, uint8_t *output, size_t output_len) {
    /* F(Password, Salt, c, i) = U_1 XOR U_2 XOR ... XOR U_c
     * where U_1 = PRF(Password, Salt || INT_32_BE(i))
     * and U_j = PRF(Password, U_{j-1})
     */
    
    uint8_t block[4];
    uint8_t u_prev[32];
    uint8_t u_curr[32];
    uint8_t dk[32]; /* Intermediate key buffer */
    
    /* Process for each block (32 bytes per block) */
    for (uint32_t i = 1; i <= (output_len + 31) / 32; i++) {
        /* Prepare block number in big-endian format */
        block[0] = (i >> 24) & 0xFF;
        block[1] = (i >> 16) & 0xFF;
        block[2] = (i >> 8) & 0xFF;
        block[3] = i & 0xFF;
        
        /* Concatenate salt with block index */
        uint8_t *salt_block = (uint8_t*)malloc(salt_len + 4);
        memcpy(salt_block, salt, salt_len);
        memcpy(salt_block + salt_len, block, 4);
        
        /* U_1 = PRF(Password, Salt || INT_32_BE(i)) */
        sa_hmac_sha256((uint8_t*)password, strlen(password), salt_block, salt_len + 4, u_prev);
        free(salt_block);
        
        /* Initialize dk with U_1 */
        memcpy(dk, u_prev, 32);
        
        /* U_j = PRF(Password, U_{j-1}) */
        for (int j = 1; j < iterations; j++) {
            sa_hmac_sha256((uint8_t*)password, strlen(password), u_prev, 32, u_curr);
            
            /* U_1 XOR U_2 XOR ... XOR U_c */
            for (int k = 0; k < 32; k++) {
                dk[k] ^= u_curr[k];
            }
            
            /* U_prev = U_curr for next iteration */
            memcpy(u_prev, u_curr, 32);
        }
        
        /* Copy derived key part to output */
        size_t copy_len = (i == (output_len + 31) / 32) ? output_len - (i - 1) * 32 : 32;
        memcpy(output + (i - 1) * 32, dk, copy_len);
    }
} 