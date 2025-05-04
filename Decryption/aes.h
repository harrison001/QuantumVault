/*

This is an implementation of the AES algorithm, specifically ECB, CTR and CBC mode.
Block size can be chosen in aes.h - available choices are AES128, AES192, AES256.

The implementation is verified against the test vectors in:
  National Institute of Standards and Technology Special Publication 800-38A 2001 ED

ECB-AES128
----------

  plain-text:
    6bc1bee22e409f96e93d7e117393172a
    ae2d8a571e03ac9c9eb76fac45af8e51
    30c81c46a35ce411e5fbc1191a0a52ef
    f69f2445df4f9b17ad2b417be66c3710

  key:
    2b7e151628aed2a6abf7158809cf4f3c

  resulting cipher
    3ad77bb40d7a3660a89ecaf32466ef97 
    f5d3d58503b9699de785895a96fdbaaf 
    43b1cd7f598ece23881b00e3ed030688 
    7b0c785e27e8ad3f8223207104725dd4 


NOTE:   String length must be evenly divisible by 16 bytes (str_len % 16 == 0)
        You should pad the end of the string with zeros if this is not the case.
        For AES192/256 the key size is proportionally larger.

*/

#ifndef _AES_H_
#define _AES_H_

#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

// #define the macros below to 1/0 to enable/disable the mode of operation.
//
// CBC enables AES encryption in CBC-mode of operation.
// CTR enables encryption in counter-mode.
// ECB enables the basic ECB 16-byte block algorithm.
//
// The constants defined below can be used to determine which mode to use
// for encryption/decryption.
#define CBC 1
#define CTR 1
#define ECB 1

#define AES128 1
#define AES192 1
#define AES256 1

#define AES_BLOCKLEN 16 // Block length in bytes - AES is 128b block only
#define AES_KEYLEN 32   // Key length in bytes
#define AES_keyExpSize 240

// OpenSSL compatibility constants - adjusted for custom format
#define SALT_SIZE 16    // Changed from 8 to 16 bytes to match user's format
#define IV_SIZE 16
#define BUFFER_SIZE 1024

struct AES_ctx
{
    uint8_t RoundKey[AES_keyExpSize];
#if (defined(CBC) && (CBC == 1)) || (defined(CTR) && (CTR == 1))
    uint8_t Iv[AES_BLOCKLEN];
#endif
};

void AES_init_ctx(struct AES_ctx* ctx, const uint8_t* key);
#if (defined(CBC) && (CBC == 1)) || (defined(CTR) && (CTR == 1))
void AES_init_ctx_iv(struct AES_ctx* ctx, const uint8_t* key, const uint8_t* iv);
void AES_ctx_set_iv(struct AES_ctx* ctx, const uint8_t* iv);
#endif

#if defined(ECB) && (ECB == 1)
// buffer size is exactly AES_BLOCKLEN bytes; 
// you need only AES_init_ctx as IV is not used in ECB 
// NB: ECB is considered insecure for most uses
void AES_ECB_encrypt(const struct AES_ctx* ctx, uint8_t* buf);
void AES_ECB_decrypt(const struct AES_ctx* ctx, uint8_t* buf);

#endif // #if defined(ECB) && (ECB == !)


#if defined(CBC) && (CBC == 1)
// buffer size MUST be multiple of AES_BLOCKLEN;
// Suggest using a multiple of 16 bytes!
void AES_CBC_encrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length);
void AES_CBC_decrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length);

#endif // #if defined(CBC) && (CBC == 1)


#if defined(CTR) && (CTR == 1)

// Same function for encrypting as for decrypting. 
// IV is incremented for every block, and used after encryption as XOR-compliment for output
// Suggesting https://en.wikipedia.org/wiki/Galois/Counter_Mode
// (GCM mode).
void AES_CTR_xcrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length);

#endif // #if defined(CTR) && (CTR == 1)

// New: OpenSSL compatibility functions
// Read OpenSSL format header (Salted__+salt+IV) from file
int AES_read_openssl_header(FILE* file, uint8_t* salt, uint8_t* iv);

// New: PKCS#7 padding handling
// Verify and remove PKCS#7 padding
int AES_remove_pkcs7_padding(uint8_t* data, size_t length);

// New: All-in-one decrypt function for OpenSSL format files
int AES_decrypt_file_openssl(const char* input_file, const char* output_file, const uint8_t* key);

// Debug helper function
void AES_print_hex(const char* label, const uint8_t* data, size_t length);

#endif // _AES_H_ 