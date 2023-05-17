#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/ripemd.h>
#include <string.h>
#include <stdio.h>
#include "hashing.h"
#include "sha3/sha3.h"

int sha256(const unsigned char *data, size_t length, unsigned char *digest) {
    SHA256_CTX ctx;
    if (SHA256_Init(&ctx) != 1) {
        printf("Failed to initialize SHA256 context\n");
        return 1;
    }
    if (SHA256_Update(&ctx, data, length) != 1) {
        printf("Failed to update digest\n");
        return 1;
    }
    if (SHA256_Final(digest, &ctx) != 1) {
        printf("Failed to finalize digest\n");
        return 1;
    }
    return 0; // Success
}

int sha256_4(size_t length, const unsigned char *data0, const unsigned char *data1,
             const unsigned char *data2, const unsigned char *data3,
             unsigned char *digest0, unsigned char *digest1,
             unsigned char *digest2, unsigned char *digest3) {
    SHA256_CTX ctx[4];
    
    if (SHA256_Init(&ctx[0]) != 1 || SHA256_Init(&ctx[1]) != 1 ||
        SHA256_Init(&ctx[2]) != 1 || SHA256_Init(&ctx[3]) != 1) {
        printf("Failed to initialize SHA256 contexts\n");
        return 1;
    }
    
    if (SHA256_Update(&ctx[0], data0, length) != 1 ||
        SHA256_Update(&ctx[1], data1, length) != 1 ||
        SHA256_Update(&ctx[2], data2, length) != 1 ||
        SHA256_Update(&ctx[3], data3, length) != 1) {
        printf("Failed to update digests\n");
        return 1;
    }
    
    if (SHA256_Final(digest0, &ctx[0]) != 1 ||
        SHA256_Final(digest1, &ctx[1]) != 1 ||
        SHA256_Final(digest2, &ctx[2]) != 1 ||
        SHA256_Final(digest3, &ctx[3]) != 1) {
        printf("Failed to finalize digests\n");
        return 1;
    }
    
    return 0; // Success
}

// Function for hashing
int keccak(const unsigned char *data, size_t length, unsigned char *digest) {
	SHA3_256_CTX ctx;
	SHA3_256_Init(&ctx);
	SHA3_256_Update(&ctx,data,length);
	KECCAK_256_Final(digest,&ctx);
	return 0; // Success
}



int rmd160(const unsigned char *data, size_t length, unsigned char *digest) {
    RIPEMD160_CTX ctx;
    if (RIPEMD160_Init(&ctx) != 1) {
        printf("Failed to initialize RIPEMD-160 context\n");
        return 1;
    }
    if (RIPEMD160_Update(&ctx, data, length) != 1) {
        printf("Failed to update digest\n");
        return 1;
    }
    if (RIPEMD160_Final(digest, &ctx) != 1) {
        printf("Failed to finalize digest\n");
        return 1;
    }
    return 0; // Success
}

int rmd160_4(size_t length, const unsigned char *data0, const unsigned char *data1,
                const unsigned char *data2, const unsigned char *data3,
                unsigned char *digest0, unsigned char *digest1,
                unsigned char *digest2, unsigned char *digest3) {
    RIPEMD160_CTX ctx[4];
    
    if (RIPEMD160_Init(&ctx[0]) != 1 || RIPEMD160_Init(&ctx[1]) != 1 ||
        RIPEMD160_Init(&ctx[2]) != 1 || RIPEMD160_Init(&ctx[3]) != 1) {
        printf("Failed to initialize RIPEMD-160 contexts\n");
        return 1;
    }
    
    if (RIPEMD160_Update(&ctx[0], data0, length) != 1 ||
        RIPEMD160_Update(&ctx[1], data1, length) != 1 ||
        RIPEMD160_Update(&ctx[2], data2, length) != 1 ||
        RIPEMD160_Update(&ctx[3], data3, length) != 1) {
        printf("Failed to update digests\n");
        return 1;
    }
    
    if (RIPEMD160_Final(digest0, &ctx[0]) != 1 ||
        RIPEMD160_Final(digest1, &ctx[1]) != 1 ||
        RIPEMD160_Final(digest2, &ctx[2]) != 1 ||
        RIPEMD160_Final(digest3, &ctx[3]) != 1) {
        printf("Failed to finalize digests\n");
        return 1;
    }
    
    return 0; // Success
}

bool sha256_file(const char* file_name, uint8_t* digest) {
    FILE* file = fopen(file_name, "rb");
    if (file == NULL) {
        printf("Failed to open file: %s\n", file_name);
        return false;
    }
    
    uint8_t buffer[8192]; // Buffer to read file contents
    size_t bytes_read;
    
    SHA256_CTX ctx;
    if (SHA256_Init(&ctx) != 1) {
        printf("Failed to initialize SHA256 context\n");
        fclose(file);
        return false;
    }
    
    while ((bytes_read = fread(buffer, 1, sizeof(buffer), file)) > 0) {
        if (SHA256_Update(&ctx, buffer, bytes_read) != 1) {
            printf("Failed to update digest\n");
            fclose(file);
            return false;
        }
    }
    
    if (SHA256_Final(digest, &ctx) != 1) {
        printf("Failed to finalize digest\n");
        fclose(file);
        return false;
    }
    
    fclose(file);
    return true;
}