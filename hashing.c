#include <openssl/evp.h>
#include <string.h>
#include <stdio.h>
#include "hashing.h"

int sha256(const unsigned char *data, size_t length, unsigned char *digest) {
	EVP_MD_CTX *mdctx;
	const EVP_MD *md;
	md = EVP_sha256();
	if(!md) {
        printf("Unknown message digest sha256\n");
        return 1;
	}
	mdctx = EVP_MD_CTX_new();
	if(!mdctx) {
        printf("Failed to create new EVP_MD_CTX\n");
        return 1;
	}
	if(EVP_DigestInit_ex(mdctx, md, NULL) != 1) {
		printf("Failed to initialize EVP_Digest with sha256\n");
		EVP_MD_CTX_free(mdctx);
		return 1;
	}
	if(EVP_DigestUpdate(mdctx, data, length) != 1) {
		printf("Failed to update digest\n");
		EVP_MD_CTX_free(mdctx);
		return 1;
	}
	unsigned int digest_len;
	if(EVP_DigestFinal_ex(mdctx, digest, &digest_len) != 1) {
		printf("Failed to finalize digest\n");
		EVP_MD_CTX_free(mdctx);
		return 1;
	}
	EVP_MD_CTX_free(mdctx);
	return 0; // Success
}

// Function for hashing
int keccak(const unsigned char *data, size_t length, unsigned char *digest) {
	EVP_MD_CTX *mdctx;
	const EVP_MD *md;
	md = EVP_get_digestbyname("keccak256");
	if(!md) {
        printf("Unknown message digest keccak256\n");
        return 1;
	}
	mdctx = EVP_MD_CTX_new();
	if(!mdctx) {
        printf("Failed to create new EVP_MD_CTX\n");
        return 1;
	}
	if(EVP_DigestInit_ex(mdctx, md, NULL) != 1) {
		printf("Failed to initialize EVP_Digest with keccak256\n");
		EVP_MD_CTX_free(mdctx);
		return 1;
	}
	if(EVP_DigestUpdate(mdctx, data, length) != 1) {
		printf("Failed to update digest\n");
		EVP_MD_CTX_free(mdctx);
		return 1;
	}
	unsigned int digest_len;
	if(EVP_DigestFinal_ex(mdctx, digest, &digest_len) != 1) {
		printf("Failed to finalize digest\n");
		EVP_MD_CTX_free(mdctx);
		return 1;
	}
	EVP_MD_CTX_free(mdctx);
	return 0; // Success
}

int rmd160(const unsigned char *data, size_t length, unsigned char *digest) {
	EVP_MD_CTX *mdctx;
	const EVP_MD *md;
	md = EVP_get_digestbyname("rmd160");
	if(!md) {
        printf("Unknown message digest rmd160\n");
        return 1;
	}
	mdctx = EVP_MD_CTX_new();
	if(!mdctx) {
        printf("Failed to create new EVP_MD_CTX\n");
        return 1;
	}
	if(EVP_DigestInit_ex(mdctx, md, NULL) != 1) {
		printf("Failed to initialize EVP_Digest with rmd160\n");
		EVP_MD_CTX_free(mdctx);
		return 1;
	}
	if(EVP_DigestUpdate(mdctx, data, length) != 1) {
		printf("Failed to update digest\n");
		EVP_MD_CTX_free(mdctx);
		return 1;
	}
	unsigned int digest_len;
	if(EVP_DigestFinal_ex(mdctx, digest, &digest_len) != 1) {
		printf("Failed to finalize digest\n");
		EVP_MD_CTX_free(mdctx);
		return 1;
	}
	EVP_MD_CTX_free(mdctx);
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
	EVP_MD_CTX *mdctx;
	const EVP_MD *md;
	md = EVP_sha256();
	if(!md) {
        printf("Unknown message digest sha256\n");
        return false;
	}
	mdctx = EVP_MD_CTX_new();
	if(!mdctx) {
        printf("Failed to create new EVP_MD_CTX\n");
        return false;
	}
	if(EVP_DigestInit_ex(mdctx, md, NULL) != 1) {
		printf("Failed to initialize EVP_Digest with sha256\n");
		EVP_MD_CTX_free(mdctx);
		return false;
	}
	// Read file contents and update SHA256 context
	while ((bytes_read = fread(buffer, 1, sizeof(buffer), file)) > 0) {
		if(EVP_DigestUpdate(mdctx, buffer, bytes_read) != 1) {
			printf("Failed to update digest\n");
			EVP_MD_CTX_free(mdctx);
			return false;
		}
	}
	unsigned int digest_len;
	if(EVP_DigestFinal_ex(mdctx, digest, &digest_len) != 1) {
		printf("Failed to finalize digest\n");
		EVP_MD_CTX_free(mdctx);
		return 1;
	}
	EVP_MD_CTX_free(mdctx);
	fclose(file);
	return true;
}