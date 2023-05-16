#ifndef HASHSING
#define HASHSING

#include <openssl/evp.h>
#include <string.h>

int sha256(const unsigned char *data, size_t length, unsigned char *digest);
int rmd160(const unsigned char *data, size_t length, unsigned char *digest);
int keccak(const unsigned char *data, size_t length, unsigned char *digest);
bool sha256_file(const char* file_name, unsigned char * checksum);

#endif // HASHSING