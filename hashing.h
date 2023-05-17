#ifndef HASHSING
#define HASHSING

int sha256(const unsigned char *data, size_t length, unsigned char *digest);
int rmd160(const unsigned char *data, size_t length, unsigned char *digest);
int keccak(const unsigned char *data, size_t length, unsigned char *digest);
bool sha256_file(const char* file_name, unsigned char * checksum);

int rmd160_4(size_t length, const unsigned char *data0, const unsigned char *data1,
                const unsigned char *data2, const unsigned char *data3,
                unsigned char *digest0, unsigned char *digest1,
                unsigned char *digest2, unsigned char *digest3);

int sha256_4(size_t length, const unsigned char *data0, const unsigned char *data1,
             const unsigned char *data2, const unsigned char *data3,
             unsigned char *digest0, unsigned char *digest1,
             unsigned char *digest2, unsigned char *digest3);

#endif // HASHSING