/*
    SHA256 implementation, source file.

    This implementation was written by Kent "ethereal" Williams-King and is
    hereby released into the public domain. Do what you wish with it.

    No guarantees as to the correctness of the implementation are provided.
*/

#include <stdint.h>
#include <string.h>

const uint32_t sha256_initial_h[8]
    = { 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 };

const uint32_t sha256_round_k[64]
    = { 0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
        0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
        0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
        0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
        0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2 };

void sha256_endian_reverse64(uint64_t input, uint8_t *output) {
    output[7] = (input >> 0) & 0xff;
    output[6] = (input >> 8) & 0xff;
    output[5] = (input >> 16) & 0xff;
    output[4] = (input >> 24) & 0xff;
    output[3] = (input >> 32) & 0xff;
    output[2] = (input >> 40) & 0xff;
    output[1] = (input >> 48) & 0xff;
    output[0] = (input >> 56) & 0xff;
}

uint32_t sha256_endian_read32(uint8_t *input) {
    uint32_t output = 0;
    output |= (input[0] << 24);
    output |= (input[1] << 16);
    output |= (input[2] << 8);
    output |= (input[3] << 0);

    return output;
}

void sha256_endian_reverse32(uint32_t input, uint8_t *output) {
    output[3] = (input >> 0) & 0xff;
    output[2] = (input >> 8) & 0xff;
    output[1] = (input >> 16) & 0xff;
    output[0] = (input >> 24) & 0xff;
}

uint32_t sha256_ror(uint32_t input, uint32_t by) {
    return (input >> by) | (((input & ((1 << by) - 1))) << (32 - by));
}

void sha256(const void *data, uint64_t len, void *output) {
    uint8_t padding[80];
    uint64_t current = (len + 1) % 64;
    // want to be == 56 % 64.
    uint64_t needed = (64 + 56 - current) % 64;
    uint64_t extra = needed + 9;
    uint64_t total = len + extra;

    for(int i = 1; i < 80; i++)
        padding[i] = 0;
    padding[0] = 0x80;
    sha256_endian_reverse64(len * 8, padding + total - len - 8);

    uint32_t v[8];
    for(int i = 0; i < 8; i++)
        v[i] = sha256_initial_h[i];

    for(uint64_t cursor = 0; cursor * 64 < total; cursor++) {
        uint32_t t[8];
        for(int i = 0; i < 8; i++)
            t[i] = v[i];

        uint32_t w[64];
        if(cursor * 64 + 64 <= len) {
            for(int j = 0; j < 16; j++) {
                w[j] = sha256_endian_read32(
                    (uint8_t *)data + cursor * 64 + j * 4);
            }
        }
        else {
            if(cursor * 64 < len) {
                uint64_t size = len - cursor * 64;
                if(size > 0) memcpy(w, (uint8_t *)data + cursor * 64, size);
                memcpy((uint8_t *)w + size, padding, 64 - size);
            }
            else {
                uint64_t off = (cursor * 64 - len) % 64;
                memcpy((uint8_t *)w, padding + off, 64);
            }

            for(int j = 0; j < 16; j++) {
                w[j] = sha256_endian_read32((uint8_t *)&w[j]);
            }
        }

        for(int j = 16; j < 64; j++) {
            uint32_t s1 = sha256_ror(w[j - 2], 17) ^ sha256_ror(w[j - 2], 19)
                ^ (w[j - 2] >> 10);
            uint32_t s0 = sha256_ror(w[j - 15], 7) ^ sha256_ror(w[j - 15], 18)
                ^ (w[j - 15] >> 3);
            w[j] = s1 + w[j - 7] + s0 + w[j - 16];
        }

        for(int j = 0; j < 64; j++) {
            uint32_t ch = (t[4] & t[5]) ^ (~t[4] & t[6]);
            uint32_t maj = (t[0] & t[1]) ^ (t[0] & t[2]) ^ (t[1] & t[2]);
            uint32_t S0 = sha256_ror(t[0], 2) ^ sha256_ror(t[0], 13)
                ^ sha256_ror(t[0], 22);
            uint32_t S1 = sha256_ror(t[4], 6) ^ sha256_ror(t[4], 11)
                ^ sha256_ror(t[4], 25);

            uint32_t t1 = t[7] + S1 + ch + sha256_round_k[j] + w[j];
            uint32_t t2 = S0 + maj;

            t[7] = t[6];
            t[6] = t[5];
            t[5] = t[4];
            t[4] = t[3] + t1;
            t[3] = t[2];
            t[2] = t[1];
            t[1] = t[0];
            t[0] = t1 + t2;
        }

        for(int i = 0; i < 8; i++)
            v[i] += t[i];
    }

    for(int i = 0; i < 8; i++)
        sha256_endian_reverse32(v[i], (uint8_t *)output + i * 4);
}
