/*
 * This file is part of the VanitySearch distribution (https://github.com/JeanLucPons/VanitySearch).
 * Copyright (c) 2019 Jean Luc PONS.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
*/

#include <string.h>
#include "sha512.h"

#define BSWAP
#define SHA512_BLOCK_SIZE	128
#define SHA512_HASH_LENGTH	64
#define MIN(x,y) (x<y)?x:y;
#define MAX(x,y) (x>y)?x:y;

/// Internal SHA-512 implementation.
namespace _sha512 {

  static const uint64_t K[80] = {
  0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL,
  0xe9b5dba58189dbbcULL, 0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL,
  0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL, 0xd807aa98a3030242ULL,
  0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
  0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL,
  0xc19bf174cf692694ULL, 0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL,
  0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL, 0x2de92c6f592b0275ULL,
  0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
  0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL,
  0xbf597fc7beef0ee4ULL, 0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL,
  0x06ca6351e003826fULL, 0x142929670a0e6e70ULL, 0x27b70a8546d22ffcULL,
  0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
  0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL,
  0x92722c851482353bULL, 0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL,
  0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL, 0xd192e819d6ef5218ULL,
  0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
  0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL,
  0x34b0bcb5e19b48a8ULL, 0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL,
  0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL, 0x748f82ee5defb2fcULL,
  0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
  0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL,
  0xc67178f2e372532bULL, 0xca273eceea26619cULL, 0xd186b8c721c0c207ULL,
  0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL, 0x06f067aa72176fbaULL,
  0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
  0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL,
  0x431d67c49c100d4cULL, 0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL,
  0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL
  };

#ifndef WIN64
#define _byteswap_ulong __builtin_bswap32
#define _byteswap_uint64 __builtin_bswap64
inline uint64_t _rotr64(uint64_t x, uint8_t r) {
  asm("rorq %1,%0" : "+r" (x) : "c" (r));
  return x;
}
#endif

#define ROR(x,n) _rotr64(x, n)
#define S0(x)		(ROR(x, 28) ^ ROR(x, 34) ^ ROR(x, 39))
#define S1(x)		(ROR(x, 14) ^ ROR(x, 18) ^ ROR(x, 41))
#define G0(x)		(ROR(x, 1) ^ ROR(x, 8) ^ (x >> 7))
#define G1(x)		(ROR(x, 19) ^ ROR(x, 61) ^ (x >> 6))

#define ROUND(i, a,b,c,d,e,f,g,h)			\
     t = h + S1(e) + (g ^ (e & (f ^ g))) + K[i] + W[i];	\
     d += t;						\
     h  = t + S0(a) + ( ((a | b) & c) | (a & b) )

#ifdef BSWAP
  #define READBE64(ptr) _byteswap_uint64(*(uint64_t *)(ptr));
  #define WRITEBE64(ptr,x) *((uint64_t *)(ptr)) = _byteswap_uint64(x);
  #define READBE32(i) _byteswap_ulong((uint32_t)(i));
#else
  #define READBE64(ptr) *(uint64_t *)(ptr);
  #define WRITEBE64(ptr,x) *(ptr) = x;
  #define READBE32(i) (uint32_t)(i);
#endif

static void Transform(uint64_t state[8], const uint8_t buf[128]) {

    uint64_t W[80], t;
    uint64_t a, b, c, d, e, f, g, h;
    int i;

    a = state[0];
    b = state[1];
    c = state[2];
    d = state[3];
    e = state[4];
    f = state[5];
    g = state[6];
    h = state[7];

    W[0] = READBE64(buf + 0x0);
    W[1] = READBE64(buf + 0x8);
    W[2] = READBE64(buf + 0x10);
    W[3] = READBE64(buf + 0x18);
    W[4] = READBE64(buf + 0x20);
    W[5] = READBE64(buf + 0x28);
    W[6] = READBE64(buf + 0x30);
    W[7] = READBE64(buf + 0x38);
    W[8] = READBE64(buf + 0x40);
    W[9] = READBE64(buf + 0x48);
    W[10] = READBE64(buf + 0x50);
    W[11] = READBE64(buf + 0x58);
    W[12] = READBE64(buf + 0x60);
    W[13] = READBE64(buf + 0x68);
    W[14] = READBE64(buf + 0x70);
    W[15] = READBE64(buf + 0x78);

    for(i = 16; i < 80; i++)
      W[i] = W[i - 16] + G0(W[i - 15]) + W[i - 7] + G1(W[i - 2]);

    for (i = 0; i < 80; i += 8) {
      ROUND(i + 0, a, b, c, d, e, f, g, h);
      ROUND(i + 1, h, a, b, c, d, e, f, g);
      ROUND(i + 2, g, h, a, b, c, d, e, f);
      ROUND(i + 3, f, g, h, a, b, c, d, e);
      ROUND(i + 4, e, f, g, h, a, b, c, d);
      ROUND(i + 5, d, e, f, g, h, a, b, c);
      ROUND(i + 6, c, d, e, f, g, h, a, b);
      ROUND(i + 7, b, c, d, e, f, g, h, a);
    }

    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
    state[5] += f;
    state[6] += g;
    state[7] += h;

}


}


class CSHA512 {

private:
  uint64_t s[8];
  unsigned char buf[128];
  size_t buffSize;
  size_t count;

public:

  CSHA512();
  void Initialize();
  void Write(const unsigned char* data, size_t len);
  void WriteDirect128(const unsigned char* data);
  void WriteDirect64(const unsigned char* data);
  void Finalize(unsigned char hash[64]);

};

CSHA512::CSHA512() {

  Initialize();

}

void CSHA512::Initialize() {

  buffSize = 0;
  count = 0;
  s[0] = 0x6a09e667f3bcc908ULL;
  s[1] = 0xbb67ae8584caa73bULL;
  s[2] = 0x3c6ef372fe94f82bULL;
  s[3] = 0xa54ff53a5f1d36f1ULL;
  s[4] = 0x510e527fade682d1ULL;
  s[5] = 0x9b05688c2b3e6c1fULL;
  s[6] = 0x1f83d9abfb41bd6bULL;
  s[7] = 0x5be0cd19137e2179ULL;

}

void CSHA512::Write(const unsigned char* data, size_t len) {

    if (buffSize > 0) {

      // Fill internal buffer up and transform
      size_t fill = MIN(len,128-buffSize);
      memcpy(buf+buffSize,data, fill);
      len -= fill;
      buffSize += fill;
      if(buffSize < 128)
        return;
      _sha512::Transform(s, buf);
      count++;

    }

    // Internal buffer is empty
    while (len >= 128) {
      _sha512::Transform(s, data);
      count++;
      data += 128;
      len -= 128;
    }

    // save rest for next time
    memcpy(buf,data,len);
    buffSize = len;

}

// Write 128 bytes aligned (buffsize must be 0)
void CSHA512::WriteDirect128(const unsigned char* data) {
  _sha512::Transform(s, data);
  count++;
}

// Write 64 bytes aligned (buffsize must be 0)
void CSHA512::WriteDirect64(const unsigned char* data) {
  memcpy(buf, data, 64);
  buffSize = 64;
}

void CSHA512::Finalize(unsigned char hash[64]) {

    size_t rest;
    size_t i;

    rest = buffSize;

    // End code
    buf[buffSize++] = 0x80;

    if (buffSize > 112) {
      memset(buf+buffSize,0,128-buffSize);
      _sha512::Transform(s, buf);
      buffSize = 0;
    }
    memset(buf+buffSize,0,112-buffSize);

    // Write length (128bit big-endian)
    WRITEBE64(buf + 112, count >> 54);
    WRITEBE64(buf + 120, ((count << 7) | rest) << 3);
    _sha512::Transform(s, buf);

    for (i = 0; i < 8; i++)
      WRITEBE64(hash + 8 * i, s[i]);

}


/* padding */
#define IPAD	  0x36
#define IPADLL	0x3636363636363636LL
#define OPAD	  0x5c
#define OPADLL  0x5c5c5c5c5c5c5c5cLL

void hmac_sha512_init(CSHA512 &ctx, const uint8_t key[SHA512_BLOCK_SIZE]) {

  uint64_t pad[SHA512_BLOCK_SIZE/8];
  uint64_t *keyPtr = (uint64_t *)key;
  int i;

  // Inner padding
  for (i = 0; i < SHA512_BLOCK_SIZE/8; i++)
    pad[i] = keyPtr[i] ^ IPADLL;

  ctx.Initialize();
  ctx.WriteDirect128((unsigned char *)pad);

}


void hmac_sha512_done(CSHA512 &ctx, const uint8_t key[SHA512_BLOCK_SIZE], uint8_t result[SHA512_HASH_LENGTH]) {

  uint64_t pad[SHA512_BLOCK_SIZE/8];
  uint64_t *keyPtr = (uint64_t *)key;
  uint8_t ihash[SHA512_HASH_LENGTH];
  int i;

  // Finalize inner hash
  ctx.Finalize(ihash);

  // Construct outer padding
  for (i = 0; i < SHA512_BLOCK_SIZE/8; i++)
    pad[i] = keyPtr[i] ^ OPADLL;

  // Final hash
  CSHA512 c;
  c.WriteDirect128((unsigned char *)pad);
  c.WriteDirect64(ihash);
  c.Finalize(result);

}


void pbkdf2_hmac_sha512(uint8_t *out, size_t outlen,
  const uint8_t *passwd, size_t passlen,
  const uint8_t *salt, size_t saltlen,
  uint64_t iter) {

  CSHA512 hmac, hmac_template;
  uint32_t i, be32i;
  uint64_t j;
  int k;

  uint8_t key[SHA512_BLOCK_SIZE];
  uint8_t	F[SHA512_HASH_LENGTH], U[SHA512_HASH_LENGTH];
  uint64_t *Fptr = (uint64_t *)F;
  uint64_t *Uptr = (uint64_t *)U;
  size_t need;

  if (passlen < SHA512_BLOCK_SIZE) {
    memcpy(key, passwd, passlen);
    memset(key + passlen, 0, SHA512_BLOCK_SIZE - passlen);
  } else {
    hmac.Write(passwd, passlen);
    hmac.Finalize(key);
    memset(key + SHA512_HASH_LENGTH, 0, SHA512_BLOCK_SIZE - SHA512_HASH_LENGTH);
  }

  hmac_sha512_init(hmac_template, key);
  hmac_template.Write(salt, saltlen);

  for (i = 1; outlen > 0; i++) {

    hmac = hmac_template;
    be32i = READBE32(i);
    hmac.Write((unsigned char *)&be32i, sizeof(be32i));
    hmac_sha512_done(hmac, key, U);
    memcpy(F, U, SHA512_HASH_LENGTH);

    for (j = 2; j <= iter; j++) {
      hmac_sha512_init(hmac, key);
      hmac.WriteDirect64(U);
      hmac_sha512_done(hmac, key, U);
      for (k = 0; k < SHA512_HASH_LENGTH/8; k++)
        Fptr[k] ^= Uptr[k];
    }

    need = MIN(SHA512_HASH_LENGTH, outlen);

    memcpy(out, F, need);
    out += need;
    outlen -= need;

  }

}

void hmac_sha512(unsigned char *key, int key_length, unsigned char *message, int message_length, unsigned char *digest) {

  uint8_t ipad[SHA512_BLOCK_SIZE];
  uint8_t opad[SHA512_BLOCK_SIZE];
  uint8_t hash[SHA512_HASH_LENGTH];
  int i;

  // TODO Handle key larger than 128

  for (i = 0; i < key_length && i < SHA512_BLOCK_SIZE; i++) {
    ipad[i] = key[i] ^ IPAD;
    opad[i] = key[i] ^ OPAD;
  }
  for (; i < SHA512_BLOCK_SIZE; i++) {
    ipad[i] = IPAD;
    opad[i] = OPAD;
  }

  CSHA512 h;
  h.WriteDirect128(ipad);
  h.Write(message, message_length);
  h.Finalize(hash);

  h.Initialize();
  h.WriteDirect128(opad);
  h.Write(hash, SHA512_HASH_LENGTH);
  h.Finalize(digest);

}

void sha512(unsigned char *input, int length, unsigned char *digest) {

  CSHA512 sha;
  sha.Write(input, length);
  sha.Finalize(digest);

}

std::string sha512_hex(unsigned char *digest) {

  char buf[2 * 64 + 1];
  buf[2 * 64] = 0;
  for (int i = 0; i < 64; i++)
    sprintf(buf + i * 2, "%02x", digest[i]);
  return std::string(buf);

}
