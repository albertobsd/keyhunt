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

#include "sha256.h"
#include <stdint.h>
#include <string.h>

#ifdef NO_SIMD

#include <stddef.h>

namespace {

static const uint32_t kSha256Init[8] = {
  0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
  0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u
};

static const uint32_t kSha256Round[64] = {
  0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u,
  0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
  0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
  0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
  0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu,
  0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
  0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u,
  0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
  0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
  0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
  0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u,
  0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
  0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u,
  0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
  0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
  0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u
};

inline uint32_t RotR(uint32_t x, uint32_t n) {
  return (x >> n) | (x << (32u - n));
}

inline uint32_t BigSigma0(uint32_t x) {
  return RotR(x, 2) ^ RotR(x, 13) ^ RotR(x, 22);
}

inline uint32_t BigSigma1(uint32_t x) {
  return RotR(x, 6) ^ RotR(x, 11) ^ RotR(x, 25);
}

inline uint32_t SmallSigma0(uint32_t x) {
  return RotR(x, 7) ^ RotR(x, 18) ^ (x >> 3);
}

inline uint32_t SmallSigma1(uint32_t x) {
  return RotR(x, 17) ^ RotR(x, 19) ^ (x >> 10);
}

inline uint32_t Ch(uint32_t x, uint32_t y, uint32_t z) {
  return (x & y) ^ (~x & z);
}

inline uint32_t Maj(uint32_t x, uint32_t y, uint32_t z) {
  return (x & y) ^ (x & z) ^ (y & z);
}

void Compress(uint32_t state[8], const uint32_t block[16]) {
  uint32_t w[64];
  for (int i = 0; i < 16; ++i) {
    w[i] = block[i];
  }
  for (int i = 16; i < 64; ++i) {
    w[i] = SmallSigma1(w[i - 2]) + w[i - 7] + SmallSigma0(w[i - 15]) + w[i - 16];
  }
  uint32_t a = state[0];
  uint32_t b = state[1];
  uint32_t c = state[2];
  uint32_t d = state[3];
  uint32_t e = state[4];
  uint32_t f = state[5];
  uint32_t g = state[6];
  uint32_t h = state[7];
  for (int i = 0; i < 64; ++i) {
    uint32_t t1 = h + BigSigma1(e) + Ch(e, f, g) + kSha256Round[i] + w[i];
    uint32_t t2 = BigSigma0(a) + Maj(a, b, c);
    h = g;
    g = f;
    f = e;
    e = d + t1;
    d = c;
    c = b;
    b = a;
    a = t1 + t2;
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

void DigestFromBlocks(const uint32_t *words, size_t blockCount, uint8_t *digest) {
  uint32_t state[8];
  for (int i = 0; i < 8; ++i) {
    state[i] = kSha256Init[i];
  }
  for (size_t b = 0; b < blockCount; ++b) {
    Compress(state, words + (b * 16));
  }
  for (int i = 0; i < 8; ++i) {
    digest[i * 4 + 0] = static_cast<uint8_t>(state[i] >> 24);
    digest[i * 4 + 1] = static_cast<uint8_t>(state[i] >> 16);
    digest[i * 4 + 2] = static_cast<uint8_t>(state[i] >> 8);
    digest[i * 4 + 3] = static_cast<uint8_t>(state[i]);
  }
}

void DoubleHashChecksum(const uint32_t *words, uint8_t *checksum) {
  uint8_t digest[32];
  DigestFromBlocks(words, 1, digest);
  uint8_t finalDigest[32];
  sha256(digest, 32, finalDigest);
  memcpy(checksum, finalDigest, 4);
}

} // namespace

void sha256sse_1B(
  uint32_t *i0, uint32_t *i1, uint32_t *i2, uint32_t *i3,
  uint8_t *d0, uint8_t *d1, uint8_t *d2, uint8_t *d3) {
  DigestFromBlocks(i0, 1, d0);
  DigestFromBlocks(i1, 1, d1);
  DigestFromBlocks(i2, 1, d2);
  DigestFromBlocks(i3, 1, d3);
}

void sha256sse_2B(
  uint32_t *i0, uint32_t *i1, uint32_t *i2, uint32_t *i3,
  uint8_t *d0, uint8_t *d1, uint8_t *d2, uint8_t *d3) {
  DigestFromBlocks(i0, 2, d0);
  DigestFromBlocks(i1, 2, d1);
  DigestFromBlocks(i2, 2, d2);
  DigestFromBlocks(i3, 2, d3);
}

void sha256sse_checksum(
  uint32_t *i0, uint32_t *i1, uint32_t *i2, uint32_t *i3,
  uint8_t *d0, uint8_t *d1, uint8_t *d2, uint8_t *d3) {
  DoubleHashChecksum(i0, d0);
  DoubleHashChecksum(i1, d1);
  DoubleHashChecksum(i2, d2);
  DoubleHashChecksum(i3, d3);
}

void sha256sse_test() {
  // SSE-specific test not available in scalar fallback.
}

#else

#include <immintrin.h>

namespace _sha256sse
{


#ifdef WIN64
  static const __declspec(align(16)) uint32_t _init[] = {
#else
  static const uint32_t _init[] __attribute__ ((aligned (16))) = {
#endif
      0x6a09e667,0x6a09e667,0x6a09e667,0x6a09e667,
      0xbb67ae85,0xbb67ae85,0xbb67ae85,0xbb67ae85,
      0x3c6ef372,0x3c6ef372,0x3c6ef372,0x3c6ef372,
      0xa54ff53a,0xa54ff53a,0xa54ff53a,0xa54ff53a,
      0x510e527f,0x510e527f,0x510e527f,0x510e527f,
      0x9b05688c,0x9b05688c,0x9b05688c,0x9b05688c,
      0x1f83d9ab,0x1f83d9ab,0x1f83d9ab,0x1f83d9ab,
      0x5be0cd19,0x5be0cd19,0x5be0cd19,0x5be0cd19
  };

//#define Maj(x,y,z) ((x&y)^(x&z)^(y&z))
//#define Ch(x,y,z)  ((x&y)^(~x&z))

// The following functions are equivalent to the above
//#define Maj(x,y,z) ((x & y) | (z & (x | y)))
//#define Ch(x,y,z) (z ^ (x & (y ^ z)))

#define Maj(b,c,d) _mm_or_si128(_mm_and_si128(b, c), _mm_and_si128(d, _mm_or_si128(b, c)) )
#define Ch(b,c,d)  _mm_xor_si128(_mm_and_si128(b, c) , _mm_andnot_si128(b , d) )
#define ROR(x,n)   _mm_or_si128( _mm_srli_epi32(x, n) , _mm_slli_epi32(x, 32 - n) )
#define SHR(x,n)   _mm_srli_epi32(x, n)

  /* SHA256 Functions */
#define	S0(x) (_mm_xor_si128(ROR((x), 2) , _mm_xor_si128(ROR((x), 13), ROR((x), 22))))
#define	S1(x) (_mm_xor_si128(ROR((x), 6) , _mm_xor_si128(ROR((x), 11), ROR((x), 25))))
#define	s0(x) (_mm_xor_si128(ROR((x), 7) , _mm_xor_si128(ROR((x), 18), SHR((x), 3))))
#define	s1(x) (_mm_xor_si128(ROR((x), 17), _mm_xor_si128(ROR((x), 19), SHR((x), 10))))

#define add4(x0, x1, x2, x3) _mm_add_epi32(_mm_add_epi32(x0, x1), _mm_add_epi32(x2, x3))
#define add3(x0, x1, x2 ) _mm_add_epi32(_mm_add_epi32(x0, x1), x2)
#define add5(x0, x1, x2, x3, x4) _mm_add_epi32(add3(x0, x1, x2), _mm_add_epi32(x3, x4))


#define	Round(a, b, c, d, e, f, g, h, i, w)                 \
    T1 = add5(h, S1(e), Ch(e, f, g), _mm_set1_epi32(i), w);	\
    d = _mm_add_epi32(d, T1);                               \
    T2 = _mm_add_epi32(S0(a), Maj(a, b, c));                \
    h = _mm_add_epi32(T1, T2);

#define WMIX() \
  w0 = add4(s1(w14), w9, s0(w1), w0); \
  w1 = add4(s1(w15), w10, s0(w2), w1); \
  w2 = add4(s1(w0), w11, s0(w3), w2); \
  w3 = add4(s1(w1), w12, s0(w4), w3); \
  w4 = add4(s1(w2), w13, s0(w5), w4); \
  w5 = add4(s1(w3), w14, s0(w6), w5); \
  w6 = add4(s1(w4), w15, s0(w7), w6); \
  w7 = add4(s1(w5), w0, s0(w8), w7); \
  w8 = add4(s1(w6), w1, s0(w9), w8); \
  w9 = add4(s1(w7), w2, s0(w10), w9); \
  w10 = add4(s1(w8), w3, s0(w11), w10); \
  w11 = add4(s1(w9), w4, s0(w12), w11); \
  w12 = add4(s1(w10), w5, s0(w13), w12); \
  w13 = add4(s1(w11), w6, s0(w14), w13); \
  w14 = add4(s1(w12), w7, s0(w15), w14); \
  w15 = add4(s1(w13), w8, s0(w0), w15);

  // Initialise state
  void Initialize(__m128i *s) {
    memcpy(s, _init, sizeof(_init));
  }

  // Perform 4 SHA in parallel using SSE2
  void Transform(__m128i *s, uint32_t *b0, uint32_t *b1, uint32_t *b2, uint32_t *b3)
  {
    __m128i a,b,c,d,e,f,g,h;
    __m128i w0, w1, w2, w3, w4, w5, w6, w7;
    __m128i w8, w9, w10, w11, w12, w13, w14, w15;
    __m128i T1, T2;

    a = _mm_load_si128(s + 0);
    b = _mm_load_si128(s + 1);
    c = _mm_load_si128(s + 2);
    d = _mm_load_si128(s + 3);
    e = _mm_load_si128(s + 4);
    f = _mm_load_si128(s + 5);
    g = _mm_load_si128(s + 6);
    h = _mm_load_si128(s + 7);

    w0 = _mm_set_epi32(b0[0], b1[0], b2[0], b3[0]);
    w1 = _mm_set_epi32(b0[1], b1[1], b2[1], b3[1]);
    w2 = _mm_set_epi32(b0[2], b1[2], b2[2], b3[2]);
    w3 = _mm_set_epi32(b0[3], b1[3], b2[3], b3[3]);
    w4 = _mm_set_epi32(b0[4], b1[4], b2[4], b3[4]);
    w5 = _mm_set_epi32(b0[5], b1[5], b2[5], b3[5]);
    w6 = _mm_set_epi32(b0[6], b1[6], b2[6], b3[6]);
    w7 = _mm_set_epi32(b0[7], b1[7], b2[7], b3[7]);
    w8 = _mm_set_epi32(b0[8], b1[8], b2[8], b3[8]);
    w9 = _mm_set_epi32(b0[9], b1[9], b2[9], b3[9]);
    w10 = _mm_set_epi32(b0[10], b1[10], b2[10], b3[10]);
    w11 = _mm_set_epi32(b0[11], b1[11], b2[11], b3[11]);
    w12 = _mm_set_epi32(b0[12], b1[12], b2[12], b3[12]);
    w13 = _mm_set_epi32(b0[13], b1[13], b2[13], b3[13]);
    w14 = _mm_set_epi32(b0[14], b1[14], b2[14], b3[14]);
    w15 = _mm_set_epi32(b0[15], b1[15], b2[15], b3[15]);

    Round(a, b, c, d, e, f, g, h, 0x428A2F98, w0);
    Round(h, a, b, c, d, e, f, g, 0x71374491, w1);
    Round(g, h, a, b, c, d, e, f, 0xB5C0FBCF, w2);
    Round(f, g, h, a, b, c, d, e, 0xE9B5DBA5, w3);
    Round(e, f, g, h, a, b, c, d, 0x3956C25B, w4);
    Round(d, e, f, g, h, a, b, c, 0x59F111F1, w5);
    Round(c, d, e, f, g, h, a, b, 0x923F82A4, w6);
    Round(b, c, d, e, f, g, h, a, 0xAB1C5ED5, w7);
    Round(a, b, c, d, e, f, g, h, 0xD807AA98, w8);
    Round(h, a, b, c, d, e, f, g, 0x12835B01, w9);
    Round(g, h, a, b, c, d, e, f, 0x243185BE, w10);
    Round(f, g, h, a, b, c, d, e, 0x550C7DC3, w11);
    Round(e, f, g, h, a, b, c, d, 0x72BE5D74, w12);
    Round(d, e, f, g, h, a, b, c, 0x80DEB1FE, w13);
    Round(c, d, e, f, g, h, a, b, 0x9BDC06A7, w14);
    Round(b, c, d, e, f, g, h, a, 0xC19BF174, w15);

    WMIX()

    Round(a, b, c, d, e, f, g, h, 0xE49B69C1, w0);
    Round(h, a, b, c, d, e, f, g, 0xEFBE4786, w1);
    Round(g, h, a, b, c, d, e, f, 0x0FC19DC6, w2);
    Round(f, g, h, a, b, c, d, e, 0x240CA1CC, w3);
    Round(e, f, g, h, a, b, c, d, 0x2DE92C6F, w4);
    Round(d, e, f, g, h, a, b, c, 0x4A7484AA, w5);
    Round(c, d, e, f, g, h, a, b, 0x5CB0A9DC, w6);
    Round(b, c, d, e, f, g, h, a, 0x76F988DA, w7);
    Round(a, b, c, d, e, f, g, h, 0x983E5152, w8);
    Round(h, a, b, c, d, e, f, g, 0xA831C66D, w9);
    Round(g, h, a, b, c, d, e, f, 0xB00327C8, w10);
    Round(f, g, h, a, b, c, d, e, 0xBF597FC7, w11);
    Round(e, f, g, h, a, b, c, d, 0xC6E00BF3, w12);
    Round(d, e, f, g, h, a, b, c, 0xD5A79147, w13);
    Round(c, d, e, f, g, h, a, b, 0x06CA6351, w14);
    Round(b, c, d, e, f, g, h, a, 0x14292967, w15);

    WMIX()

    Round(a, b, c, d, e, f, g, h, 0x27B70A85, w0);
    Round(h, a, b, c, d, e, f, g, 0x2E1B2138, w1);
    Round(g, h, a, b, c, d, e, f, 0x4D2C6DFC, w2);
    Round(f, g, h, a, b, c, d, e, 0x53380D13, w3);
    Round(e, f, g, h, a, b, c, d, 0x650A7354, w4);
    Round(d, e, f, g, h, a, b, c, 0x766A0ABB, w5);
    Round(c, d, e, f, g, h, a, b, 0x81C2C92E, w6);
    Round(b, c, d, e, f, g, h, a, 0x92722C85, w7);
    Round(a, b, c, d, e, f, g, h, 0xA2BFE8A1, w8);
    Round(h, a, b, c, d, e, f, g, 0xA81A664B, w9);
    Round(g, h, a, b, c, d, e, f, 0xC24B8B70, w10);
    Round(f, g, h, a, b, c, d, e, 0xC76C51A3, w11);
    Round(e, f, g, h, a, b, c, d, 0xD192E819, w12);
    Round(d, e, f, g, h, a, b, c, 0xD6990624, w13);
    Round(c, d, e, f, g, h, a, b, 0xF40E3585, w14);
    Round(b, c, d, e, f, g, h, a, 0x106AA070, w15);

    WMIX()

    Round(a, b, c, d, e, f, g, h, 0x19A4C116, w0);
    Round(h, a, b, c, d, e, f, g, 0x1E376C08, w1);
    Round(g, h, a, b, c, d, e, f, 0x2748774C, w2);
    Round(f, g, h, a, b, c, d, e, 0x34B0BCB5, w3);
    Round(e, f, g, h, a, b, c, d, 0x391C0CB3, w4);
    Round(d, e, f, g, h, a, b, c, 0x4ED8AA4A, w5);
    Round(c, d, e, f, g, h, a, b, 0x5B9CCA4F, w6);
    Round(b, c, d, e, f, g, h, a, 0x682E6FF3, w7);
    Round(a, b, c, d, e, f, g, h, 0x748F82EE, w8);
    Round(h, a, b, c, d, e, f, g, 0x78A5636F, w9);
    Round(g, h, a, b, c, d, e, f, 0x84C87814, w10);
    Round(f, g, h, a, b, c, d, e, 0x8CC70208, w11);
    Round(e, f, g, h, a, b, c, d, 0x90BEFFFA, w12);
    Round(d, e, f, g, h, a, b, c, 0xA4506CEB, w13);
    Round(c, d, e, f, g, h, a, b, 0xBEF9A3F7, w14);
    Round(b, c, d, e, f, g, h, a, 0xC67178F2, w15);

    s[0] = _mm_add_epi32(a, s[0]);
    s[1] = _mm_add_epi32(b, s[1]);
    s[2] = _mm_add_epi32(c, s[2]);
    s[3] = _mm_add_epi32(d, s[3]);
    s[4] = _mm_add_epi32(e, s[4]);
    s[5] = _mm_add_epi32(f, s[5]);
    s[6] = _mm_add_epi32(g, s[6]);
    s[7] = _mm_add_epi32(h, s[7]);

  }

  // Perform 4 SHA(SHA(bi))[0] in parallel using SSE2
  void Transform2(__m128i *s, uint32_t *b0, uint32_t *b1, uint32_t *b2, uint32_t *b3) {
    __m128i a, b, c, d, e, f, g, h;
    __m128i w0, w1, w2, w3, w4, w5, w6, w7;
    __m128i w8, w9, w10, w11, w12, w13, w14, w15;
    __m128i T1, T2;

    a = _mm_load_si128(s + 0);
    b = _mm_load_si128(s + 1);
    c = _mm_load_si128(s + 2);
    d = _mm_load_si128(s + 3);
    e = _mm_load_si128(s + 4);
    f = _mm_load_si128(s + 5);
    g = _mm_load_si128(s + 6);
    h = _mm_load_si128(s + 7);

    w0 = _mm_set_epi32(b0[0], b1[0], b2[0], b3[0]);
    w1 = _mm_set_epi32(b0[1], b1[1], b2[1], b3[1]);
    w2 = _mm_set_epi32(b0[2], b1[2], b2[2], b3[2]);
    w3 = _mm_set_epi32(b0[3], b1[3], b2[3], b3[3]);
    w4 = _mm_set_epi32(b0[4], b1[4], b2[4], b3[4]);
    w5 = _mm_set_epi32(b0[5], b1[5], b2[5], b3[5]);
    w6 = _mm_set_epi32(b0[6], b1[6], b2[6], b3[6]);
    w7 = _mm_set_epi32(b0[7], b1[7], b2[7], b3[7]);
    w8 = _mm_set_epi32(b0[8], b1[8], b2[8], b3[8]);
    w9 = _mm_set_epi32(b0[9], b1[9], b2[9], b3[9]);
    w10 = _mm_set_epi32(b0[10], b1[10], b2[10], b3[10]);
    w11 = _mm_set_epi32(b0[11], b1[11], b2[11], b3[11]);
    w12 = _mm_set_epi32(b0[12], b1[12], b2[12], b3[12]);
    w13 = _mm_set_epi32(b0[13], b1[13], b2[13], b3[13]);
    w14 = _mm_set_epi32(b0[14], b1[14], b2[14], b3[14]);
    w15 = _mm_set_epi32(b0[15], b1[15], b2[15], b3[15]);

    Round(a, b, c, d, e, f, g, h, 0x428A2F98, w0);
    Round(h, a, b, c, d, e, f, g, 0x71374491, w1);
    Round(g, h, a, b, c, d, e, f, 0xB5C0FBCF, w2);
    Round(f, g, h, a, b, c, d, e, 0xE9B5DBA5, w3);
    Round(e, f, g, h, a, b, c, d, 0x3956C25B, w4);
    Round(d, e, f, g, h, a, b, c, 0x59F111F1, w5);
    Round(c, d, e, f, g, h, a, b, 0x923F82A4, w6);
    Round(b, c, d, e, f, g, h, a, 0xAB1C5ED5, w7);
    Round(a, b, c, d, e, f, g, h, 0xD807AA98, w8);
    Round(h, a, b, c, d, e, f, g, 0x12835B01, w9);
    Round(g, h, a, b, c, d, e, f, 0x243185BE, w10);
    Round(f, g, h, a, b, c, d, e, 0x550C7DC3, w11);
    Round(e, f, g, h, a, b, c, d, 0x72BE5D74, w12);
    Round(d, e, f, g, h, a, b, c, 0x80DEB1FE, w13);
    Round(c, d, e, f, g, h, a, b, 0x9BDC06A7, w14);
    Round(b, c, d, e, f, g, h, a, 0xC19BF174, w15);

    WMIX()

    Round(a, b, c, d, e, f, g, h, 0xE49B69C1, w0);
    Round(h, a, b, c, d, e, f, g, 0xEFBE4786, w1);
    Round(g, h, a, b, c, d, e, f, 0x0FC19DC6, w2);
    Round(f, g, h, a, b, c, d, e, 0x240CA1CC, w3);
    Round(e, f, g, h, a, b, c, d, 0x2DE92C6F, w4);
    Round(d, e, f, g, h, a, b, c, 0x4A7484AA, w5);
    Round(c, d, e, f, g, h, a, b, 0x5CB0A9DC, w6);
    Round(b, c, d, e, f, g, h, a, 0x76F988DA, w7);
    Round(a, b, c, d, e, f, g, h, 0x983E5152, w8);
    Round(h, a, b, c, d, e, f, g, 0xA831C66D, w9);
    Round(g, h, a, b, c, d, e, f, 0xB00327C8, w10);
    Round(f, g, h, a, b, c, d, e, 0xBF597FC7, w11);
    Round(e, f, g, h, a, b, c, d, 0xC6E00BF3, w12);
    Round(d, e, f, g, h, a, b, c, 0xD5A79147, w13);
    Round(c, d, e, f, g, h, a, b, 0x06CA6351, w14);
    Round(b, c, d, e, f, g, h, a, 0x14292967, w15);

    WMIX()

    Round(a, b, c, d, e, f, g, h, 0x27B70A85, w0);
    Round(h, a, b, c, d, e, f, g, 0x2E1B2138, w1);
    Round(g, h, a, b, c, d, e, f, 0x4D2C6DFC, w2);
    Round(f, g, h, a, b, c, d, e, 0x53380D13, w3);
    Round(e, f, g, h, a, b, c, d, 0x650A7354, w4);
    Round(d, e, f, g, h, a, b, c, 0x766A0ABB, w5);
    Round(c, d, e, f, g, h, a, b, 0x81C2C92E, w6);
    Round(b, c, d, e, f, g, h, a, 0x92722C85, w7);
    Round(a, b, c, d, e, f, g, h, 0xA2BFE8A1, w8);
    Round(h, a, b, c, d, e, f, g, 0xA81A664B, w9);
    Round(g, h, a, b, c, d, e, f, 0xC24B8B70, w10);
    Round(f, g, h, a, b, c, d, e, 0xC76C51A3, w11);
    Round(e, f, g, h, a, b, c, d, 0xD192E819, w12);
    Round(d, e, f, g, h, a, b, c, 0xD6990624, w13);
    Round(c, d, e, f, g, h, a, b, 0xF40E3585, w14);
    Round(b, c, d, e, f, g, h, a, 0x106AA070, w15);

    WMIX()

    Round(a, b, c, d, e, f, g, h, 0x19A4C116, w0);
    Round(h, a, b, c, d, e, f, g, 0x1E376C08, w1);
    Round(g, h, a, b, c, d, e, f, 0x2748774C, w2);
    Round(f, g, h, a, b, c, d, e, 0x34B0BCB5, w3);
    Round(e, f, g, h, a, b, c, d, 0x391C0CB3, w4);
    Round(d, e, f, g, h, a, b, c, 0x4ED8AA4A, w5);
    Round(c, d, e, f, g, h, a, b, 0x5B9CCA4F, w6);
    Round(b, c, d, e, f, g, h, a, 0x682E6FF3, w7);
    Round(a, b, c, d, e, f, g, h, 0x748F82EE, w8);
    Round(h, a, b, c, d, e, f, g, 0x78A5636F, w9);
    Round(g, h, a, b, c, d, e, f, 0x84C87814, w10);
    Round(f, g, h, a, b, c, d, e, 0x8CC70208, w11);
    Round(e, f, g, h, a, b, c, d, 0x90BEFFFA, w12);
    Round(d, e, f, g, h, a, b, c, 0xA4506CEB, w13);
    Round(c, d, e, f, g, h, a, b, 0xBEF9A3F7, w14);
    Round(b, c, d, e, f, g, h, a, 0xC67178F2, w15);

    w0 = _mm_add_epi32(a, s[0]);
    w1 = _mm_add_epi32(b, s[1]);
    w2 = _mm_add_epi32(c, s[2]);
    w3 = _mm_add_epi32(d, s[3]);
    w4 = _mm_add_epi32(e, s[4]);
    w5 = _mm_add_epi32(f, s[5]);
    w6 = _mm_add_epi32(g, s[6]);
    w7 = _mm_add_epi32(h, s[7]);
    w8 = _mm_set1_epi32(0x80000000);
    w9 = _mm_xor_si128(w9,w9);
    w10 = _mm_xor_si128(w10, w10);
    w11 = _mm_xor_si128(w11, w11);
    w12 = _mm_xor_si128(w12, w12);
    w13 = _mm_xor_si128(w13, w13);
    w14 = _mm_xor_si128(w14, w14);
    w15 = _mm_set1_epi32(0x100);

    a = _mm_load_si128(s + 0);
    b = _mm_load_si128(s + 1);
    c = _mm_load_si128(s + 2);
    d = _mm_load_si128(s + 3);
    e = _mm_load_si128(s + 4);
    f = _mm_load_si128(s + 5);
    g = _mm_load_si128(s + 6);
    h = _mm_load_si128(s + 7);

    Round(a, b, c, d, e, f, g, h, 0x428A2F98, w0);
    Round(h, a, b, c, d, e, f, g, 0x71374491, w1);
    Round(g, h, a, b, c, d, e, f, 0xB5C0FBCF, w2);
    Round(f, g, h, a, b, c, d, e, 0xE9B5DBA5, w3);
    Round(e, f, g, h, a, b, c, d, 0x3956C25B, w4);
    Round(d, e, f, g, h, a, b, c, 0x59F111F1, w5);
    Round(c, d, e, f, g, h, a, b, 0x923F82A4, w6);
    Round(b, c, d, e, f, g, h, a, 0xAB1C5ED5, w7);
    Round(a, b, c, d, e, f, g, h, 0xD807AA98, w8);
    Round(h, a, b, c, d, e, f, g, 0x12835B01, w9);
    Round(g, h, a, b, c, d, e, f, 0x243185BE, w10);
    Round(f, g, h, a, b, c, d, e, 0x550C7DC3, w11);
    Round(e, f, g, h, a, b, c, d, 0x72BE5D74, w12);
    Round(d, e, f, g, h, a, b, c, 0x80DEB1FE, w13);
    Round(c, d, e, f, g, h, a, b, 0x9BDC06A7, w14);
    Round(b, c, d, e, f, g, h, a, 0xC19BF174, w15);

    WMIX()

    Round(a, b, c, d, e, f, g, h, 0xE49B69C1, w0);
    Round(h, a, b, c, d, e, f, g, 0xEFBE4786, w1);
    Round(g, h, a, b, c, d, e, f, 0x0FC19DC6, w2);
    Round(f, g, h, a, b, c, d, e, 0x240CA1CC, w3);
    Round(e, f, g, h, a, b, c, d, 0x2DE92C6F, w4);
    Round(d, e, f, g, h, a, b, c, 0x4A7484AA, w5);
    Round(c, d, e, f, g, h, a, b, 0x5CB0A9DC, w6);
    Round(b, c, d, e, f, g, h, a, 0x76F988DA, w7);
    Round(a, b, c, d, e, f, g, h, 0x983E5152, w8);
    Round(h, a, b, c, d, e, f, g, 0xA831C66D, w9);
    Round(g, h, a, b, c, d, e, f, 0xB00327C8, w10);
    Round(f, g, h, a, b, c, d, e, 0xBF597FC7, w11);
    Round(e, f, g, h, a, b, c, d, 0xC6E00BF3, w12);
    Round(d, e, f, g, h, a, b, c, 0xD5A79147, w13);
    Round(c, d, e, f, g, h, a, b, 0x06CA6351, w14);
    Round(b, c, d, e, f, g, h, a, 0x14292967, w15);

    WMIX()

    Round(a, b, c, d, e, f, g, h, 0x27B70A85, w0);
    Round(h, a, b, c, d, e, f, g, 0x2E1B2138, w1);
    Round(g, h, a, b, c, d, e, f, 0x4D2C6DFC, w2);
    Round(f, g, h, a, b, c, d, e, 0x53380D13, w3);
    Round(e, f, g, h, a, b, c, d, 0x650A7354, w4);
    Round(d, e, f, g, h, a, b, c, 0x766A0ABB, w5);
    Round(c, d, e, f, g, h, a, b, 0x81C2C92E, w6);
    Round(b, c, d, e, f, g, h, a, 0x92722C85, w7);
    Round(a, b, c, d, e, f, g, h, 0xA2BFE8A1, w8);
    Round(h, a, b, c, d, e, f, g, 0xA81A664B, w9);
    Round(g, h, a, b, c, d, e, f, 0xC24B8B70, w10);
    Round(f, g, h, a, b, c, d, e, 0xC76C51A3, w11);
    Round(e, f, g, h, a, b, c, d, 0xD192E819, w12);
    Round(d, e, f, g, h, a, b, c, 0xD6990624, w13);
    Round(c, d, e, f, g, h, a, b, 0xF40E3585, w14);
    Round(b, c, d, e, f, g, h, a, 0x106AA070, w15);

    WMIX()

    Round(a, b, c, d, e, f, g, h, 0x19A4C116, w0);
    Round(h, a, b, c, d, e, f, g, 0x1E376C08, w1);
    Round(g, h, a, b, c, d, e, f, 0x2748774C, w2);
    Round(f, g, h, a, b, c, d, e, 0x34B0BCB5, w3);
    Round(e, f, g, h, a, b, c, d, 0x391C0CB3, w4);
    Round(d, e, f, g, h, a, b, c, 0x4ED8AA4A, w5);
    Round(c, d, e, f, g, h, a, b, 0x5B9CCA4F, w6);
    Round(b, c, d, e, f, g, h, a, 0x682E6FF3, w7);
    Round(a, b, c, d, e, f, g, h, 0x748F82EE, w8);
    Round(h, a, b, c, d, e, f, g, 0x78A5636F, w9);
    Round(g, h, a, b, c, d, e, f, 0x84C87814, w10);
    Round(f, g, h, a, b, c, d, e, 0x8CC70208, w11);
    Round(e, f, g, h, a, b, c, d, 0x90BEFFFA, w12);
    Round(d, e, f, g, h, a, b, c, 0xA4506CEB, w13);
    Round(c, d, e, f, g, h, a, b, 0xBEF9A3F7, w14);
    Round(b, c, d, e, f, g, h, a, 0xC67178F2, w15);

    s[0] = _mm_add_epi32(a, s[0]);

  }

} // end namespace

void sha256sse_1B(
  uint32_t *i0,
  uint32_t *i1,
  uint32_t *i2,
  uint32_t *i3,
  unsigned char *d0,
  unsigned char *d1,
  unsigned char *d2,
  unsigned char *d3) {

  __m128i s[8];

  _sha256sse::Initialize(s);
  _sha256sse::Transform(s,i0,i1,i2,i3);

  // Unpack
  __m128i mask = _mm_set_epi8(12, 13, 14, 15, /**/ 4, 5, 6, 7,  /**/ 8, 9, 10, 11,  /**/ 0, 1, 2, 3 );

  __m128i u0 = _mm_unpacklo_epi32(s[0], s[1]);   // S2_1 S2_0 S3_1 S3_0
  __m128i u1 = _mm_unpackhi_epi32(s[0], s[1]);   // S0_1 S0_0 S1_1 S1_0

  __m128i u2 = _mm_unpacklo_epi32(s[2], s[3]);   // S2_3 S2_2 S3_3 S3_2
  __m128i u3 = _mm_unpackhi_epi32(s[2], s[3]);   // S0_3 S0_2 S1_3 S1_2

  __m128i _d3 = _mm_unpacklo_epi32(u0, u2);      // S3_3 S3_1 S3_2 S3_0
  __m128i _d2 = _mm_unpackhi_epi32(u0, u2);      // S2_3 S2_1 S2_2 S2_0
  __m128i _d1 = _mm_unpacklo_epi32(u1, u3);      // S1_3 S1_1 S1_2 S1_0
  __m128i _d0 = _mm_unpackhi_epi32(u1, u3);      // S0_3 S0_1 S0_2 S0_0

  _d0 = _mm_shuffle_epi8(_d0, mask);
  _d1 = _mm_shuffle_epi8(_d1, mask);
  _d2 = _mm_shuffle_epi8(_d2, mask);
  _d3 = _mm_shuffle_epi8(_d3, mask);

  _mm_store_si128((__m128i *)d0, _d0);
  _mm_store_si128((__m128i *)d1, _d1);
  _mm_store_si128((__m128i *)d2, _d2);
  _mm_store_si128((__m128i *)d3, _d3);

  // --------------------

  u0 = _mm_unpacklo_epi32(s[4], s[5]);
  u1 = _mm_unpackhi_epi32(s[4], s[5]);

  u2 = _mm_unpacklo_epi32(s[6], s[7]);
  u3 = _mm_unpackhi_epi32(s[6], s[7]);

  _d3 = _mm_unpacklo_epi32(u0, u2);
  _d2 = _mm_unpackhi_epi32(u0, u2);
  _d1 = _mm_unpacklo_epi32(u1, u3);
  _d0 = _mm_unpackhi_epi32(u1, u3);

  _d0 = _mm_shuffle_epi8(_d0, mask);
  _d1 = _mm_shuffle_epi8(_d1, mask);
  _d2 = _mm_shuffle_epi8(_d2, mask);
  _d3 = _mm_shuffle_epi8(_d3, mask);

  _mm_store_si128((__m128i *)(d0 + 16), _d0);
  _mm_store_si128((__m128i *)(d1 + 16), _d1);
  _mm_store_si128((__m128i *)(d2 + 16), _d2);
  _mm_store_si128((__m128i *)(d3 + 16), _d3);

}


void sha256sse_2B(
  uint32_t *i0,
  uint32_t *i1,
  uint32_t *i2,
  uint32_t *i3,
  unsigned char *d0,
  unsigned char *d1,
  unsigned char *d2,
  unsigned char *d3) {

  __m128i s[8];

  _sha256sse::Initialize(s);
  _sha256sse::Transform(s, i0, i1, i2, i3);
  _sha256sse::Transform(s, i0 + 16, i1 + 16, i2 + 16, i3 + 16);

  // Unpack
  __m128i mask = _mm_set_epi8(12, 13, 14, 15, /**/ 4, 5, 6, 7,  /**/ 8, 9, 10, 11,  /**/ 0, 1, 2, 3);

  __m128i u0 = _mm_unpacklo_epi32(s[0], s[1]);   // S2_1 S2_0 S3_1 S3_0
  __m128i u1 = _mm_unpackhi_epi32(s[0], s[1]);   // S0_1 S0_0 S1_1 S1_0

  __m128i u2 = _mm_unpacklo_epi32(s[2], s[3]);   // S2_3 S2_2 S3_3 S3_2
  __m128i u3 = _mm_unpackhi_epi32(s[2], s[3]);   // S0_3 S0_2 S1_3 S1_2

  __m128i _d3 = _mm_unpacklo_epi32(u0, u2);      // S3_3 S3_1 S3_2 S3_0
  __m128i _d2 = _mm_unpackhi_epi32(u0, u2);      // S2_3 S2_1 S2_2 S2_0
  __m128i _d1 = _mm_unpacklo_epi32(u1, u3);      // S1_3 S1_1 S1_2 S1_0
  __m128i _d0 = _mm_unpackhi_epi32(u1, u3);      // S0_3 S0_1 S0_2 S0_0

  _d0 = _mm_shuffle_epi8(_d0, mask);
  _d1 = _mm_shuffle_epi8(_d1, mask);
  _d2 = _mm_shuffle_epi8(_d2, mask);
  _d3 = _mm_shuffle_epi8(_d3, mask);

  _mm_store_si128((__m128i *)d0, _d0);
  _mm_store_si128((__m128i *)d1, _d1);
  _mm_store_si128((__m128i *)d2, _d2);
  _mm_store_si128((__m128i *)d3, _d3);

  // --------------------

  u0 = _mm_unpacklo_epi32(s[4], s[5]);
  u1 = _mm_unpackhi_epi32(s[4], s[5]);

  u2 = _mm_unpacklo_epi32(s[6], s[7]);
  u3 = _mm_unpackhi_epi32(s[6], s[7]);

  _d3 = _mm_unpacklo_epi32(u0, u2);
  _d2 = _mm_unpackhi_epi32(u0, u2);
  _d1 = _mm_unpacklo_epi32(u1, u3);
  _d0 = _mm_unpackhi_epi32(u1, u3);

  _d0 = _mm_shuffle_epi8(_d0, mask);
  _d1 = _mm_shuffle_epi8(_d1, mask);
  _d2 = _mm_shuffle_epi8(_d2, mask);
  _d3 = _mm_shuffle_epi8(_d3, mask);

  _mm_store_si128((__m128i *)(d0 + 16), _d0);
  _mm_store_si128((__m128i *)(d1 + 16), _d1);
  _mm_store_si128((__m128i *)(d2 + 16), _d2);
  _mm_store_si128((__m128i *)(d3 + 16), _d3);

}

void sha256sse_checksum(uint32_t *i0, uint32_t *i1, uint32_t *i2, uint32_t *i3,
  uint8_t *d0, uint8_t *d1, uint8_t *d2, uint8_t *d3) {

  __m128i s[8];

  _sha256sse::Initialize(s);
  _sha256sse::Transform2(s, i0, i1, i2, i3);

#ifndef WIN64
  uint32_t *s32 = (uint32_t *)(&s[0]);
  *((uint32_t *)d0) = __builtin_bswap32(s32[3]);
  *((uint32_t *)d1) = __builtin_bswap32(s32[2]);
  *((uint32_t *)d2) = __builtin_bswap32(s32[1]);
  *((uint32_t *)d3) = __builtin_bswap32(s32[0]);
#else
  *((uint32_t *)d0) = _byteswap_ulong(s[0].m128i_u32[3]);
  *((uint32_t *)d1) = _byteswap_ulong(s[0].m128i_u32[2]);
  *((uint32_t *)d2) = _byteswap_ulong(s[0].m128i_u32[1]);
  *((uint32_t *)d3) = _byteswap_ulong(s[0].m128i_u32[0]);
#endif

}

#if 0
void sha256sse_test() {

  unsigned char h0[32];
  unsigned char h1[32];
  unsigned char h2[32];
  unsigned char h3[32];
  unsigned char ch0[32];
  unsigned char ch1[32];
  unsigned char ch2[32];
  unsigned char ch3[32];
  unsigned char m0[64];
  unsigned char m1[64];
  unsigned char m2[64];
  unsigned char m3[64];

  strcpy((char *)m0, "This is a test message to test 01");
  strcpy((char *)m1, "This is a test message to test 02");
  strcpy((char *)m2, "This is a test message to test 03");
  strcpy((char *)m3, "This is a test message to test 04");

  sha256_33(m0, ch0);
  sha256_33(m1, ch1);
  sha256_33(m2, ch2);
  sha256_33(m3, ch3);

  sha256sse_33(m0,m1,m2,m3,h0,h1,h2,h3);

  if((sha256_hex(h0) != sha256_hex(ch0)) ||
     (sha256_hex(h1) != sha256_hex(ch1)) ||
     (sha256_hex(h2) != sha256_hex(ch2)) ||
     (sha256_hex(h3) != sha256_hex(ch3))) {

    printf("SHA() Results Wrong !\n");
    printf("SHA: %s\n", sha256_hex(ch0).c_str());
    printf("SHA: %s\n", sha256_hex(ch1).c_str());
    printf("SHA: %s\n", sha256_hex(ch2).c_str());
    printf("SHA: %s\n\n", sha256_hex(ch3).c_str());
    printf("SSE: %s\n", sha256_hex(h0).c_str());
    printf("SSE: %s\n", sha256_hex(h1).c_str());
    printf("SSE: %s\n", sha256_hex(h2).c_str());
    printf("SSE: %s\n\n", sha256_hex(h3).c_str());

  }

  printf("SHA() Results OK !\n");

}
#endif

#endif  // NO_SIMD
