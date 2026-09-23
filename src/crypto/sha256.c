#include "crypto.h"

static const uint32_t K[64] = {
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

/* A rotate as a call, as in sha512.c: the inline expansions were most
 * of a 3 KB compression, and this hash is per login, not per packet (5.22). */
static uint32_t __attribute__((noinline)) ROR(uint32_t x, uint8_t n)
{
  uint8_t q = (uint8_t)(n >> 3), r = (uint8_t)(n & 7);
  while (q--) x = (x >> 8) | (x << 24);
  while (r--) x = (x >> 1) | (x << 31);
  return x;
}

static void compress(uint32_t h[8], const uint8_t blk[64])
{
  static uint32_t w[16];                /* a rolling schedule, as in sha512.c (5.22) */
  static uint32_t a, b, c, d, e, f, g, hh, t1, t2, S0, S1, ch, maj;
  unsigned i;
  for (i = 0; i < 16; i++)
    w[i] = ((uint32_t)blk[4 * i] << 24) | ((uint32_t)blk[4 * i + 1] << 16) | ((uint32_t)blk[4 * i + 2] << 8) | blk[4 * i + 3];
  a = h[0]; b = h[1]; c = h[2]; d = h[3]; e = h[4]; f = h[5]; g = h[6]; hh = h[7];
  for (i = 0; i < 64; i++) {
    if (i >= 16) {
      uint32_t s0 = ROR(w[(i - 15) & 15], 7) ^ ROR(w[(i - 15) & 15], 18) ^ (w[(i - 15) & 15] >> 3);
      uint32_t s1 = ROR(w[(i - 2) & 15], 17) ^ ROR(w[(i - 2) & 15], 19) ^ (w[(i - 2) & 15] >> 10);
      w[i & 15] += s0 + w[(i - 7) & 15] + s1;
    }
    S1 = ROR(e, 6) ^ ROR(e, 11) ^ ROR(e, 25);
    ch = (e & f) ^ (~e & g);
    S0 = ROR(a, 2) ^ ROR(a, 13) ^ ROR(a, 22);
    maj = (a & b) ^ (a & c) ^ (b & c);
    t1 = hh + S1 + ch + K[i] + w[i & 15];
    t2 = S0 + maj;
    hh = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
  }
  h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
}

void sha256_init(sha256_ctx *c)
{
  static const uint32_t iv[8] = { 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                                  0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 };
  unsigned i;
  for (i = 0; i < 8; i++) c->h[i] = iv[i];
  c->len = 0; c->total_lo = 0; c->total_hi = 0;
}

void sha256_update(sha256_ctx *c, const uint8_t *p, size_t n)
{
  while (n) {
    size_t take = 64 - c->len;
    if (take > n) take = n;
    {
      size_t i;
      for (i = 0; i < take; i++) c->buf[c->len + i] = p[i];
    }
    c->len = (uint8_t)(c->len + take); p += take; n -= take;
    c->total_lo += (uint32_t)take;
    if (c->total_lo < (uint32_t)take) c->total_hi++;
    if (c->len == 64) { compress(c->h, c->buf); c->len = 0; }
  }
}

void sha256_final(sha256_ctx *c, uint8_t out[32])
{
  uint64_t bits = ((uint64_t)c->total_hi << 32 | c->total_lo) * 8;
  unsigned i;
  c->buf[c->len++] = 0x80;
  if (c->len > 56) {
    while (c->len < 64) c->buf[c->len++] = 0;
    compress(c->h, c->buf); c->len = 0;
  }
  while (c->len < 56) c->buf[c->len++] = 0;
  for (i = 0; i < 8; i++) c->buf[56 + i] = (uint8_t)(bits >> (56 - 8 * i));
  compress(c->h, c->buf);
  for (i = 0; i < 8; i++) {
    out[4 * i] = (uint8_t)(c->h[i] >> 24); out[4 * i + 1] = (uint8_t)(c->h[i] >> 16);
    out[4 * i + 2] = (uint8_t)(c->h[i] >> 8); out[4 * i + 3] = (uint8_t)c->h[i];
  }
}

void sha256(const uint8_t *p, size_t n, uint8_t out[32])
{
  sha256_ctx c;
  sha256_init(&c); sha256_update(&c, p, n); sha256_final(&c, out);
}
