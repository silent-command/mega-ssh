#include "crypto.h"

#define ROTL(x, n) (((x) << (n)) | ((x) >> (32 - (n))))
#define QR(a, b, c, d) \
  a += b; d ^= a; d = ROTL(d, 16); \
  c += d; b ^= c; b = ROTL(b, 12); \
  a += b; d ^= a; d = ROTL(d, 8);  \
  c += d; b ^= c; b = ROTL(b, 7);

static uint32_t le32(const uint8_t *p)
{
  return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

/* The state's words 12-15 are the counter and nonce; the two forms
 * differ only in how those four words are filled. */
static void block(const uint32_t in[16], uint8_t out[64])
{
  static uint32_t x[16];
  unsigned i;
  for (i = 0; i < 16; i++) x[i] = in[i];
  for (i = 0; i < 10; i++) {
    QR(x[0], x[4], x[8], x[12])  QR(x[1], x[5], x[9], x[13])
    QR(x[2], x[6], x[10], x[14]) QR(x[3], x[7], x[11], x[15])
    QR(x[0], x[5], x[10], x[15]) QR(x[1], x[6], x[11], x[12])
    QR(x[2], x[7], x[8], x[13])  QR(x[3], x[4], x[9], x[14])
  }
  for (i = 0; i < 16; i++) {
    uint32_t v = x[i] + in[i];
    out[4 * i] = (uint8_t)v; out[4 * i + 1] = (uint8_t)(v >> 8);
    out[4 * i + 2] = (uint8_t)(v >> 16); out[4 * i + 3] = (uint8_t)(v >> 24);
  }
}

static void setup(uint32_t st[16], const uint8_t key[32])
{
  unsigned i;
  st[0] = 0x61707865; st[1] = 0x3320646e; st[2] = 0x79622d32; st[3] = 0x6b206574;
  for (i = 0; i < 8; i++) st[4 + i] = le32(key + 4 * i);
}

void chacha20_block(const uint8_t key[32], const uint8_t nonce[12], uint32_t counter, uint8_t out[64])
{
  static uint32_t st[16];
  setup(st, key);
  st[12] = counter; st[13] = le32(nonce); st[14] = le32(nonce + 4); st[15] = le32(nonce + 8);
  block(st, out);
}

void chacha20_block64(const uint8_t key[32], const uint8_t nonce[8], uint64_t counter, uint8_t out[64])
{
  static uint32_t st[16];
  setup(st, key);
  st[12] = (uint32_t)counter; st[13] = (uint32_t)(counter >> 32);
  st[14] = le32(nonce); st[15] = le32(nonce + 4);
  block(st, out);
}

void chacha20_xor(const uint8_t key[32], const uint8_t nonce[12], uint32_t counter, uint8_t *p, size_t n)
{
  static uint8_t ks[64];
  while (n) {
    size_t i, take = n < 64 ? n : 64;
    chacha20_block(key, nonce, counter++, ks);
    for (i = 0; i < take; i++) p[i] ^= ks[i];
    p += take; n -= take;
  }
}

void chacha20_xor64(const uint8_t key[32], const uint8_t nonce[8], uint64_t counter, uint8_t *p, size_t n)
{
  static uint8_t ks[64];
  while (n) {
    size_t i, take = n < 64 ? n : 64;
    chacha20_block64(key, nonce, counter++, ks);
    for (i = 0; i < take; i++) p[i] ^= ks[i];
    p += take; n -= take;
  }
}
