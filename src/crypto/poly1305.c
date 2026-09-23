/* Poly1305 in seventeen 8-bit limbs with 32-bit sums, the arrangement
 * TweetNaCl uses (public domain): no 64-bit arithmetic anywhere, which
 * on a 6502 is the difference between 9 KB of code and a small loop.
 * 289 multiply-adds per 16-byte block, all of them 8x8 -> 16 bit. */
#include "crypto.h"

static void add1305(uint32_t *h, const uint32_t *c)
{
  uint32_t u = 0;
  unsigned j;
  for (j = 0; j < 17; j++) { u += h[j] + c[j]; h[j] = u & 255; u >>= 8; }
}

void poly1305_init(poly1305_ctx *c, const uint8_t key[32])
{
  unsigned j;
  for (j = 0; j < 17; j++) c->h[j] = 0;
  for (j = 0; j < 16; j++) c->r[j] = key[j];
  c->r[16] = 0;
  c->r[3] &= 15; c->r[4] &= 252; c->r[7] &= 15; c->r[8] &= 252;
  c->r[11] &= 15; c->r[12] &= 252; c->r[15] &= 15;
  for (j = 0; j < 16; j++) c->s[j] = key[16 + j];
  c->len = 0;
  c->rr_ready = 0;
}

#ifdef __mos__
/* The 17 column sums come from the assembly loop in mulacc_m65.S. */
uint8_t poly_mul_h[17];
uint32_t poly_mul_rr[34], poly_mul_x[17];
void poly_mul_m65(void);
#endif

/* One block of n bytes (1 to 16), padded with the 1 byte as the RFC says. */
static void block(poly1305_ctx *c, const uint8_t *m, unsigned n)
{
  static uint32_t cc[17];
  uint32_t u;
  unsigned i, j;
  for (j = 0; j < 17; j++) cc[j] = 0;
  for (j = 0; j < n; j++) cc[j] = m[j];
  cc[j] = 1;
  add1305(c->h, cc);
#ifdef __mos__
  for (j = 0; j < 17; j++) poly_mul_h[j] = (uint8_t)c->h[j];
  if (!c->rr_ready) {
    for (j = 0; j < 17; j++) { poly_mul_rr[j] = 320 * c->r[j]; poly_mul_rr[17 + j] = c->r[j]; }
    c->rr_ready = 1;
  }
  poly_mul_m65();
  for (i = 0; i < 17; i++) c->h[i] = poly_mul_x[i];
#else
  {
    static uint32_t x[17];
    for (i = 0; i < 17; i++) {
      x[i] = 0;
      for (j = 0; j < 17; j++)
        x[i] += c->h[j] * ((j <= i) ? c->r[i - j] : 320 * c->r[i + 17 - j]);
    }
    for (i = 0; i < 17; i++) c->h[i] = x[i];
  }
#endif
  u = 0;
  for (j = 0; j < 16; j++) { u += c->h[j]; c->h[j] = u & 255; u >>= 8; }
  u += c->h[16]; c->h[16] = u & 3;
  u = 5 * (u >> 2);
  for (j = 0; j < 16; j++) { u += c->h[j]; c->h[j] = u & 255; u >>= 8; }
  u += c->h[16]; c->h[16] = u;
}

void poly1305_update(poly1305_ctx *c, const uint8_t *p, size_t n)
{
  size_t i;
  if (c->len) {
    size_t take = 16 - c->len;
    if (take > n) take = n;
    for (i = 0; i < take; i++) c->buf[c->len + i] = p[i];
    c->len = (uint8_t)(c->len + take); p += take; n -= take;
    if (c->len < 16) return;
    block(c, c->buf, 16); c->len = 0;
  }
  while (n >= 16) { block(c, p, 16); p += 16; n -= 16; }
  for (i = 0; i < n; i++) c->buf[i] = p[i];
  c->len = (uint8_t)n;
}

void poly1305_final(poly1305_ctx *c, uint8_t tag[16])
{
  static const uint32_t minusp[17] = { 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 252 };
  static uint32_t g[17], cc[17];
  uint32_t s;
  unsigned j;
  if (c->len) block(c, c->buf, c->len);
  for (j = 0; j < 17; j++) g[j] = c->h[j];
  add1305(c->h, minusp);
  s = 0 - (c->h[16] >> 7);
  for (j = 0; j < 17; j++) c->h[j] ^= s & (g[j] ^ c->h[j]);
  for (j = 0; j < 16; j++) cc[j] = c->s[j];
  cc[16] = 0;
  add1305(c->h, cc);
  for (j = 0; j < 16; j++) tag[j] = (uint8_t)c->h[j];
}

void poly1305(const uint8_t key[32], const uint8_t *p, size_t n, uint8_t tag[16])
{
  static poly1305_ctx c;
  poly1305_init(&c, key); poly1305_update(&c, p, n); poly1305_final(&c, tag);
}
