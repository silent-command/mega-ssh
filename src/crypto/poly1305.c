/* Poly1305 in 32-bit limbs, the arrangement OpenSSL uses on 32-bit
 * machines (radix 2^32, h in five words, r in four): 20 products of
 * 32 x 32 bits per 16-byte block, which is what the MEGA65's math unit
 * multiplies. The first version used TweetNaCl's seventeen 8-bit limbs,
 * 289 products and 17-limb carry loops, and spent 80 ms a kilobyte on
 * the machine, three times ChaCha20 (REQUIREMENTS.md 5.21).
 *
 * The clamp makes r[1..3] multiples of 4, so 2^128 * r[i] folds to
 * 5 r[i] / 4 exactly modulo 2^130 - 5, and h[4] * r[0] stays at 2^128.
 * On the host one block is the C below; on the target it is
 * poly_block_m65 in mulacc_m65.S, which works on fixed buffers: this
 * file copies a context in and out around every update, so any number
 * of contexts may interleave. The context holds bytes, and everything
 * outside the block is byte loops: 32-bit arithmetic in C costs this
 * compiler a kilobyte here. The same test vectors check both. */
#include <string.h>
#include "crypto.h"

void poly1305_init(poly1305_ctx *c, const uint8_t key[32])
{
  static const uint8_t clamp[16] = { 255, 255, 255, 15, 252, 255, 255, 15, 252, 255, 255, 15, 252, 255, 255, 15 };
  uint8_t *r = c->rr + 16, *s;
  unsigned i, j, u;
  for (j = 0; j < 16; j++) r[j] = key[j] & clamp[j];
  for (i = 1; i < 4; i++) {                       /* 5 r[i] / 4 = r[i] + (r[i] >> 2) */
    s = c->rr + 4 * i; u = 0;
    for (j = 0; j < 4; j++) {
      u += r[4 * i + j] + (uint8_t)((r[4 * i + j] >> 2) | (j < 3 ? r[4 * i + j + 1] << 6 : 0));
      s[j] = (uint8_t)u; u >>= 8;
    }
  }
  for (j = 0; j < 4; j++) c->rr[j] = 0;
  for (j = 0; j < 20; j++) c->h[j] = 0;
  for (j = 0; j < 16; j++) c->s[j] = key[16 + j];
  c->len = 0;
}

#ifdef __mos__
/* The assembly's buffers: h (20 bytes), the multipliers (32), the block
 * (16) and the 2^128 bit (1 for a full block, 0 for the padded last). */
uint8_t poly_h[20], poly_rr[32], poly_m[16], poly_hibit;
void poly_block_m65(void);

static void load(const poly1305_ctx *c)
{
  memcpy(poly_h, c->h, 20);
  memcpy(poly_rr, c->rr, 32);
}

static void store(poly1305_ctx *c)
{
  memcpy(c->h, poly_h, 20);
}

static void block(const uint8_t *m, uint8_t hibit)
{
  memcpy(poly_m, m, 16);
  poly_hibit = hibit;
  poly_block_m65();
}
#else
static uint32_t ph[5], pr[8];

static uint32_t le32(const uint8_t *p)
{
  return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static void load(const poly1305_ctx *c)
{
  unsigned j;
  for (j = 0; j < 5; j++) ph[j] = le32(c->h + 4 * j);
  for (j = 0; j < 8; j++) pr[j] = le32(c->rr + 4 * j);
}

static void store(poly1305_ctx *c)
{
  unsigned j;
  for (j = 0; j < 20; j++) c->h[j] = (uint8_t)(ph[j / 4] >> (8 * (j % 4)));
}

/* h = (h + m + hibit 2^128) * r, partly reduced: what poly_block_m65 does. */
static void block(const uint8_t *m, uint8_t hibit)
{
  const uint32_t *s = pr, *r = pr + 4;
  uint64_t d0, d1, d2, d3;
  uint32_t h0, h1, h2, h3, h4, c;

  h0 = (uint32_t)(d0 = (uint64_t)ph[0] + le32(m));
  h1 = (uint32_t)(d1 = (uint64_t)ph[1] + (d0 >> 32) + le32(m + 4));
  h2 = (uint32_t)(d2 = (uint64_t)ph[2] + (d1 >> 32) + le32(m + 8));
  h3 = (uint32_t)(d3 = (uint64_t)ph[3] + (d2 >> 32) + le32(m + 12));
  h4 = ph[4] + (uint32_t)(d3 >> 32) + hibit;

  d0 = (uint64_t)h0 * r[0] + (uint64_t)h1 * s[3] + (uint64_t)h2 * s[2] + (uint64_t)h3 * s[1];
  d1 = (uint64_t)h0 * r[1] + (uint64_t)h1 * r[0] + (uint64_t)h2 * s[3] + (uint64_t)h3 * s[2] + (uint64_t)h4 * s[1];
  d2 = (uint64_t)h0 * r[2] + (uint64_t)h1 * r[1] + (uint64_t)h2 * r[0] + (uint64_t)h3 * s[3] + (uint64_t)h4 * s[2];
  d3 = (uint64_t)h0 * r[3] + (uint64_t)h1 * r[2] + (uint64_t)h2 * r[1] + (uint64_t)h3 * r[0] + (uint64_t)h4 * s[3];
  h4 = h4 * r[0];

  h0 = (uint32_t)d0;
  h1 = (uint32_t)(d1 += d0 >> 32);
  h2 = (uint32_t)(d2 += d1 >> 32);
  h3 = (uint32_t)(d3 += d2 >> 32);
  h4 += (uint32_t)(d3 >> 32);

  /* the bits from 2^130 up, times 5, back in at the bottom */
  c = (h4 >> 2) + (h4 & ~3UL);
  h4 &= 3;
  d0 = (uint64_t)h0 + c;          ph[0] = (uint32_t)d0;
  d0 = (uint64_t)h1 + (d0 >> 32); ph[1] = (uint32_t)d0;
  d0 = (uint64_t)h2 + (d0 >> 32); ph[2] = (uint32_t)d0;
  d0 = (uint64_t)h3 + (d0 >> 32); ph[3] = (uint32_t)d0;
  ph[4] = h4 + (uint32_t)(d0 >> 32);
}
#endif

void poly1305_update(poly1305_ctx *c, const uint8_t *p, size_t n)
{
  const uint8_t *e;
  size_t i;
  if (c->len) {
    size_t take = 16 - c->len;
    if (take > n) take = n;
    for (i = 0; i < take; i++) c->buf[c->len + i] = p[i];
    c->len = (uint8_t)(c->len + take); p += take; n -= take;
    if (c->len < 16) return;
    load(c); block(c->buf, 1); store(c);
    c->len = 0;
  }
  if (n >= 16) {
    e = p + (n & ~(size_t)15);
    load(c);
    while (p < e) { block(p, 1); p += 16; }       /* a pointer walk, not a count (5.6) */
    store(c);
    n &= 15;
  }
  for (i = 0; i < n; i++) c->buf[i] = p[i];
  c->len = (uint8_t)n;
}

void poly1305_final(poly1305_ctx *c, uint8_t tag[16])
{
  uint8_t g[17], mask;
  unsigned j, u;
  if (c->len) {
    c->buf[c->len] = 1;                           /* the 1 byte the RFC appends, then zeros */
    for (j = c->len + 1; j < 16; j++) c->buf[j] = 0;
    load(c); block(c->buf, 0); store(c);
  }
  /* Fully reduce: h - p is h + 5 - 2^130; take it when that carries
   * into bit 130, without a branch on h. Then tag = (h + s) mod 2^128. */
  u = 5;
  for (j = 0; j < 17; j++) { u += c->h[j]; g[j] = (uint8_t)u; u >>= 8; }
  mask = (uint8_t)(0 - (g[16] >> 2));
  u = 0;
  for (j = 0; j < 16; j++) {
    u += (uint8_t)((c->h[j] & ~mask) | (g[j] & mask));
    u += c->s[j];
    tag[j] = (uint8_t)u; u >>= 8;
  }
}

void poly1305(const uint8_t key[32], const uint8_t *p, size_t n, uint8_t tag[16])
{
  static poly1305_ctx c;
  poly1305_init(&c, key); poly1305_update(&c, p, n); poly1305_final(&c, tag);
}
