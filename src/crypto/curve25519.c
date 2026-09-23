/* X25519 and Ed25519 verification over GF(2^255-19).
 *
 * The algorithms are TweetNaCl's (public domain): the Montgomery ladder,
 * the extended-coordinate group law, the same decompression and scalar
 * reduction. The arithmetic underneath is not: TweetNaCl keeps limbs in
 * int64_t, and on a 6502 every 64-bit operation is emulated inline, which
 * made the first version of this file 15 KB of code and 7 KB of data for
 * a machine with 44 KB (REQUIREMENTS.md 5.2). Here a field element is
 * sixteen unsigned 16-bit limbs, always fully reduced below p; sums and
 * products are accumulated in 32 bits; and the one 16x16 multiply goes
 * through fe_mul16, which the MEGA65 build points at the 45GS02's
 * hardware multiplier and the host build at a plain multiply. Same C on
 * both, and the host suite proves it against the RFC vectors. */
#include <string.h>
#include "crypto.h"

void (*crypto_yield)(void) = 0;

typedef uint16_t fe[16];

static const fe P = { 0xffed, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff,
                      0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0x7fff };
static const fe fe_0 = { 0 };
static const fe fe_1 = { 1 };
static const fe c121665 = { 0xDB41, 1 };
static const fe D = { 0x78a3, 0x1359, 0x4dca, 0x75eb, 0xd8ab, 0x4141, 0x0a4d, 0x0070,
                      0xe898, 0x7779, 0x4079, 0x8cc7, 0xfe73, 0x2b6f, 0x6cee, 0x5203 };
static const fe D2 = { 0xf159, 0x26b2, 0x9b94, 0xebd6, 0xb156, 0x8283, 0x149a, 0x00e0,
                       0xd130, 0xeef3, 0x80f2, 0x198e, 0xfce7, 0x56df, 0xd9dc, 0x2406 };
static const fe BX = { 0xd51a, 0x8f25, 0x2d60, 0xc956, 0xa7b2, 0x9525, 0xc760, 0x692c,
                       0xdc5c, 0xfdd6, 0xe231, 0xc0a4, 0x53fe, 0xcd6e, 0x36d3, 0x2169 };
static const fe BY = { 0x6658, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666,
                       0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666 };
static const fe SQRTM1 = { 0xa0b0, 0x4a0e, 0x1b27, 0xc4ee, 0xe478, 0xad2f, 0x1806, 0x2f43,
                           0xd7a7, 0x3dfb, 0x0099, 0x2b4d, 0xdf0b, 0x4fc1, 0x2480, 0x2b83 };

int crypto_equal(const uint8_t *a, const uint8_t *b, size_t n)
{
  uint8_t d = 0;
  size_t i;
  for (i = 0; i < n; i++) d |= a[i] ^ b[i];
  return d == 0;
}

/* ---- the one multiply ------------------------------------------------ */

#ifndef __mos__
static uint32_t fe_mul16(uint16_t a, uint16_t b) { return (uint32_t)a * b; }
#endif

/* ---- the field ----------------------------------------------------------- */

static void fe_copy(fe o, const fe a) { unsigned i; for (i = 0; i < 16; i++) o[i] = a[i]; }

/* o = o - P if o >= P, else o. */
static void fe_reduce_once(fe o)
{
  static fe t;                            /* static: keeps the bank's zero page free */
  uint32_t b = 0;
  unsigned i;
  for (i = 0; i < 16; i++) {
    b = (uint32_t)o[i] - P[i] - b;
    t[i] = (uint16_t)b;
    b = (b >> 16) & 1;
  }
  if (!b) fe_copy(o, t);                  /* no borrow: o was >= P */
}

#ifdef __mos__
/* On the machine the field add, sub and the tail of a multiply are in
 * mulacc_m65.S on the same fixed buffers as the multiply (5.11). */
void fe_add_m65(void);
void fe_sub_m65(void);
void fe_red_m65(void);
extern uint16_t fe_mul_in_a[16], fe_mul_in_b[16], fe_mul_out[32];
#define FE_IN(a, b) (memcpy(fe_mul_in_a, a, 32), memcpy(fe_mul_in_b, b, 32))
static void fe_add(fe o, const fe a, const fe b) { FE_IN(a, b); fe_add_m65(); memcpy(o, fe_mul_out, 32); }
static void fe_sub(fe o, const fe a, const fe b) { FE_IN(a, b); fe_sub_m65(); memcpy(o, fe_mul_out, 32); }
#else
static void fe_add(fe o, const fe a, const fe b)
{
  uint32_t c = 0;
  unsigned i;
  for (i = 0; i < 16; i++) { c += (uint32_t)a[i] + b[i]; o[i] = (uint16_t)c; c >>= 16; }
  fe_reduce_once(o);                      /* a, b < 2^255, so no carry out of 256 bits */
}

static void fe_sub(fe o, const fe a, const fe b)
{
  uint32_t br = 0, c = 0;
  unsigned i;
  for (i = 0; i < 16; i++) {
    br = (uint32_t)a[i] - b[i] - br;
    o[i] = (uint16_t)br;
    br = (br >> 16) & 1;
  }
  if (br)                                 /* went negative: add P back */
    for (i = 0; i < 16; i++) { c += (uint32_t)o[i] + P[i]; o[i] = (uint16_t)c; c >>= 16; }
}

#endif

#ifdef __mos__
/* The 512-bit product comes from the assembly loop in mulacc_m65.S,
 * through these buffers. */
uint16_t fe_mul_in_a[16], fe_mul_in_b[16], fe_mul_out[32];
void fe_mul_m65(void);
#endif

static void fe_mul(fe o, const fe a, const fe b)
{
  static uint16_t t[32];
  uint32_t c;
  unsigned i;
#ifdef __mos__
  (void)t; (void)c; (void)i;
  FE_IN(a, b);
  fe_mul_m65();
  fe_red_m65();                           /* the fold and the two reductions, in place */
  memcpy(o, fe_mul_out, 32);
  return;
#else
  {
    static uint32_t acc[33];
    uint32_t p;
    unsigned j;
    for (i = 0; i < 33; i++) acc[i] = 0;
    for (i = 0; i < 16; i++) {
      uint16_t ai = a[i];
      if (!ai) continue;
      for (j = 0; j < 16; j++) {
        p = fe_mul16(ai, b[j]);
        acc[i + j] += (uint16_t)p;
        acc[i + j + 1] += p >> 16;
      }
    }
    /* carry into 32 limbs of the 512-bit product */
    c = 0;
    for (i = 0; i < 32; i++) { c += acc[i]; t[i] = (uint16_t)c; c >>= 16; }
  }
#endif
  /* 2^256 = 38 mod p: fold the high half in, twice */
  c = 0;
  for (i = 0; i < 16; i++) { c += (uint32_t)t[i] + 38 * (uint32_t)t[i + 16]; t[i] = (uint16_t)c; c >>= 16; }
  c *= 38;
  for (i = 0; i < 16 && c; i++) { c += t[i]; t[i] = (uint16_t)c; c >>= 16; }
  for (i = 0; i < 16; i++) o[i] = t[i];
  fe_reduce_once(o);
  fe_reduce_once(o);
}

static void fe_sq(fe o, const fe a) { fe_mul(o, a, a); }

static void fe_cswap(fe a, fe b, uint16_t swap)
{
  uint16_t m = (uint16_t)(0 - swap), t;
  unsigned i;
  for (i = 0; i < 16; i++) { t = m & (a[i] ^ b[i]); a[i] ^= t; b[i] ^= t; }
}

static void fe_frombytes(fe o, const uint8_t *n)
{
  unsigned i;
  for (i = 0; i < 16; i++) o[i] = (uint16_t)(n[2 * i] | ((uint16_t)n[2 * i + 1] << 8));
  o[15] &= 0x7fff;
  fe_reduce_once(o);
}

static void fe_tobytes(uint8_t *o, const fe a)
{
  unsigned i;
  for (i = 0; i < 16; i++) { o[2 * i] = (uint8_t)a[i]; o[2 * i + 1] = (uint8_t)(a[i] >> 8); }
}

static int fe_eq(const fe a, const fe b)
{
  uint16_t d = 0;
  unsigned i;
  for (i = 0; i < 16; i++) d |= a[i] ^ b[i];
  return d == 0;
}

static uint8_t fe_parity(const fe a) { return (uint8_t)(a[0] & 1); }

static void fe_inv(fe o, const fe i)
{
  static fe c;
  int a;
  fe_copy(c, i);
  for (a = 253; a >= 0; a--) {
    fe_sq(c, c);
    if (a != 2 && a != 4) fe_mul(c, c, i);
    if (crypto_yield && (a & 15) == 0) crypto_yield();
  }
  fe_copy(o, c);
}

static void fe_pow2523(fe o, const fe i)
{
  static fe c;
  int a;
  fe_copy(c, i);
  for (a = 250; a >= 0; a--) {
    fe_sq(c, c);
    if (a != 1) fe_mul(c, c, i);
    if (crypto_yield && (a & 15) == 0) crypto_yield();
  }
  fe_copy(o, c);
}

/* ---- X25519 ---------------------------------------------------------------- */

void x25519(uint8_t out[32], const uint8_t scalar[32], const uint8_t point[32])
{
  static uint8_t z[32];
  static fe x, a, b, c, d, e, f;
  int i;
  uint16_t r;
  for (i = 0; i < 31; i++) z[i] = scalar[i];
  z[31] = (uint8_t)((scalar[31] & 127) | 64);
  z[0] &= 248;
  fe_frombytes(x, point);
  fe_copy(b, x); fe_copy(a, fe_1); fe_copy(c, fe_0); fe_copy(d, fe_1);
  for (i = 254; i >= 0; i--) {
    r = (uint16_t)((z[i >> 3] >> (i & 7)) & 1);
    fe_cswap(a, b, r); fe_cswap(c, d, r);
    fe_add(e, a, c); fe_sub(a, a, c); fe_add(c, b, d); fe_sub(b, b, d);
    fe_sq(d, e); fe_sq(f, a); fe_mul(a, c, a); fe_mul(c, b, e);
    fe_add(e, a, c); fe_sub(a, a, c); fe_sq(b, a); fe_sub(c, d, f);
    fe_mul(a, c, c121665); fe_add(a, a, d); fe_mul(c, c, a); fe_mul(a, d, f);
    fe_mul(d, b, x); fe_sq(b, e);
    fe_cswap(a, b, r); fe_cswap(c, d, r);
    if (crypto_yield && (i & 7) == 0) crypto_yield();
  }
  fe_inv(c, c);
  fe_mul(a, a, c);
  fe_tobytes(out, a);
}

void x25519_base(uint8_t out[32], const uint8_t scalar[32])
{
  static const uint8_t nine[32] = { 9 };
  x25519(out, scalar, nine);
}

/* ---- Ed25519 verification ------------------------------------------- */

typedef fe ge[4];                      /* extended coordinates X, Y, Z, T */

static void ge_add(ge p, const ge q)
{
  static fe a, b, c, d, t, e, f, g, h;
  fe_sub(a, p[1], p[0]); fe_sub(t, q[1], q[0]); fe_mul(a, a, t);
  fe_add(b, p[0], p[1]); fe_add(t, q[0], q[1]); fe_mul(b, b, t);
  fe_mul(c, p[3], q[3]); fe_mul(c, c, D2);
  fe_mul(d, p[2], q[2]); fe_add(d, d, d);
  fe_sub(e, b, a); fe_sub(f, d, c); fe_add(g, d, c); fe_add(h, b, a);
  fe_mul(p[0], e, f); fe_mul(p[1], h, g); fe_mul(p[2], g, f); fe_mul(p[3], e, h);
}

static void ge_cswap(ge p, ge q, uint16_t b)
{
  unsigned i;
  for (i = 0; i < 4; i++) fe_cswap(p[i], q[i], b);
}

static void __attribute__((noinline)) ge_pack(uint8_t *r, const ge p)
{
  static fe tx, ty, zi;
  fe_inv(zi, p[2]);
  fe_mul(tx, p[0], zi); fe_mul(ty, p[1], zi);
  fe_tobytes(r, ty);
  r[31] ^= (uint8_t)(fe_parity(tx) << 7);
}

static void ge_scalarmult(ge p, ge q, const uint8_t *s)
{
  int i;
  fe_copy(p[0], fe_0); fe_copy(p[1], fe_1); fe_copy(p[2], fe_1); fe_copy(p[3], fe_0);
  for (i = 255; i >= 0; i--) {
    uint16_t b = (uint16_t)((s[i / 8] >> (i & 7)) & 1);
    ge_cswap(p, q, b);
    ge_add(q, p);
    ge_add(p, p);
    ge_cswap(p, q, b);
    if (crypto_yield && (i & 7) == 0) crypto_yield();
  }
}

static void __attribute__((noinline)) ge_scalarbase(ge p, const uint8_t *s)
{
  static ge q;
  fe_copy(q[0], BX); fe_copy(q[1], BY); fe_copy(q[2], fe_1); fe_mul(q[3], BX, BY);
  ge_scalarmult(p, q, s);
}

/* Decompresses p into -A (the negated point), as TweetNaCl's unpackneg. */
static int ge_unpackneg(ge r, const uint8_t p[32])
{
  static fe t, chk, num, den, den2, den4, den6;
  fe_copy(r[2], fe_1);
  fe_frombytes(r[1], p);
  fe_sq(num, r[1]); fe_mul(den, num, D); fe_sub(num, num, r[2]); fe_add(den, r[2], den);
  fe_sq(den2, den); fe_sq(den4, den2); fe_mul(den6, den4, den2);
  fe_mul(t, den6, num); fe_mul(t, t, den);
  fe_pow2523(t, t);
  fe_mul(t, t, num); fe_mul(t, t, den); fe_mul(t, t, den); fe_mul(r[0], t, den);
  fe_sq(chk, r[0]); fe_mul(chk, chk, den);
  if (!fe_eq(chk, num)) fe_mul(r[0], r[0], SQRTM1);
  fe_sq(chk, r[0]); fe_mul(chk, chk, den);
  if (!fe_eq(chk, num)) return -1;
  if (fe_parity(r[0]) == (p[31] >> 7)) fe_sub(r[0], fe_0, r[0]);
  fe_mul(r[3], r[0], r[1]);
  return 0;
}

static const uint8_t L[32] = { 0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2,
                               0xde, 0xf9, 0xde, 0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10 };

/* r = x mod L, x a 64-byte little-endian number; TweetNaCl's modL in
 * 32-bit arithmetic, which every step fits. */
static void __attribute__((noinline)) modL(uint8_t *r, int32_t x[64])
{
  int32_t carry;
  int i, j;
  for (i = 63; i >= 32; i--) {
    carry = 0;
    for (j = i - 32; j < i - 12; j++) {
      x[j] += carry - 16 * x[i] * (int32_t)L[j - (i - 32)];
      carry = (x[j] + 128) >> 8;
      x[j] -= carry << 8;
    }
    x[j] += carry;
    x[i] = 0;
  }
  carry = 0;
  for (j = 0; j < 32; j++) {
    x[j] += carry - (x[31] >> 4) * (int32_t)L[j];
    carry = x[j] >> 8;
    x[j] &= 255;
  }
  for (j = 0; j < 32; j++) x[j] -= carry * (int32_t)L[j];
  for (i = 0; i < 32; i++) {
    x[i + 1] += x[i] >> 8;
    r[i] = (uint8_t)(x[i] & 255);
  }
}

/* Scratch shared by verification and signing, which never nest: the
 * bank has no room for a private set each (5.22). */
static int32_t lx[64];
static uint8_t h64[64], d64[64], r64[64];
static ge gp, gq;
static sha512_ctx shc;

static void __attribute__((noinline)) reduce(uint8_t *r)
{
  unsigned i;
  for (i = 0; i < 64; i++) lx[i] = r[i];
  for (i = 0; i < 64; i++) r[i] = 0;
  modL(r, lx);
}

int ed25519_verify(const uint8_t sig[64], const uint8_t *msg, size_t n, const uint8_t pk[32])
{
  static uint8_t t[32];
  if (ge_unpackneg(gq, pk)) return 0;
  sha512_init(&shc);
  sha512_update(&shc, sig, 32);          /* R */
  sha512_update(&shc, pk, 32);           /* A */
  sha512_update(&shc, msg, n);           /* M */
  sha512_final(&shc, h64);
  reduce(h64);
  ge_scalarmult(gp, gq, h64);            /* h * (-A) */
  ge_scalarbase(gq, sig + 32);           /* S * B */
  ge_add(gp, gq);                        /* S * B - h * A, which must equal R */
  ge_pack(t, gp);
  return crypto_equal(sig, t, 32);
}

/* ---- Ed25519 signing: a key from a seed, and a signature -------------
 * For public-key authentication (REQUIREMENTS.md 5.22): the client's
 * identity is a 32-byte seed; RFC 8032 5.1.5 makes the scalar and the
 * prefix from its SHA-512. */

static void __attribute__((noinline)) expand_seed(const uint8_t seed[32])
{
  sha512_init(&shc); sha512_update(&shc, seed, 32); sha512_final(&shc, d64);
  d64[0] &= 248; d64[31] &= 127; d64[31] |= 64;
}

void ed25519_keypair(uint8_t pk[32], const uint8_t seed[32])
{
  expand_seed(seed);
  ge_scalarbase(gp, d64);
  ge_pack(pk, gp);
  memset(d64, 0, sizeof d64);
}

/* (R, S): R = rB with r = H(prefix, M) mod L; S = r + H(R, A, M) a mod L.
 * The product is carried down to byte limbs before modL, which was
 * written for byte-sized limbs in 32-bit arithmetic (reduce above). */
void ed25519_sign(uint8_t sig[64], const uint8_t *msg, size_t n, const uint8_t seed[32], const uint8_t pk[32])
{
  unsigned i, j;
  int32_t carry;
  expand_seed(seed);
  sha512_init(&shc); sha512_update(&shc, d64 + 32, 32); sha512_update(&shc, msg, n); sha512_final(&shc, r64);
  reduce(r64);
  ge_scalarbase(gp, r64);
  ge_pack(sig, gp);
  sha512_init(&shc); sha512_update(&shc, sig, 32); sha512_update(&shc, pk, 32); sha512_update(&shc, msg, n); sha512_final(&shc, h64);
  reduce(h64);
  for (i = 0; i < 64; i++) lx[i] = i < 32 ? r64[i] : 0;
  for (i = 0; i < 32; i++)
    for (j = 0; j < 32; j++) lx[i + j] += (int32_t)h64[i] * d64[j];     /* at most 32 * 255 * 255 + 255 per limb */
  carry = 0;
  for (i = 0; i < 64; i++) { lx[i] += carry; carry = lx[i] >> 8; lx[i] &= 255; }
  modL(sig + 32, lx);
  memset(d64, 0, sizeof d64); memset(r64, 0, sizeof r64); memset(lx, 0, sizeof lx);
}

/* Identities in the field, for finding where a port went wrong: each
 * bit of the result is one failing check. Host and machine both run it. */
unsigned crypto_fe_selftest(void)
{
  static const uint8_t one[32] = { 1 };
  static uint8_t pm1[32], b[32], w[32];
  static fe x, y, z;
  unsigned bad = 0, i;
  /* p - 1 */
  for (i = 0; i < 32; i++) pm1[i] = 0xff;
  pm1[0] = 0xec; pm1[31] = 0x7f;
  fe_frombytes(x, pm1); fe_tobytes(b, x);
  if (!crypto_equal(b, pm1, 32)) bad |= 1;            /* frombytes/tobytes round trip */
  fe_mul(y, x, x); fe_tobytes(b, y);
  if (!crypto_equal(b, one, 32)) bad |= 2;            /* (p-1)^2 = 1 */
  fe_frombytes(z, one);
  fe_add(y, x, z); fe_tobytes(b, y);
  for (i = 0; i < 32; i++) w[i] = 0;
  if (!crypto_equal(b, w, 32)) bad |= 4;              /* (p-1) + 1 = 0 */
  fe_sub(y, z, x); fe_tobytes(b, y);
  w[0] = 2;
  if (!crypto_equal(b, w, 32)) bad |= 8;              /* 1 - (p-1) = 2 */
  fe_sub(y, y, x); fe_tobytes(b, y);                  /* 2 - (p-1) = 3 */
  w[0] = 3;
  if (!crypto_equal(b, w, 32)) bad |= 16;
  /* 2^200 * 2^100 = 2^300 = 19 * 2^45 mod p */
  for (i = 0; i < 32; i++) w[i] = 0;
  w[25] = 1; fe_frombytes(x, w);
  for (i = 0; i < 32; i++) w[i] = 0;
  w[12] = 0x10; fe_frombytes(y, w);
  fe_mul(z, x, y); fe_tobytes(b, z);
  for (i = 0; i < 32; i++) w[i] = 0;
  w[5] = 0x60; w[6] = 0x02;                           /* 19 << 45: 2^255 = 19 mod p, so 2^300 = 19 * 2^45 */
  if (!crypto_equal(b, w, 32)) bad |= 32;
  /* inverse of 2 is (p+1)/2 */
  for (i = 0; i < 32; i++) w[i] = 0;
  w[0] = 2; fe_frombytes(x, w);
  fe_inv(y, x); fe_tobytes(b, y);
  for (i = 0; i < 32; i++) w[i] = 0xff;
  w[0] = 0xf7; w[31] = 0x3f;
  if (!crypto_equal(b, w, 32)) bad |= 64;
  /* cswap */
  fe_frombytes(x, one); fe_frombytes(y, pm1);
  fe_cswap(x, y, 1); fe_tobytes(b, x);
  if (!crypto_equal(b, pm1, 32)) bad |= 128;
  return bad;
}

/* Benchmark hooks for the spike (5.11): n of each operation on fixed
 * operands, so the machine can say where a multiply's time goes. */
void crypto_fe_bench(unsigned char which, unsigned n)
{
  static fe a, b, o;
  unsigned i;
  for (i = 0; i < 16; i++) { a[i] = (uint16_t)(0x1234 + i); b[i] = (uint16_t)(0x7654 - i); }
  switch (which) {
  case 0: for (i = 0; i < n; i++) fe_mul(o, a, b); break;
  case 1: for (i = 0; i < n; i++) fe_add(o, a, b); break;
  case 2: for (i = 0; i < n; i++) fe_sub(o, a, b); break;
  case 3: for (i = 0; i < n; i++) fe_cswap(a, b, (uint16_t)(i & 1)); break;
  case 4: for (i = 0; i < n; i++) memcpy(o, a, 32); break;
#ifdef __mos__
  case 5: for (i = 0; i < n; i++) fe_mul_m65(); break;
  case 6: for (i = 0; i < n; i++) fe_red_m65(); break;
#endif
  default: break;
  }
}
