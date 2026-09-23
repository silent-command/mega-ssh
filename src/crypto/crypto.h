/* The primitives an SSH 2 client needs for one algorithm of each kind:
 * curve25519-sha256, ssh-ed25519, chacha20-poly1305@openssh.com.
 *
 * Written from the RFCs (6234, 8439, 7748, 8032) in C99 with stdint.h
 * and nothing else, so the same code runs on the host, where the test
 * suite proves it against the published vectors, and on the MEGA65,
 * where the frame counter times it. Constant time is not a goal. */
#ifndef CRYPTO_H
#define CRYPTO_H

#include <stdint.h>
#include <stddef.h>

/* ---- SHA-256 (RFC 6234) ---------------------------------------------- */
typedef struct {
  uint32_t h[8];
  uint8_t buf[64];
  uint8_t len;               /* bytes in buf */
  uint32_t total_lo, total_hi;   /* bytes hashed so far */
} sha256_ctx;

void sha256_init(sha256_ctx *c);
void sha256_update(sha256_ctx *c, const uint8_t *p, size_t n);
void sha256_final(sha256_ctx *c, uint8_t out[32]);
void sha256(const uint8_t *p, size_t n, uint8_t out[32]);

/* ---- SHA-512 (RFC 6234); Ed25519 needs it ---------------------------- */
typedef struct {
  uint64_t h[8];
  uint8_t buf[128];
  uint8_t len;
  uint64_t total;
} sha512_ctx;

void sha512_init(sha512_ctx *c);
void sha512_update(sha512_ctx *c, const uint8_t *p, size_t n);
void sha512_final(sha512_ctx *c, uint8_t out[64]);

/* ---- ChaCha20 (RFC 8439) --------------------------------------------- */
/* One 64-byte keystream block for key, 96-bit nonce and 32-bit counter
 * (the RFC form), and the OpenSSH form with a 64-bit nonce and 64-bit
 * counter, which is what chacha20-poly1305@openssh.com uses (nonce = the
 * packet sequence number). */
void chacha20_block(const uint8_t key[32], const uint8_t nonce[12], uint32_t counter, uint8_t out[64]);
void chacha20_block64(const uint8_t key[32], const uint8_t nonce[8], uint64_t counter, uint8_t out[64]);
/* XOR n bytes in place with the keystream from `counter` on (RFC form). */
void chacha20_xor(const uint8_t key[32], const uint8_t nonce[12], uint32_t counter, uint8_t *p, size_t n);
/* The same for the OpenSSH form. */
void chacha20_xor64(const uint8_t key[32], const uint8_t nonce[8], uint64_t counter, uint8_t *p, size_t n);

/* ---- Poly1305 (RFC 8439) --------------------------------------------- */
typedef struct {
  uint32_t r[17], h[17];      /* 8-bit limbs in 32-bit words, TweetNaCl's arrangement */
  uint8_t s[16];
  uint8_t buf[16];
  uint8_t len;
  uint8_t rr_ready;           /* the multiplier table for this r is built (target) */
} poly1305_ctx;

void poly1305_init(poly1305_ctx *c, const uint8_t key[32]);
void poly1305_update(poly1305_ctx *c, const uint8_t *p, size_t n);
void poly1305_final(poly1305_ctx *c, uint8_t tag[16]);
void poly1305(const uint8_t key[32], const uint8_t *p, size_t n, uint8_t tag[16]);

/* ---- X25519 (RFC 7748) and Ed25519 verification (RFC 8032) ---------- */
/* out = scalar * point; scalar clamped as the RFC says. */
void x25519(uint8_t out[32], const uint8_t scalar[32], const uint8_t point[32]);
/* The base point, 9. */
void x25519_base(uint8_t out[32], const uint8_t scalar[32]);
/* 1 when sig is a valid signature of msg under pk. */
int ed25519_verify(const uint8_t sig[64], const uint8_t *msg, size_t n, const uint8_t pk[32]);
/* The public key from a 32-byte seed, and a signature with the pair (RFC 8032 5.1.5, 5.1.6). */
void ed25519_keypair(uint8_t pk[32], const uint8_t seed[32]);
void ed25519_sign(uint8_t sig[64], const uint8_t *msg, size_t n, const uint8_t seed[32], const uint8_t pk[32]);

/* A yield the long computations call between rounds, so a client can
 * poll the network stack while a scalar multiplication runs. Null by
 * default. */
extern void (*crypto_yield)(void);

/* Field identities; 0 when all hold, else a bit per failing check. */
unsigned crypto_fe_selftest(void);

/* Compares n bytes; 1 if equal. */
int crypto_equal(const uint8_t *a, const uint8_t *b, size_t n);


/* n field operations for timing: 0 mul, 1 add, 2 sub, 3 cswap, 4 a 32-byte copy, 5 the bare multiply loop, 6 the bare reduce */
void crypto_fe_bench(unsigned char which, unsigned n);

#endif
