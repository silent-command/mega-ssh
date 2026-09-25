/* The client's side of the crypto bank: the same operations as crypto.h,
 * marshalled through the trampoline at $1700 with parameter blocks the
 * bank reads by DMA. Hash and Poly1305 contexts and cipher keys live in
 * the bank, named by slot. */
#ifndef CKIT_H
#define CKIT_H

#include <stdint.h>

#define CK_TR 0x1700
#define CK_BASE 0x12000UL             /* where the image is loaded */
#define CK_TERM_BASE 0x1E000UL        /* the terminal, the top of the same bank */

/* Loads SSHCRYPTO and TERM from the boot disk into bank 1, puts the
 * trampoline at $1700 and runs INIT. 0 with a message on failure. */
unsigned char ck_boot(const char **err);
extern unsigned char ck_boot_tries;    /* loads attempted: 2 when both files came first time */

/* sha256 slots: 0 the exchange hash, 1 derivation, 2 general, 3 random */
void ck_sha256_init(uint8_t slot);
void ck_sha256_update(uint8_t slot, const void *p, uint16_t n);
void ck_sha256_final(uint8_t slot, uint8_t out[32]);
void ck_sha512_init(void);
void ck_sha512_update(const void *p, uint16_t n);
void ck_sha512_final(uint8_t out[64]);
/* key slots: 0 c2s payload, 1 c2s length, 2 s2c payload, 3 s2c length */
void ck_key_set(uint8_t slot, const uint8_t key[32]);
void ck_chacha_block(uint8_t keyslot, const uint8_t nonce[8], uint32_t counter, uint8_t out[64]);
void ck_chacha_xor(uint8_t keyslot, const uint8_t nonce[8], uint32_t counter, uint8_t *p, uint16_t n);
void ck_poly_init(uint8_t slot, const uint8_t key[32]);
void ck_poly_update(uint8_t slot, const void *p, uint16_t n);
void ck_poly_final(uint8_t slot, uint8_t out[16]);
void ck_x25519(uint8_t out[32], const uint8_t scalar[32], const uint8_t point[32]);
void ck_x25519_base(uint8_t out[32], const uint8_t scalar[32]);
uint8_t ck_ed25519_verify(const uint8_t sig[64], const uint8_t *msg, uint16_t n, const uint8_t pk[32]);
/* The identity's public key from its seed, and a signature; the message must fit the stage (256 bytes). */
uint8_t ck_ed25519_keypair(uint8_t pk[32], const uint8_t seed[32]);
uint8_t ck_ed25519_sign(uint8_t sig[64], const uint8_t *msg, uint16_t n, const uint8_t seed[32], const uint8_t pk[32]);
unsigned ck_selftest(void);
uint8_t ck_equal(const uint8_t *a, const uint8_t *b, uint16_t n);

/* The terminal, which lives in the bank too (src/bank/term.c): the
 * whole screen, in the given text colour; bytes from the host; the
 * cursor. ck_term_write reports whether the host asked for application
 * cursor keys. */
void ck_term_init(uint8_t colour, uint8_t bg, uint8_t rows);
void ck_term_write(const uint8_t *p, uint16_t n, uint8_t *app_cursor);
void ck_term_cursor(uint8_t on);
void ck_term_end(void);   /* restore $D021 and the extended attributes at session end */
void ck_term_recolour(uint8_t colour, uint8_t bg);   /* live local colours */

#endif
