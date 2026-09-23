#include <string.h>
#include "mega65/memory.h"
#include "m65_cbmdos.h"
#include "m65_boot.h"
#include "ck_payload.h"                  /* generated: the trampoline bytes and the image size */
#include "ckit.h"

#define TR(o) (*(volatile uint8_t *)(CK_TR + (o)))
enum { E_INIT = 0x2000, E_VERSION = 0x2003, E_S256_INIT = 0x2006, E_S256_UPDATE = 0x2009, E_S256_FINAL = 0x200C,
       E_S512_INIT = 0x200F, E_S512_UPDATE = 0x2012, E_S512_FINAL = 0x2015, E_KEY_SET = 0x2018,
       E_CHACHA_BLOCK = 0x201B, E_CHACHA_XOR = 0x201E, E_POLY_INIT = 0x2021, E_POLY_UPDATE = 0x2024,
       E_POLY_FINAL = 0x2027, E_X25519 = 0x202A, E_X25519_BASE = 0x202D, E_ED_VERIFY = 0x2030, E_SELFTEST = 0x2033,
       E_TERM_INIT = 0x2036, E_TERM_WRITE = 0x2039, E_TERM_CURSOR = 0x203C, E_TERM_END = 0x203F, E_TERM_RECOLOUR = 0x2042,
       E_ED_KEYPAIR = 0x2045, E_ED_SIGN = 0x2048 };

static uint8_t blk[40];

static uint8_t call(uint16_t entry, uint8_t a, uint8_t x, uint8_t y)
{
  TR(0) = (uint8_t)entry; TR(1) = (uint8_t)(entry >> 8);
  TR(2) = a; TR(3) = x; TR(4) = y; TR(5) = 0;
  ((void (*)(void))(CK_TR + 0x0E))();
  return TR(6);
}

static uint8_t call_blk(uint16_t entry)
{
  uint16_t p = (uint16_t)(uintptr_t)blk;
  return call(entry, (uint8_t)p, (uint8_t)(p >> 8), 0);
}

static void put28(uint8_t *at, const void *p)
{
  uint16_t v = (uint16_t)(uintptr_t)p;               /* bank 0: physical is the CPU address */
  at[0] = (uint8_t)v; at[1] = (uint8_t)(v >> 8); at[2] = 0; at[3] = 0;
}

static void put16(uint8_t *at, uint16_t v) { at[0] = (uint8_t)v; at[1] = (uint8_t)(v >> 8); }

unsigned char ck_boot_tries;

static unsigned char load_retry(const char *name, unsigned long dest, unsigned long size)
{
  unsigned char try;
  for (try = 0; try < 3; try++) {
    ck_boot_tries++;
    if (cbmdos_load(name, boot_drive, dest, size) == size) return 1;
    /* the third file loaded in a row failed one boot in two (5.8): let the drive settle */
    { unsigned char last = PEEK(0xd7fa), n = 0; while (n < 20) { if (PEEK(0xd7fa) != last) { last = PEEK(0xd7fa); n++; } } }
  }
  return 0;
}

unsigned char ck_boot(const char **err)
{
  lcopy((long)ck_tramp_bin, (long)CK_TR, CK_TRAMP_SIZE);
  TR(0x0D) = 0x00;                                /* the caller's MAPHI Z: no KERNAL, m65_own_vectors() */
  ck_boot_tries = 0;
  if (!load_retry("CRYPTO", CK_BASE, CK_BIN_SIZE)) { *err = "CRYPTO not found on the boot disk (or wrong size)"; return 0; }
  if (lpeek(CK_BASE) != 0x4c) { *err = "the crypto image did not land"; return 0; }
  if (!load_retry("TERM", CK_TERM_BASE, CK_TERM_SIZE)) { *err = "TERM not found on the boot disk (or wrong size)"; return 0; }
  call(E_INIT, 0, 0, 0);
  *err = 0;
  return 1;
}

void ck_sha256_init(uint8_t slot) { call(E_S256_INIT, slot, 0, 0); }
void ck_sha256_update(uint8_t slot, const void *p, uint16_t n)
{ blk[0] = slot; put28(blk + 1, p); put16(blk + 5, n); call_blk(E_S256_UPDATE); }
void ck_sha256_final(uint8_t slot, uint8_t out[32]) { blk[0] = slot; put28(blk + 1, out); call_blk(E_S256_FINAL); }
void ck_sha512_init(void) { call(E_S512_INIT, 0, 0, 0); }
void ck_sha512_update(const void *p, uint16_t n) { blk[0] = 0; put28(blk + 1, p); put16(blk + 5, n); call_blk(E_S512_UPDATE); }
void ck_sha512_final(uint8_t out[64]) { blk[0] = 0; put28(blk + 1, out); call_blk(E_S512_FINAL); }
void ck_key_set(uint8_t slot, const uint8_t key[32]) { blk[0] = slot; put28(blk + 1, key); call_blk(E_KEY_SET); }

void ck_chacha_block(uint8_t keyslot, const uint8_t nonce[8], uint32_t counter, uint8_t out[64])
{
  blk[0] = keyslot; memcpy(blk + 1, nonce, 8);
  blk[9] = (uint8_t)counter; blk[10] = (uint8_t)(counter >> 8); blk[11] = (uint8_t)(counter >> 16); blk[12] = (uint8_t)(counter >> 24);
  put28(blk + 13, out);
  call_blk(E_CHACHA_BLOCK);
}

void ck_chacha_xor(uint8_t keyslot, const uint8_t nonce[8], uint32_t counter, uint8_t *p, uint16_t n)
{
  blk[0] = keyslot; memcpy(blk + 1, nonce, 8);
  blk[9] = (uint8_t)counter; blk[10] = (uint8_t)(counter >> 8); blk[11] = (uint8_t)(counter >> 16); blk[12] = (uint8_t)(counter >> 24);
  put28(blk + 13, p); put16(blk + 17, n);
  call_blk(E_CHACHA_XOR);
}

void ck_poly_init(uint8_t slot, const uint8_t key[32]) { blk[0] = slot; put28(blk + 1, key); call_blk(E_POLY_INIT); }
void ck_poly_update(uint8_t slot, const void *p, uint16_t n) { blk[0] = slot; put28(blk + 1, p); put16(blk + 5, n); call_blk(E_POLY_UPDATE); }
void ck_poly_final(uint8_t slot, uint8_t out[16]) { blk[0] = slot; put28(blk + 1, out); call_blk(E_POLY_FINAL); }

void ck_x25519(uint8_t out[32], const uint8_t scalar[32], const uint8_t point[32])
{ put28(blk, out); put28(blk + 4, scalar); put28(blk + 8, point); call_blk(E_X25519); }
void ck_x25519_base(uint8_t out[32], const uint8_t scalar[32]) { put28(blk, out); put28(blk + 4, scalar); call_blk(E_X25519_BASE); }
uint8_t ck_ed25519_verify(const uint8_t sig[64], const uint8_t *msg, uint16_t n, const uint8_t pk[32])
{ put28(blk, sig); put28(blk + 4, msg); put16(blk + 8, n); put28(blk + 10, pk); return call_blk(E_ED_VERIFY); }
uint8_t ck_ed25519_keypair(uint8_t pk[32], const uint8_t seed[32]) { put28(blk, pk); put28(blk + 4, seed); return call_blk(E_ED_KEYPAIR); }
uint8_t ck_ed25519_sign(uint8_t sig[64], const uint8_t *msg, uint16_t n, const uint8_t seed[32], const uint8_t pk[32])
{ put28(blk, sig); put28(blk + 4, msg); put16(blk + 8, n); put28(blk + 10, seed); put28(blk + 14, pk); return call_blk(E_ED_SIGN); }
unsigned ck_selftest(void) { return call(E_SELFTEST, 0, 0, 0); }

uint8_t ck_equal(const uint8_t *a, const uint8_t *b, uint16_t n)
{
  uint8_t d = 0;
  uint16_t i;
  for (i = 0; i < n; i++) d |= a[i] ^ b[i];      /* not while (n--): 5.6 */
  return d == 0;
}

void ck_term_init(uint8_t colour, uint8_t bg, uint8_t rows) { call(E_TERM_INIT, colour, bg, rows); }
void ck_term_write(const uint8_t *p, uint16_t n, uint8_t *app_cursor)
{
  put28(blk, p); put16(blk + 4, n);
  call_blk(E_TERM_WRITE);
  *app_cursor = TR(7);
}
void ck_term_cursor(uint8_t on) { call(E_TERM_CURSOR, on, 0, 0); }
void ck_term_end(void) { call(E_TERM_END, 0, 0, 0); }
void ck_term_recolour(uint8_t colour, uint8_t bg) { call(E_TERM_RECOLOUR, colour, bg, 0); }
