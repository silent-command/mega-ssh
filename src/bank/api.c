/* The crypto bank's entries: the C behind each jump in jumptable.S.
 *
 * Every entry reads a parameter block from the caller's memory by DMA
 * (A/X/Y hold its 28-bit address), moves data in and out through a
 * staging buffer here, and never touches the caller's memory with the
 * CPU, which is hidden while the bank is mapped. INIT is this image's
 * crt0: no runtime ran, so .bss, .zp.bss and .zp.data are ours to set
 * up, and the interrupt vectors in force during a call are written to
 * the top of the bank (mega-net REQUIREMENTS.md 5.7, 5.11). The long
 * operations yield to mega-net's poll between rounds, with the
 * network trampoline told to restore this bank's map, not the client's. */
#include <stdint.h>
#include "crypto.h"
#include "dma.h"
#include "term.h"

#define IN_BSS(n) __attribute__((section(".bss." n)))
#define POKE(a, v) (*(volatile uint8_t *)(a) = (uint8_t)(v))
#define PEEK(a) (*(volatile uint8_t *)(a))
#define PHYS(p) ((uint32_t)(uintptr_t)(p) + CK_PHYS_BASE)

extern volatile uint8_t ck_api_a, ck_api_x, ck_api_y, ck_api_z;
extern volatile uint8_t ck_api_ra, ck_api_rx, ck_api_ry, ck_api_rz;
extern char __bss_start[], __bss_size[];
extern char __zp_bss_start[], __zp_bss_size[];
extern char __zp_data_start[], __zp_data_load_start[], __zp_data_size[];

#define SLOTS256 4
#define KEYS 4
static sha256_ctx c256[SLOTS256] IN_BSS("c256");
static sha512_ctx c512 IN_BSS("c512");
static poly1305_ctx cpoly[2] IN_BSS("cpoly");
static uint8_t keys[KEYS][32] IN_BSS("keys");
static uint8_t stage[256] IN_BSS("stage");     /* 256, not 512: the terminal needed the room (5.7) */
static uint8_t blk[40] IN_BSS("blk");
static uint8_t small[64] IN_BSS("small");
static uint8_t sig[64] IN_BSS("sig");
static uint8_t pk[32] IN_BSS("pk");
static uint8_t out32[32] IN_BSS("out32");

static uint32_t arg_ptr(void)
{
  return (uint32_t)ck_api_a | ((uint32_t)ck_api_x << 8) | ((uint32_t)ck_api_y << 16);
}

static uint32_t p28(const uint8_t *b)
{
  return (uint32_t)b[0] | ((uint32_t)b[1] << 8) | ((uint32_t)b[2] << 16) | ((uint32_t)b[3] << 24);
}

static uint16_t u16(const uint8_t *b) { return (uint16_t)(b[0] | ((uint16_t)b[1] << 8)); }

static void get_block(void) { ck_dma_copy(arg_ptr(), PHYS(blk), sizeof blk); }

/* ---- the yield: mega-net's poll, with the map put back to ours ------ */

#define NET_TR 0x1600
#define NET_ENTRY_POLL 0x200F

static void net_poll(void)
{
  uint8_t sa, sx, sy, sz;
  sa = PEEK(NET_TR + 0x0A); sx = PEEK(NET_TR + 0x0B); sy = PEEK(NET_TR + 0x0C); sz = PEEK(NET_TR + 0x0D);
  POKE(NET_TR + 0x0A, 0x00); POKE(NET_TR + 0x0B, 0xE1);       /* our map, as the crypto trampoline sets it */
  POKE(NET_TR + 0x0C, 0x00); POKE(NET_TR + 0x0D, 0xB1);
  POKE(NET_TR + 0x00, NET_ENTRY_POLL & 0xff); POKE(NET_TR + 0x01, NET_ENTRY_POLL >> 8);
  POKE(NET_TR + 0x02, 0); POKE(NET_TR + 0x03, 0); POKE(NET_TR + 0x04, 0); POKE(NET_TR + 0x05, 0);
  ((void (*)(void))(NET_TR + 0x0E))();
  POKE(NET_TR + 0x0A, sa); POKE(NET_TR + 0x0B, sx); POKE(NET_TR + 0x0C, sy); POKE(NET_TR + 0x0D, sz);
}

/* ---- entries ---------------------------------------------------------- */

void ck_api_init(void)
{
  uint16_t n = (uint16_t)(uintptr_t)__bss_size, i;
  for (i = 0; i < n; i++) __bss_start[i] = 0;
  n = (uint16_t)(uintptr_t)__zp_bss_size;
  for (i = 0; i < n; i++) __zp_bss_start[i] = 0;
  n = (uint16_t)(uintptr_t)__zp_data_size;
  for (i = 0; i < n; i++) __zp_data_start[i] = __zp_data_load_start[i];
  /* the vectors in force while the bank is mapped: an RTI at $FFF0 */
  POKE(0xFFF0, 0x40);
  POKE(0xFFFA, 0xF0); POKE(0xFFFB, 0xFF);
  POKE(0xFFFC, 0xF0); POKE(0xFFFD, 0xFF);
  POKE(0xFFFE, 0xF0); POKE(0xFFFF, 0xFF);
  crypto_yield = net_poll;
  ck_api_ra = 0;
}

void ck_api_version(void) { ck_api_ra = 0; ck_api_rx = 1; }

/* {slot} */
void ck_api_sha256_init(void)
{
  uint8_t s = ck_api_a & (SLOTS256 - 1);
  sha256_init(&c256[s]);
}

/* {slot u8, ptr28, len u16}: data in chunks through the stage */
static void update_from(uint8_t kind)
{
  uint8_t s;
  uint32_t src;
  uint16_t left, take;
  get_block();
  s = blk[0]; src = p28(blk + 1); left = u16(blk + 5);
  while (left) {
    take = left < sizeof stage ? left : sizeof stage;
    ck_dma_copy(src, PHYS(stage), take);
    if (kind == 0) sha256_update(&c256[s & (SLOTS256 - 1)], stage, take);
    else if (kind == 1) sha512_update(&c512, stage, take);
    else poly1305_update(&cpoly[s & 1], stage, take);
    src += take; left = (uint16_t)(left - take);
  }
}

void ck_api_sha256_update(void) { update_from(0); }

/* {slot u8, out28} */
void ck_api_sha256_final(void)
{
  get_block();
  sha256_final(&c256[blk[0] & (SLOTS256 - 1)], out32);
  ck_dma_copy(PHYS(out32), p28(blk + 1), 32);
}

void ck_api_sha512_init(void) { sha512_init(&c512); }
void ck_api_sha512_update(void) { update_from(1); }
void ck_api_sha512_final(void)
{
  get_block();
  sha512_final(&c512, small);
  ck_dma_copy(PHYS(small), p28(blk + 1), 64);
}

/* {slot u8, key28} */
void ck_api_key_set(void)
{
  get_block();
  ck_dma_copy(p28(blk + 1), PHYS(keys[blk[0] & (KEYS - 1)]), 32);
}

/* {keyslot u8, nonce[8], counter u32, out28} */
void ck_api_chacha_block(void)
{
  uint32_t ctr;
  get_block();
  ctr = p28(blk + 9);
  chacha20_block64(keys[blk[0] & (KEYS - 1)], blk + 1, ctr, small);
  ck_dma_copy(PHYS(small), p28(blk + 13), 64);
}

/* {keyslot u8, nonce[8], counter u32, ptr28, len u16}: in place, in
 * chunks the size of the stage, so the counter advances by a stage's
 * worth of 64-byte blocks per chunk (a hard-coded eight here, from the
 * 512-byte stage, made the tail of every long packet garbage when the
 * stage shrank to 256: 5.7) */
void ck_api_chacha_xor(void)
{
  uint32_t ctr, src;
  uint16_t left, take;
  uint8_t k;
  get_block();
  k = blk[0] & (KEYS - 1); ctr = p28(blk + 9); src = p28(blk + 13); left = u16(blk + 17);
  while (left) {
    take = left < sizeof stage ? left : sizeof stage;
    ck_dma_copy(src, PHYS(stage), take);
    chacha20_xor64(keys[k], blk + 1, ctr, stage, take);
    ck_dma_copy(PHYS(stage), src, take);
    src += take; left = (uint16_t)(left - take); ctr += sizeof stage / 64;
  }
}

/* {slot u8, key28} */
void ck_api_poly_init(void)
{
  get_block();
  ck_dma_copy(p28(blk + 1), PHYS(small), 32);
  poly1305_init(&cpoly[blk[0] & 1], small);
}

void ck_api_poly_update(void) { update_from(2); }

/* {slot u8, out28} */
void ck_api_poly_final(void)
{
  get_block();
  poly1305_final(&cpoly[blk[0] & 1], small);
  ck_dma_copy(PHYS(small), p28(blk + 1), 16);
}

/* {out28, scalar28, point28} */
void ck_api_x25519(void)
{
  get_block();
  ck_dma_copy(p28(blk + 4), PHYS(pk), 32);            /* the scalar */
  ck_dma_copy(p28(blk + 8), PHYS(out32), 32);         /* the point */
  x25519(small, pk, out32);
  ck_dma_copy(PHYS(small), p28(blk), 32);
  ck_api_ra = 1;
}

/* {out28, scalar28} */
void ck_api_x25519_base(void)
{
  get_block();
  ck_dma_copy(p28(blk + 4), PHYS(pk), 32);
  x25519_base(small, pk);
  ck_dma_copy(PHYS(small), p28(blk), 32);
  ck_api_ra = 1;
}

/* {sig28, msg28, msglen u16, pk28}; the message must fit the stage */
void ck_api_ed25519_verify(void)
{
  uint16_t n;
  get_block();
  n = u16(blk + 8);
  if (n > sizeof stage) { ck_api_ra = 0; return; }
  ck_dma_copy(p28(blk), PHYS(sig), 64);
  ck_dma_copy(p28(blk + 4), PHYS(stage), n);
  ck_dma_copy(p28(blk + 10), PHYS(pk), 32);
  ck_api_ra = (uint8_t)ed25519_verify(sig, stage, n, pk);
}

/* {pk28, seed28}: the identity's public key from its seed (5.22) */
void ck_api_ed25519_keypair(void)
{
  uint8_t i;
  get_block();
  ck_dma_copy(p28(blk + 4), PHYS(small), 32);         /* the seed */
  ed25519_keypair(pk, small);
  ck_dma_copy(PHYS(pk), p28(blk), 32);
  for (i = 0; i < 32; i++) small[i] = 0;
  ck_api_ra = 1;
}

/* {sig28, msg28, msglen16, seed28, pk28}; the message must fit the stage */
void ck_api_ed25519_sign(void)
{
  uint16_t n;
  get_block();
  n = u16(blk + 8);
  if (n > sizeof stage) { ck_api_ra = 0; return; }
  ck_dma_copy(p28(blk + 4), PHYS(stage), n);
  ck_dma_copy(p28(blk + 10), PHYS(small), 32);        /* the seed */
  ck_dma_copy(p28(blk + 14), PHYS(pk), 32);
  ed25519_sign(sig, stage, n, small, pk);
  ck_dma_copy(PHYS(sig), p28(blk), 64);
  for (n = 0; n < 32; n++) small[n] = 0;
  ck_api_ra = 1;
}

/* The field self-test left the bank when signing needed its 1.2 KB (5.22);
 * the host suite proves the same identities. The entry answers 0. */
void ck_api_selftest(void) { ck_api_ra = 0; }

/* ---- the terminal ------------------------------------------------------ */

/* A = the text colour, X = the background, Y = the rows (25 or 50) */
void ck_api_term_init(void) { term_init(ck_api_a, ck_api_x, ck_api_y); }

/* {src28, len16}: the bytes in chunks through the stage; X says whether
 * the host wants application cursor keys */
void ck_api_term_write(void)
{
  uint32_t src;
  uint16_t left, take;
  get_block();
  src = p28(blk); left = u16(blk + 4);
  while (left) {
    take = left < sizeof stage ? left : sizeof stage;
    ck_dma_copy(src, PHYS(stage), take);
    term_write(stage, take);
    src += take; left = (uint16_t)(left - take);
  }
  ck_api_ra = 0;
  ck_api_rx = term_app_cursor;
}

/* A = on */
void ck_api_term_cursor(void) { term_cursor(ck_api_a); }

void ck_api_term_end(void) { term_end(); }

/* A = text colour, X = background */
void ck_api_term_recolour(void) { term_recolour(ck_api_a, ck_api_x); }
