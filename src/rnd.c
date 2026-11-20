/* Copyright 2026 Justin Cameron
 * SPDX-License-Identifier: Apache-2.0 */
/* Random bytes for the key exchange's private scalar, the KEXINIT cookie
 * and packet padding.
 *
 * The seed is timing jitter: over about a second, the raster position
 * and a CIA timer are sampled at every change of the frame counter,
 * along with the ethernet controller's frame counters if the stack is
 * up, and the machine's random register and thermal noise bit (hwrng
 * below), and all of it is hashed. Keystrokes and network replies add
 * more through rnd_stir. Output is SHA-256 of the seed and a counter.
 * This is a hobbyist's source, not a certified one; REQUIREMENTS.md
 * says so. */
#include "mega65/memory.h"
#include "ckit.h"
#include "rnd.h"

static uint8_t seed[32];          /* the pool is sha256 slot 3 in the bank */
static uint32_t counter;
static uint8_t stir_byte;

/* The MEGA65's own random-number generator (the MEGA65 book, K-17:
 * $D7EF HWRNGRAND, a read starts the next; $D7FE bit 7 HWRNGNOTRDY) and
 * the FPGA's thermal noise bit ($D6DE bit 0, mega65-libc's random.c).
 * Both go into the pool beside the timing, never instead of it: the wait
 * is bounded, so a core without them costs a few cycles and adds
 * nothing, and neither has been measured on this machine. */
static uint8_t hwrng(void)
{
  uint8_t i;
  for (i = 0; i < 32; i++)
    if (!(PEEK(0xd7fe) & 0x80)) break;
  return PEEK(0xd7ef);
}

static void sample(void)
{
  uint8_t s[8];
  s[0] = PEEK(0xd012); s[1] = PEEK(0xd7fa); s[2] = PEEK(0xdc04); s[3] = PEEK(0xdc05);
  s[4] = PEEK(0xd6e1); s[5] = stir_byte++; s[6] = hwrng(); s[7] = PEEK(0xd6de);
  ck_sha256_update(3, s, 8);
}

void rnd_init(void)
{
  unsigned n;
  uint8_t last = PEEK(0xd7fa);
  ck_sha256_init(3);
  for (n = 0; n < 60; ) {                          /* sixty frames, about 1.2 s */
    if (PEEK(0xd7fa) != last) { last = PEEK(0xd7fa); n++; sample(); }
    sample();
  }
  ck_sha256_final(3, seed);
  ck_sha256_init(3);
  ck_sha256_update(3, seed, 32);
  counter = 0;
}

void rnd_stir(uint8_t v)
{
  uint8_t s[3];
  s[0] = v; s[1] = PEEK(0xd012); s[2] = PEEK(0xd7fa);
  ck_sha256_update(3, s, 3);
}

void rnd_fill(uint8_t *out, unsigned n)
{
  static uint8_t block[32] __attribute__((section(".bss.rnd_block")));
  uint8_t cb[4];
  unsigned i, take;
  /* fold whatever has been stirred into the seed */
  ck_sha256_final(3, seed);
  ck_sha256_init(3);
  ck_sha256_update(3, seed, 32);
  while (n) {
    counter++;
    cb[0] = (uint8_t)counter; cb[1] = (uint8_t)(counter >> 8); cb[2] = (uint8_t)(counter >> 16); cb[3] = (uint8_t)(counter >> 24);
    ck_sha256_init(2); ck_sha256_update(2, seed, 32); ck_sha256_update(2, cb, 4); ck_sha256_final(2, block);
    take = n < 32 ? n : 32;
    for (i = 0; i < take; i++) out[i] = block[i];
    out += take; n -= take;
  }
}
