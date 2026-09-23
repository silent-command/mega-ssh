/* Random bytes for the key exchange's private scalar, the KEXINIT cookie
 * and packet padding.
 *
 * The MEGA65 has no random-number hardware this program can reach, so
 * the seed is timing jitter: over about a second, the raster position
 * and a CIA timer are sampled at every change of the frame counter,
 * along with the ethernet controller's frame counters if the stack is
 * up, and all of it is hashed. Keystrokes and network replies add more
 * through rnd_stir. Output is SHA-256 of the seed and a counter. This is
 * a hobbyist's source, not a certified one; REQUIREMENTS.md says so. */
#include "mega65/memory.h"
#include "ckit.h"
#include "rnd.h"

static uint8_t seed[32];          /* the pool is sha256 slot 3 in the bank */
static uint32_t counter;
static uint8_t stir_byte;

static void sample(void)
{
  uint8_t s[6];
  s[0] = PEEK(0xd012); s[1] = PEEK(0xd7fa); s[2] = PEEK(0xdc04); s[3] = PEEK(0xdc05);
  s[4] = PEEK(0xd6e1); s[5] = stir_byte++;
  ck_sha256_update(3, s, 6);
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
