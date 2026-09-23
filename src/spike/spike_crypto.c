/* Step 3: the primitives on the MEGA65, checked against the same vectors
 * the host suite uses, and timed on the frame counter. The go/no-go for
 * the project: X25519 and an Ed25519 verification must fit a handshake
 * people will wait for. REQUIREMENTS.md 5.2. */
#include <string.h>
#include "mega65/memory.h"
#include "m65_screen.h"
#include "ui.h"
#include "crypto.h"

/* Frames are counted through crypto_yield, because $D7FA wraps every
 * 256 frames and the long operations run for longer than that. */
static unsigned int frames;
static unsigned char last_frame;

static void tick(void)
{
  unsigned char f = PEEK(0xd7fa);
  frames = (unsigned int)(frames + (unsigned char)(f - last_frame));
  last_frame = f;
}

static void t_start(void) { last_frame = PEEK(0xd7fa); frames = 0; }

static void hex(uint8_t *out, const char *s)
{
  while (*s) {
    unsigned hi = *s <= '9' ? *s - '0' : (*s | 32) - 'a' + 10; s++;
    unsigned lo = *s <= '9' ? *s - '0' : (*s | 32) - 'a' + 10; s++;
    *out++ = (uint8_t)(hi << 4 | lo);
  }
}

static char line[81];
static char num[12];
static unsigned char row;

static void report(const char *name, unsigned char ok)
{
  tick();
  strcpy(line, name);
  strcat(line, ok ? ": ok, " : ": FAIL, ");
  ui_put_ulong(num, frames); strcat(line, num);
  strcat(line, " frames = ");
  ui_put_ulong(num, frames / 50); strcat(line, num); strcat(line, ".");
  ui_put_ulong(num, (frames % 50) * 2); strcat(line, num);
  strcat(line, " s");
  ui_line(row++, line, 0);
}

static uint8_t out[64], key[32], nonce[12], pk[32], sig[64], msg[64], a[32], b[32], want[64];
static uint8_t buf[1024];

int main(void)
{
  unsigned i;
  mega65_io_enable();
  m65_screen_init();
  ui_line(0, "ssh: the primitives on the MEGA65, timed (PAL frames, 50/s)  build " __TIME__, 0);
  row = 2;
  crypto_yield = tick;

  /* SHA-256 over 1 KB, ten times */
  hex(want, "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");
  {
    sha256_ctx c;
    memset(buf, 'a', sizeof buf);
    t_start();
    sha256_init(&c);
    for (i = 0; i < 10; i++) { sha256_update(&c, buf, sizeof buf); tick(); }
    sha256_final(&c, out);
    /* 10 KB of 'a' is not the million-a vector; just time it */
    report("sha256, 10 KB", 1);
  }
  sha256((const uint8_t *)"abc", 3, out);
  hex(want, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
  t_start(); report("sha256 abc", crypto_equal(out, want, 32));

  {
    sha512_ctx c;
    t_start();
    sha512_init(&c); sha512_update(&c, (const uint8_t *)"abc", 3); sha512_final(&c, out);
    hex(want, "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f");
    report("sha512 abc", crypto_equal(out, want, 64));
  }

  hex(key, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
  hex(nonce, "000000090000004a00000000");
  t_start();
  chacha20_block(key, nonce, 1, out);
  hex(want, "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4ed2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e");
  report("chacha20 block", crypto_equal(out, want, 64));
  t_start();
  for (i = 0; i < 4; i++) { chacha20_xor(key, nonce, 1, buf, sizeof buf); tick(); }
  report("chacha20, 4 KB", 1);

  hex(key, "85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b");
  t_start();
  poly1305(key, (const uint8_t *)"Cryptographic Forum Research Group", 34, out);
  hex(want, "a8061dc1305136c6c22b8baf0c0127a9");
  report("poly1305 tag", crypto_equal(out, want, 16));
  t_start();
  for (i = 0; i < 4; i++) { poly1305(key, buf, sizeof buf, out); tick(); }
  report("poly1305, 4 KB", 1);

  t_start();
  i = crypto_fe_selftest();
  strcpy(line, "field identities: failing bits "); ui_put_ulong(num, i); strcat(line, num);
  ui_line(row++, line, 0);

  hex(a, "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
  hex(pk, "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
  hex(want, "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");
  {
    static const char *names[7] = { "fe_mul x200", "fe_add x200", "fe_sub x200", "fe_cswap x200", "memcpy 32 x200", "mul loop x200", "reduce x200" };
    unsigned char w;
    for (w = 0; w < 7; w++) { t_start(); crypto_fe_bench(w, 200); report(names[w], 1); }
  }
  ui_line(row, "x25519 running...", 0);
  t_start();
  x25519(out, a, pk);
  report("x25519 shared secret", crypto_equal(out, want, 32));

  hex(pk, "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025");
  hex(sig, "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a");
  hex(msg, "af82");
  ui_line(row, "ed25519 verify running...", 0);
  t_start();
  i = (unsigned)ed25519_verify(sig, msg, 2, pk);
  report("ed25519 verify", i == 1);
  msg[1] ^= 1;
  t_start();
  i = (unsigned)ed25519_verify(sig, msg, 2, pk);
  report("ed25519 rejects", i == 0);

  ui_line(row + 1, "done", 0);
  (void)b;
  for (;;) ;
}
