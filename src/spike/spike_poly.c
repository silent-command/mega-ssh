/* Copyright 2026 Justin Cameron
 * SPDX-License-Identifier: Apache-2.0 */
/* Probe: the Poly1305 block in assembly alone, on trivial inputs, and
 * the whole tag against the RFC vector. Its own spike: added to
 * spike_mul it moved the program enough that an earlier step crashed
 * (5.3). */
#include <string.h>
#include "mega65/memory.h"
#include "m65_screen.h"
#include "ui.h"
#include "crypto.h"

extern uint8_t poly_h[20], poly_rr[32], poly_m[16], poly_hibit;
void poly_block_m65(void);

static unsigned long word(const uint8_t *p)
{
  return (unsigned long)p[0] | ((unsigned long)p[1] << 8) | ((unsigned long)p[2] << 16) | ((unsigned long)p[3] << 24);
}

static char line[81];
static char num[12];
static unsigned char row = 2;

static void say(const char *a, unsigned long v, const char *b, unsigned long w)
{
  strcpy(line, a); ui_put_ulong(num, v); strcat(line, num);
  if (b) { strcat(line, b); ui_put_ulong(num, w); strcat(line, num); }
  ui_line(row++, line, 0);
}

static void hex(uint8_t *out, const char *s)
{
  while (*s) {
    unsigned hi = *s <= '9' ? *s - '0' : (*s | 32) - 'a' + 10; s++;
    unsigned lo = *s <= '9' ? *s - '0' : (*s | 32) - 'a' + 10; s++;
    *out++ = (uint8_t)(hi << 4 | lo);
  }
}

static uint8_t key[32], tag[16], want[16];

int main(void)
{
  mega65_io_enable();
  m65_screen_init();
  ui_line(0, "ssh spike: the Poly1305 block  build " __TIME__, 0);
  ui_line(row++, "block 1: calling...", 0);
  memset(poly_h, 0, 20); memset(poly_rr, 0, 32); memset(poly_m, 0, 16);
  poly_m[0] = 1; poly_hibit = 0; poly_rr[16] = 2;          /* m = 1, r0 = 2 */
  poly_block_m65();
  say("block 1: h0 ", word(poly_h), " h1 ", word(poly_h + 4));
  say("   h4 ", word(poly_h + 16), " (want 2, 0, 0)", 0);
  memset(poly_h, 0, 20); memset(poly_rr, 0, 32); memset(poly_m, 0, 16);
  poly_hibit = 1; poly_rr[16] = 3; poly_rr[4] = 5;         /* h4 = 1, r0 = 3, 5r1/4 = 5 */
  poly_block_m65();
  say("block 2: h1 ", word(poly_h + 4), " h4 ", word(poly_h + 16));
  ui_line(row++, "   (want 5 and 3)", 0);
  hex(key, "85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b");
  hex(want, "a8061dc1305136c6c22b8baf0c0127a9");
  ui_line(row, "tag: computing...", 0);
  poly1305(key, (const uint8_t *)"Cryptographic Forum Research Group", 34, tag);
  ui_line(row++, crypto_equal(tag, want, 16) ? "tag: ok, matches RFC 8439" : "tag: FAIL", 0);
  ui_line(row + 1, "done", 0);
  for (;;) ;
}
