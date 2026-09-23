/* Probe: the Poly1305 assembly loop alone, on trivial inputs, and the
 * whole tag against the RFC vector. Its own spike: added to spike_mul it
 * moved the program enough that an earlier step crashed (5.3). */
#include <string.h>
#include "mega65/memory.h"
#include "m65_screen.h"
#include "ui.h"
#include "crypto.h"

extern uint8_t poly_mul_h[17];
extern uint32_t poly_mul_rr[34], poly_mul_x[17];
void poly_mul_m65(void);

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
  unsigned i;
  mega65_io_enable();
  m65_screen_init();
  ui_line(0, "ssh spike: the Poly1305 loop  build " __TIME__, 0);
  ui_line(row++, "loop 1: calling...", 0);
  for (i = 0; i < 17; i++) { poly_mul_h[i] = 0; poly_mul_x[i] = 7; }
  for (i = 0; i < 34; i++) poly_mul_rr[i] = 0;
  poly_mul_h[0] = 1; poly_mul_rr[17] = 2; poly_mul_rr[0] = 640;
  poly_mul_m65();
  say("loop 1: x[0] ", poly_mul_x[0], " x[1] ", poly_mul_x[1]);
  say("   x[16] ", poly_mul_x[16], " (want 2, 0, 0)", 0);
  for (i = 0; i < 17; i++) { poly_mul_h[i] = 0; poly_mul_x[i] = 7; }
  for (i = 0; i < 34; i++) poly_mul_rr[i] = 0;
  poly_mul_h[16] = 1; poly_mul_rr[17] = 3; poly_mul_rr[0] = 960; poly_mul_rr[18] = 5; poly_mul_rr[1] = 1600;
  poly_mul_m65();
  say("loop 2: x[16] ", poly_mul_x[16], " x[0] ", poly_mul_x[0]);
  ui_line(row++, "   (want 3 and 1600)", 0);
  hex(key, "85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b");
  hex(want, "a8061dc1305136c6c22b8baf0c0127a9");
  ui_line(row, "tag: computing...", 0);
  poly1305(key, (const uint8_t *)"Cryptographic Forum Research Group", 34, tag);
  ui_line(row++, crypto_equal(tag, want, 16) ? "tag: ok, matches RFC 8439" : "tag: FAIL", 0);
  ui_line(row + 1, "done", 0);
  for (;;) ;
}
