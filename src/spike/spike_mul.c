/* Probe: the assembly multiply loop against a C reference, on the
 * machine, for known inputs; and the math unit's latency, read at
 * several delays after the operand write. REQUIREMENTS.md 5.3. */
#include <string.h>
#include "mega65/memory.h"
#include "m65_screen.h"
#include "ui.h"
#include "crypto.h"

extern uint16_t fe_mul_in_a[16], fe_mul_in_b[16], fe_mul_out[32];
void fe_mul_m65(void);
void fe_red_m65(void);

static char line[81];
static unsigned char row = 2;
static char num[12];

static void say(const char *a, unsigned long v, const char *b, unsigned long w)
{
  strcpy(line, a); ui_put_ulong(num, v); strcat(line, num);
  if (b) { strcat(line, b); ui_put_ulong(num, w); strcat(line, num); }
  ui_line(row++, line, 0);
}

/* C reference: the 512-bit product, 16-bit limbs, 32-bit accumulation. */
static void ref_mul(uint16_t *o, const uint16_t *a, const uint16_t *b)
{
  static uint32_t acc[33];
  uint32_t c, p;
  unsigned i, j;
  for (i = 0; i < 33; i++) acc[i] = 0;
  for (i = 0; i < 16; i++)
    for (j = 0; j < 16; j++) {
      p = (uint32_t)a[i] * b[j];
      acc[i + j] += (uint16_t)p;
      acc[i + j + 1] += p >> 16;
    }
  c = 0;
  for (i = 0; i < 32; i++) { c += acc[i]; o[i] = (uint16_t)c; c >>= 16; }
}

#define R(a) (*(volatile unsigned char *)(a))

int main(void)
{
  static uint16_t ref[32];
  unsigned i, bad;
  unsigned long p;
  mega65_io_enable();
  m65_screen_init();
  ui_line(0, "ssh spike: the multiplier and the assembly loop", 0);

  /* 1. one product, read at once and after a pause */
  R(0xd772) = 0; R(0xd773) = 0; R(0xd776) = 0; R(0xd777) = 0;
  R(0xd770) = 0xff; R(0xd771) = 0xff; R(0xd774) = 0xff; R(0xd775) = 0xff;
  p = (unsigned long)R(0xd778) | ((unsigned long)R(0xd779) << 8) | ((unsigned long)R(0xd77a) << 16) | ((unsigned long)R(0xd77b) << 24);
  say("65535*65535 read at once: ", p, " want ", 4294836225UL);
  R(0xd770) = 0x34; R(0xd771) = 0x12; R(0xd774) = 0x78; R(0xd775) = 0x56;
  for (i = 0; i < 100; i++) __asm__ volatile("nop");
  p = (unsigned long)R(0xd778) | ((unsigned long)R(0xd779) << 8) | ((unsigned long)R(0xd77a) << 16) | ((unsigned long)R(0xd77b) << 24);
  say("4660*22136 after a pause: ", p, " want ", 103153760UL);

  /* 2. the loop on simple inputs */
  memset(fe_mul_in_a, 0, 32); memset(fe_mul_in_b, 0, 32);
  fe_mul_in_a[0] = 2; fe_mul_in_b[0] = 3;
  fe_mul_m65();
  say("2*3: limb0 ", fe_mul_out[0], " limb1 ", fe_mul_out[1]);
  for (i = 0; i < 16; i++) { fe_mul_in_a[i] = 0xffff; fe_mul_in_b[i] = 0; }
  fe_mul_in_b[0] = 1;
  fe_mul_m65();
  say("(2^256-1)*1: limb0 ", fe_mul_out[0], " limb15 ", fe_mul_out[15]);
  say("   limb16 (want 0) ", fe_mul_out[16], " limb31 ", fe_mul_out[31]);

  /* 2b. single products: a[i]=1, b[j]=1 must give limb i+j = 1 and nothing else */
  {
    static const unsigned char pairs[][2] = { {1, 14}, {1, 15}, {15, 1}, {0, 16 - 1}, {8, 8}, {15, 15} };
    unsigned k;
    for (k = 0; k < 6; k++) {
      unsigned ai = pairs[k][0], bj = pairs[k][1], nz = 0, first = 99;
      memset(fe_mul_in_a, 0, 32); memset(fe_mul_in_b, 0, 32);
      fe_mul_in_a[ai] = 1; fe_mul_in_b[bj] = 1;
      fe_mul_m65();
      for (i = 0; i < 32; i++) if (fe_mul_out[i]) { nz++; if (first == 99) first = i; }
      strcpy(line, "a["); ui_put_ulong(num, ai); strcat(line, num); strcat(line, "]*b["); ui_put_ulong(num, bj); strcat(line, num);
      strcat(line, "]: nonzero limbs "); ui_put_ulong(num, nz); strcat(line, num);
      strcat(line, ", first at "); ui_put_ulong(num, first); strcat(line, num);
      strcat(line, " = "); ui_put_ulong(num, first < 32 ? fe_mul_out[first] : 0); strcat(line, num);
      strcat(line, " (want limb "); ui_put_ulong(num, ai + bj); strcat(line, num); strcat(line, " = 1)");
      ui_line(row++, line, 0);
    }
  }
  /* 3. against the reference on a pseudo-random pair */
  for (i = 0; i < 16; i++) { fe_mul_in_a[i] = (uint16_t)(i * 40503u + 12345u); fe_mul_in_b[i] = (uint16_t)(i * 32771u + 777u); }
  ref_mul(ref, fe_mul_in_a, fe_mul_in_b);
  fe_mul_m65();
  bad = 32;
  for (i = 0; i < 32; i++) if (ref[i] != fe_mul_out[i]) { bad = i; break; }
  if (bad == 32) ui_line(row++, "random pair: all 32 limbs agree with the C reference", 0);
  else say("random pair: first bad limb ", bad, " asm=", fe_mul_out[bad]), say("   reference ", ref[bad], 0, 0);
  /* 4. the fold and reduction in assembly against the same thing in C */
  {
    static uint16_t r[16]; static const uint16_t P[16] = { 0xffed, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff,
                                                            0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0x7fff };
    uint32_t c = 0; unsigned k, pass;
    for (i = 0; i < 16; i++) { c += (uint32_t)ref[i] + 38 * (uint32_t)ref[i + 16]; r[i] = (uint16_t)c; c >>= 16; }
    c *= 38;
    for (i = 0; i < 16 && c; i++) { c += r[i]; r[i] = (uint16_t)c; c >>= 16; }
    for (pass = 0; pass < 2; pass++) {
      static uint16_t s[16]; uint32_t b = 0;
      for (i = 0; i < 16; i++) { b = (uint32_t)r[i] - P[i] - b; s[i] = (uint16_t)b; b = (b >> 16) & 1; }
      if (!b) for (i = 0; i < 16; i++) r[i] = s[i];
    }
    fe_red_m65();
    for (k = 0; k < 16 && fe_mul_out[k] == r[k]; k++) ;
    if (k == 16) ui_line(row++, "fold and reduce: all 16 limbs agree with C", 0);
    else say("fold and reduce: first bad limb ", k, " asm=", fe_mul_out[k]), say("   reference ", r[k], 0, 0);
  }
  /* 5. the fold on products known by hand */
  {
    static const struct { unsigned char limb; uint16_t v; const char *name; } cases[4] = {
      { 0, 5, "t=5" }, { 16, 1, "t=2^256 (want 38)" }, { 15, 0x8000, "t=2^255 (want 19)" }, { 31, 1, "t=2^496 (want 38*2^240)" } };
    unsigned k;
    for (k = 0; k < 4; k++) {
      for (i = 0; i < 32; i++) fe_mul_out[i] = 0;
      fe_mul_out[cases[k].limb] = cases[k].v;
      fe_red_m65();
      say(cases[k].name, fe_mul_out[0], " limb1 ", fe_mul_out[1]);
      say("   limb15 ", fe_mul_out[15], " limb14 ", fe_mul_out[14]);
    }
  }
  ui_line(row + 1, "done", 0);
  for (;;) ;
}
