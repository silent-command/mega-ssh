#include <string.h>
#include "mega65/memory.h"
#include "m65_screen.h"
#include "screen.h"
#include "meganet.h"
#include "ui.h"

void (*ui_idle)(void);

/* Pinned to .bss: the compiler promoted this 81-byte buffer to zero
 * page, which the crypto bank needs from $70 up (bank/crypto.ld). */
static char row_buf[81] __attribute__((section(".bss.row_buf")));
char ui_scratch[81] __attribute__((section(".bss.ui_scratch")));
static unsigned char last_frame;
static unsigned char spin_frame;

/* The typing queue's top event as ASCII ($D610); Escape is $1B there,
 * measured with a key probe (5.21). */
unsigned char ui_key(void)
{
  unsigned char k = PEEK(0xd610);
  if (k) POKE(0xd610, 0);                      /* pop it */
  return k;
}

unsigned char ui_key_mods(unsigned char *mods)
{
  *mods = PEEK(0xd611);                        /* the modifiers held right now, read before the pop */
  return ui_key();
}

void ui_flush_keys(void)
{
  while (ui_key()) ;
}

unsigned char ui_wait_key(void)
{
  unsigned char k;
  for (;;) {
    k = ui_key();
    if (k) return k;
    meganet_poll();
    if (PEEK(0xd7fa) != last_frame) {
      last_frame = PEEK(0xd7fa);
      if (ui_idle) ui_idle();
    }
  }
}

/* Builds a+b padded with spaces to all 80 columns. It was 79 from the
 * console-library days, when an 80th character wrapped; scr_text does
 * not wrap, and the unpainted column kept a session's last column on
 * the host screen after it ended (5.24). */
static void build_row(const char *a, const char *b)
{
  unsigned char n = 0;
  if (a) while (*a && n < 80) row_buf[n++] = *a++;
  if (b) while (*b && n < 80) row_buf[n++] = *b++;
  while (n < 80) row_buf[n++] = ' ';
  row_buf[n] = 0;
}

void ui_line(unsigned char row, const char *a, const char *b)
{
  build_row(a, b);
  scr_text(row, 0, row_buf, m65_screen_text_colour(), 0);
}

void ui_line_rev(unsigned char row, const char *a, const char *b)
{
  build_row(a, b);
  scr_text(row, 0, row_buf, m65_screen_text_colour(), 1);
}

void ui_status(const char *a, const char *b)
{
  ui_line(UI_ROW_STATUS, a, b);
}

void ui_clear_rows(unsigned char from, unsigned char to)
{
  while (from <= to) { ui_line(from, 0, 0); from++; }
}

unsigned char ui_read_line(unsigned char row, const char *prompt, char *out,
                           unsigned char maxlen, unsigned char hide)
{
  char *shown = ui_scratch;
  unsigned char len, key, i, n;
  unsigned char fresh = 1;                      /* the default is still untouched */
  const char *p;

  out[maxlen] = 0;
  for (len = 0; out[len]; len++) ;
  /* No flush on entry: a flush here ate keys typed ahead of a prompt, and
   * the key that opened the prompt was already consumed by whoever read
   * it. A held RETURN auto-repeating through several prompts submits
   * their defaults, which is what holding RETURN asks for. */
  for (;;) {
    n = 0;
    for (p = prompt; *p && n < 78; p++) shown[n++] = *p;
    for (i = 0; i < len && n < 78; i++) shown[n++] = hide ? '*' : out[i];
    shown[n++] = '_'; shown[n] = 0;
    ui_line(row, shown, 0);

    key = ui_wait_key();
    if (key == KEY_RETURN) return 1;             /* an empty line is the caller's to judge */
    if (key == KEY_STOP) return 0;
    if (key == KEY_F1) return 2;                 /* the identity screen, for the Host prompt (5.22) */
    if (key == KEY_DEL) { fresh = 0; if (len) out[--len] = 0; continue; }
    if (key >= 0x20 && key < 0x7f) {
      if (fresh) { len = 0; fresh = 0; }         /* typing replaces the offered default */
      if (len < maxlen) { out[len++] = (char)key; out[len] = 0; }
    }
  }
}

void ui_spin(void)
{
  static const char glyphs[4] = { '.', 'o', 'O', 'o' };
  char s[2];
  if (++spin_frame & 7) return;
  s[0] = glyphs[(spin_frame >> 3) & 3];
  s[1] = 0;
  scr_text(UI_ROW_TITLE, 79, s, m65_screen_text_colour(), 0);
}

void ui_spin_clear(void)
{
  scr_text(UI_ROW_TITLE, 79, " ", m65_screen_text_colour(), 0);
}

void ui_put_ulong(char *p, unsigned long v)
{
  char t[11];
  unsigned char n = 0;
  do { t[n++] = (char)('0' + v % 10); v /= 10; } while (v);
  while (n) *p++ = t[--n];
  *p = 0;
}

void ui_put_size(char *p, unsigned long v)
{
  char t[12];
  unsigned char n, pad;
  if (v > 9999999UL) { ui_put_ulong(t, v >> 10); strcat(t, "K"); }
  else ui_put_ulong(t, v);
  n = (unsigned char)strlen(t);
  pad = (unsigned char)(n < 7 ? 7 - n : 0);
  for (; pad; pad--) *p++ = ' ';                   /* not while (pad--): 5.6 */
  strcpy(p, t);
}
