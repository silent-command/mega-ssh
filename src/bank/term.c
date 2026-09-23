#include <stdint.h>
#include "glyph.h"
#include "dma.h"
#include "term.h"

#ifdef TERM_HOST_TEST
#include <string.h>
#define IN_BSS(n)
#else
#include "termscr.h"
#define IN_BSS(n) __attribute__((section(".bss." n)))
#endif

uint8_t term_app_cursor;

#define LAST_COL (TERM_COLS - 1)
#define LAST_ROW ((uint8_t)(term_rows - 1))
#define NONE 0xff                     /* no colour chosen: the screen's own */

/* ---- state ------------------------------------------------------------ */

static uint8_t row, col, wrap_pending;
static uint8_t term_rows;             /* 25 or 50 (5.23) */
static uint8_t cursor_on, cursor_visible, under_cursor;
static uint8_t fg, bg, bold, rev, uline, blink;  /* fg, bg: ANSI 0-15, 16 + a machine colour, or NONE */
static uint8_t top, bot;              /* the scroll region, inclusive */
static uint8_t autowrap, insert_mode, newline_mode;
static uint8_t s_row, s_col, s_fg, s_bg, s_bold, s_rev, s_uline, s_blink;
static uint8_t g0_line, g1_line, in_g1;          /* DEC line drawing in G0/G1; SO selects G1 */
static uint8_t def_fg, def_bg;        /* the machine's colours, MEGA65 0-15 */
static uint8_t scr_bg;                /* the MEGA65 colour now in $D021 */

enum { S_GROUND, S_ESC, S_CSI, S_OSC, S_OSC_ESC, S_SKIP1, S_CHARSET };
static uint8_t state, which_set;
static uint16_t params[16] IN_BSS("term_params");   /* a truecolor pair is ten (5.22) */
static uint8_t nparams, priv, inter, digits;

static uint16_t cp;                   /* the UTF-8 code point being assembled */
static uint8_t need;                  /* continuation bytes still expected */

/* ANSI colour n to the machine's palette: the eight, then the bright eight. */
static const uint8_t palette[16] = { 0, 2, 5, 7, 6, 4, 3, 15, 11, 10, 13, 7, 14, 4, 3, 1 };

/* The machine's sixteen as RGB (the C64 palette the ROM sets), for the
 * nearest match to a 256-colour index or a truecolor triple (5.22). */
static const uint8_t m65_rgb[16][3] = {
  { 0, 0, 0 }, { 255, 255, 255 }, { 136, 0, 0 }, { 170, 255, 238 }, { 204, 68, 204 }, { 0, 204, 85 }, { 0, 0, 170 }, { 238, 238, 119 },
  { 221, 136, 85 }, { 102, 68, 0 }, { 255, 119, 119 }, { 51, 51, 51 }, { 119, 119, 119 }, { 170, 255, 102 }, { 0, 136, 255 }, { 187, 187, 187 }
};

/* The squared difference of two channels, scaled to a quarter so that
 * three of them, green twice, fit sixteen bits: no 32-bit arithmetic in
 * the bank, which links no helper for it. */
static uint16_t chan_d(uint8_t a, uint8_t b)
{
  uint8_t ad = a > b ? (uint8_t)(a - b) : (uint8_t)(b - a);
  return (uint16_t)(((uint16_t)ad * ad) >> 2);
}

static uint8_t nearest(uint8_t r, uint8_t g, uint8_t b)
{
  uint8_t i, best = 0;
  uint16_t d, bd = 0xffff;
  for (i = 0; i < 16; i++) {
    d = (uint16_t)(chan_d(r, m65_rgb[i][0]) + 2 * chan_d(g, m65_rgb[i][1]) + chan_d(b, m65_rgb[i][2]));   /* green weighs most */
    if (d < bd) { bd = d; best = i; }
  }
  return best;
}

static uint8_t cube(uint8_t v) { return v ? (uint8_t)(55 + (v << 5) + (v << 3)) : 0; }   /* 55 + 40 v */

/* An xterm 256-colour index: the sixteen as themselves, the 6x6x6 cube
 * and the greys as the nearest machine colour, offset by 16. */
static uint8_t colour256(uint16_t n)
{
  uint8_t r, g, b;
  if (n < 16) return (uint8_t)n;
  if (n > 255) n = 255;
  if (n >= 232) { uint8_t x = (uint8_t)(n - 232); r = g = b = (uint8_t)(8 + (x << 3) + (x << 1)); }   /* 8 + 10 x */
  else {
    uint8_t x = (uint8_t)(n - 16), rr = 0, gg = 0;
    while (x >= 36) { x = (uint8_t)(x - 36); rr++; }
    while (x >= 6) { x = (uint8_t)(x - 6); gg++; }
    r = cube(rr); g = cube(gg); b = cube(x);
  }
  return (uint8_t)(16 + nearest(r, g, b));
}

/* A colour value as the machine's colour. */
static uint8_t m65_of(uint8_t x) { return x >= 16 ? (uint8_t)(x - 16) : palette[x]; }

/* ---- cells ------------------------------------------------------------
 * Everything below the parser reaches the screen through five calls
 * (termscr.h on the machine): here the host test's, two arrays. */

static uint16_t off(uint8_t r, uint8_t c) { return (uint16_t)((uint16_t)r * TERM_COLS + c); }

#ifdef TERM_HOST_TEST
uint8_t host_screen[TERM_COLS * TERM_ROWS_MAX], host_colour[TERM_COLS * TERM_ROWS_MAX];
static uint8_t sc_peek(uint16_t o) { return host_screen[o]; }
static void sc_poke(uint16_t o, uint8_t v) { host_screen[o] = v; }
static void fill_both(uint16_t o, uint8_t code, uint8_t colour, uint16_t n)
{
  memset(host_screen + o, code, n); memset(host_colour + o, colour, n);
}
static void copy_both(uint16_t from, uint16_t to, uint16_t n)
{
  memmove(host_screen + to, host_screen + from, n); memmove(host_colour + to, host_colour + from, n);
}
static void move_cells(uint16_t from, uint16_t to, uint8_t n) { copy_both(from, to, n); }
#endif

static void cell_put(uint8_t r, uint8_t c, uint8_t code, uint8_t colour)
{
  fill_both(off(r, c), code, colour, 1);
}

static void rows_copy(uint8_t dst, uint8_t src, uint8_t n)
{
  if (!n || dst == src) return;
  if (dst < src) copy_both(off(src, 0), off(dst, 0), (uint16_t)n * TERM_COLS);
  else {                                          /* downward: the rows overlap, so from the bottom up */
    uint8_t i;
    for (i = n; i; ) {
      i--;                                        /* not while (n--): REQUIREMENTS.md 5.6 */
      copy_both(off((uint8_t)(src + i), 0), off((uint8_t)(dst + i), 0), TERM_COLS);
    }
  }
}

#ifdef TERM_HOST_TEST
uint8_t host_d021, host_d031;
static void set_screen_bg(uint8_t m65) { host_d021 = m65; scr_bg = m65; }
static void set_attr_mode(uint8_t on) { host_d031 = on ? 0x20 : 0; }
static void restore_screen(void) { host_d031 = 0; host_d021 = def_bg; }
#else
#define VD020 (*(volatile uint8_t *)0xD020)
#define VD021 (*(volatile uint8_t *)0xD021)
#define VD031 (*(volatile uint8_t *)0xD031)
static void set_screen_bg(uint8_t m65) { VD021 = m65; scr_bg = m65; }
static void set_attr_mode(uint8_t on) { if (on) VD031 |= 0x20; else VD031 = (uint8_t)(VD031 & ~0x20); }
static void restore_screen(void) { VD031 = (uint8_t)(VD031 & ~0x20); VD021 = def_bg; }
#endif

/* A background differs from the screen's global background when the host
 * set one and it is not the color in $D021, which is the client's own
 * (inherited or cycled with MEGA+B; 5.31): only then is the reverse-video
 * approximation needed. A background that matches the screen lets the
 * real foreground show. */
static uint8_t bg_differs(void) { return bg != NONE && m65_of(bg) != scr_bg; }

static uint8_t cell_colour(void)
{
  uint8_t c;
  if (bg_differs() && !rev) c = m65_of(bg);        /* a differing background is drawn as reverse video in it */
  else if (fg == NONE) c = def_fg;
  else if (fg >= 16) c = (uint8_t)(fg - 16);
  else { c = fg; if (bold && c < 8) c = (uint8_t)(c + 8); c = palette[c]; }
  /* the VIC-III extended attributes: colour bit 7 underline, bit 4 blink */
  if (uline) c |= 0x80;
  if (blink) c |= 0x10;
  return c;
}

static uint8_t cell_rev(void) { return (uint8_t)(bg_differs() ^ rev); }

static uint8_t blank_code(void) { return (uint8_t)(0x20 | (cell_rev() ? 0x80 : 0)); }

static void hide(void)
{
  if (cursor_on) { sc_poke(off(row, col), under_cursor); cursor_on = 0; }
}

static void show(void)
{
  if (cursor_on || !cursor_visible) return;
  under_cursor = sc_peek(off(row, col));
  sc_poke(off(row, col), (uint8_t)(under_cursor ^ 0x80));
  cursor_on = 1;
}

void term_cursor(uint8_t on)
{
  if (on) show(); else hide();
}

void term_end(void)
{
  restore_screen();
}

/* Local colours the user cycles during a session: the default text
 * colour for cells the host has not coloured, and the screen background
 * and border, applied at once (5.20). */
void term_recolour(uint8_t text_colour, uint8_t bg_colour)
{
  def_fg = text_colour;
  def_bg = bg_colour;
  set_screen_bg(bg_colour);
#ifdef TERM_HOST_TEST
  (void)0;
#else
  VD020 = bg_colour;
#endif
}

static void erase(uint8_t r, uint8_t c, uint8_t n)
{
  fill_both(off(r, c), blank_code(), cell_colour(), n);
}

static void erase_rows(uint8_t from, uint8_t to)
{
  while (from <= to) { erase(from, 0, TERM_COLS); if (from == LAST_ROW) break; from++; }
}

static void scroll_up(uint8_t t, uint8_t b, uint8_t n)
{
  uint8_t h = (uint8_t)(b - t + 1);
  if (n >= h) { erase_rows(t, b); return; }
  rows_copy(t, (uint8_t)(t + n), (uint8_t)(h - n));
  erase_rows((uint8_t)(b - n + 1), b);
}

static void scroll_down(uint8_t t, uint8_t b, uint8_t n)
{
  uint8_t h = (uint8_t)(b - t + 1);
  if (n >= h) { erase_rows(t, b); return; }
  rows_copy((uint8_t)(t + n), t, (uint8_t)(h - n));
  erase_rows(t, (uint8_t)(t + n - 1));
}

static void insert_cells(uint8_t n)
{
  uint16_t o = off(row, col);
  if (n > TERM_COLS - col) n = (uint8_t)(TERM_COLS - col);
  move_cells(o, (uint16_t)(o + n), (uint8_t)(TERM_COLS - col - n));
  erase(row, col, n);
}

static void delete_cells(uint8_t n)
{
  uint16_t o = off(row, col);
  if (n > TERM_COLS - col) n = (uint8_t)(TERM_COLS - col);
  move_cells((uint16_t)(o + n), o, (uint8_t)(TERM_COLS - col - n));
  erase(row, (uint8_t)(TERM_COLS - n), n);
}

/* ---- cursor ----------------------------------------------------------- */

static void linefeed(void)
{
  if (row == bot) scroll_up(top, bot, 1);
  else if (row < LAST_ROW) row++;
}

static void reverse_index(void)
{
  if (row == top) scroll_down(top, bot, 1);
  else if (row) row--;
}

static void move_up(uint8_t n)
{
  uint8_t lim = row >= top ? top : 0;
  row = (uint8_t)((n > row || row - n < lim) ? lim : row - n);
  wrap_pending = 0;
}

static void move_down(uint8_t n)
{
  uint8_t lim = row <= bot ? bot : LAST_ROW;
  row = (uint8_t)(row + n > lim ? lim : row + n);
  wrap_pending = 0;
}

static void set_col(uint8_t c) { col = c > LAST_COL ? LAST_COL : c; wrap_pending = 0; }
static void set_row(uint8_t r) { row = r > LAST_ROW ? LAST_ROW : r; wrap_pending = 0; }

static void save_cursor(void) { s_row = row; s_col = col; s_fg = fg; s_bg = bg; s_bold = bold; s_rev = rev; s_uline = uline; s_blink = blink; }
static void restore_cursor(void) { row = s_row; col = s_col; fg = s_fg; bg = s_bg; bold = s_bold; rev = s_rev; uline = s_uline; blink = s_blink; wrap_pending = 0; }

/* ---- glyphs ----------------------------------------------------------- */

/* DEC special graphics, '`' to '~', as this machine's screen codes. */
static const uint8_t dec_graphics[31] = {
  0x2a, 0x66, 0x2e, 0x2e, 0x2e, 0x2e, 0x0f, 0x2b, 0x20, 0x20,
  0x7d, 0x6e, 0x70, 0x6d, 0x5b, 0x40, 0x40, 0x40, 0x40, 0x40,
  0x6b, 0x73, 0x72, 0x71, 0x5d, 0x3c, 0x3e, 0x10, 0x23, 0x1c, 0x2a
};

static uint8_t ascii_code(uint8_t c)
{
  if ((in_g1 ? g1_line : g0_line) && c >= 0x60 && c <= 0x7e) return dec_graphics[c - 0x60];
  return (uint8_t)m65_ascii_to_screencode((char)c);
}

/* The Unicode box-drawing block, to the same graphics; 0 for none.
 * Ranges, first match wins: the verticals before the run of lines. */
static const uint16_t box_lo[] = { 0x2502, 0x250a, 0x2551, 0x2500, 0x254c, 0x250c, 0x2552, 0x2510, 0x2555, 0x2514, 0x2558,
                                   0x2518, 0x255b, 0x251c, 0x255e, 0x2524, 0x2561, 0x252c, 0x2564, 0x2534, 0x2567, 0x253c, 0x256a,
                                   0x256d, 0x256e, 0x256f, 0x2570,                                     /* the rounded corners (5.22) */
                                   0x2580, 0x2581, 0x2584, 0x2588, 0x2589, 0x258d, 0x258e, 0x258f, 0x2590, 0x2591, 0x2594, 0x2595,
                                   0x2596, 0x2597, 0x2598, 0x259a, 0x259d, 0x259e, 0x2599, 0x25a0 };
static const uint16_t box_hi[] = { 0x2503, 0x250b, 0x2551, 0x250b, 0x2550, 0x250f, 0x2554, 0x2513, 0x2557, 0x2517, 0x255a,
                                   0x251b, 0x255d, 0x2523, 0x2560, 0x252b, 0x2563, 0x2533, 0x2566, 0x253b, 0x2569, 0x254b, 0x256c,
                                   0x256d, 0x256e, 0x256f, 0x2570,
                                   0x2580, 0x2583, 0x2587, 0x2588, 0x258c, 0x258d, 0x258e, 0x258f, 0x2590, 0x2593, 0x2594, 0x2595,
                                   0x2596, 0x2597, 0x2598, 0x259a, 0x259d, 0x259e, 0x259f, 0x25ae };
static const uint8_t box_to[] =  { 0x5d, 0x5d, 0x5d, 0x40, 0x40, 0x70, 0x70, 0x6e, 0x6e, 0x6d, 0x6d,
                                   0x7d, 0x7d, 0x6b, 0x6b, 0x73, 0x73, 0x71, 0x71, 0x72, 0x72, 0x5b, 0x5b,
                                   0x70, 0x6e, 0x7d, 0x6d,
                                   0xe2, 0x64, 0x62, 0xa0, 0x61, 0x75, 0x74, 0x65, 0xe1, 0x66, 0x63, 0x67,
                                   0x7b, 0x6c, 0x7e, 0x7f, 0x7c, 0xff, 0xa0, 0xa0 };

static uint8_t box_code(uint16_t u)
{
  uint8_t i;
  if (u < 0x2500 || u > 0x25ae) return 0;
  for (i = 0; i < sizeof box_to; i++)
    if (u >= box_lo[i] && u <= box_hi[i]) return box_to[i];
  return 0;
}

static void put_code(uint8_t code)
{
  if (wrap_pending) {
    wrap_pending = 0;
    if (autowrap) { col = 0; linefeed(); }
  }
  if (insert_mode) insert_cells(1);
  cell_put(row, col, (uint8_t)(code | (cell_rev() ? 0x80 : 0)), cell_colour());
  if (col < LAST_COL) col++; else wrap_pending = 1;
}

static void put_codepoint(uint16_t u)
{
  uint8_t code = box_code(u);
  if (!code) code = (uint8_t)m65_ascii_to_screencode(m65_fold_codepoint(u));
  put_code(code);
}

/* ---- the escape sequences --------------------------------------------- */

static uint16_t P(uint8_t i, uint16_t def) { return (i < nparams && params[i]) ? params[i] : def; }
static uint16_t P0(uint8_t i) { return i < nparams ? params[i] : 0; }

static void sgr(void)
{
  uint8_t i;
  if (!nparams) { fg = bg = NONE; bold = rev = uline = blink = 0; return; }
  for (i = 0; i < nparams; i++) {
    uint16_t v = params[i];
    if (v == 0) { fg = bg = NONE; bold = rev = uline = blink = 0; }
    else if (v == 1) bold = 1;
    else if (v == 4) uline = 1;
    else if (v == 5 || v == 6) blink = 1;
    else if (v == 7) rev = 1;
    else if (v == 22) bold = 0;
    else if (v == 24) uline = 0;
    else if (v == 25) blink = 0;
    else if (v == 27) rev = 0;
    else if (v >= 30 && v <= 37) fg = (uint8_t)(v - 30);
    else if (v == 39) fg = NONE;
    else if (v >= 40 && v <= 47) bg = (uint8_t)(v - 40);
    else if (v == 49) bg = NONE;
    else if (v >= 90 && v <= 97) fg = (uint8_t)(v - 90 + 8);
    else if (v >= 100 && v <= 107) bg = (uint8_t)(v - 100 + 8);
    else if (v == 38 || v == 48) {                /* 38;5;n and 38;2;r;g;b: the nearest of the sixteen (5.22) */
      uint8_t c = NONE;
      if (i + 2 < nparams && params[i + 1] == 5) { c = colour256(params[i + 2]); i = (uint8_t)(i + 2); }
      else if (i + 4 < nparams && params[i + 1] == 2) {
        c = (uint8_t)(16 + nearest((uint8_t)params[i + 2], (uint8_t)params[i + 3], (uint8_t)params[i + 4])); i = (uint8_t)(i + 4);
      } else break;                                 /* malformed: the rest of the sequence is unreadable */
      if (v == 38) fg = c; else bg = c;
    }
  }
}

static void set_mode(uint8_t on)
{
  uint8_t i;
  for (i = 0; i < nparams; i++) {
    uint16_t v = params[i];
    if (priv) {
      if (v == 1) term_app_cursor = on;
      else if (v == 7) autowrap = on;
      else if (v == 25) { cursor_visible = on; if (!on) hide(); }
      else if (v == 47 || v == 1047 || v == 1049) {
        if (on) { if (v == 1049) save_cursor(); erase_rows(0, LAST_ROW); }
        else { erase_rows(0, LAST_ROW); if (v == 1049) restore_cursor(); }
      }
    } else {
      if (v == 4) insert_mode = on;
      else if (v == 20) newline_mode = on;
    }
  }
}

static void csi(uint8_t final)
{
  uint8_t n;
  if (inter) return;                              /* CSI ! p, CSI $ q and friends: nothing here */
  switch (final) {
  case 'A': move_up((uint8_t)P(0, 1)); break;
  case 'B': case 'e': move_down((uint8_t)P(0, 1)); break;
  case 'C': case 'a': n = (uint8_t)P(0, 1); set_col((uint8_t)(col + n > LAST_COL ? LAST_COL : col + n)); break;
  case 'D': n = (uint8_t)P(0, 1); set_col((uint8_t)(n > col ? 0 : col - n)); break;
  case 'E': move_down((uint8_t)P(0, 1)); set_col(0); break;
  case 'F': move_up((uint8_t)P(0, 1)); set_col(0); break;
  case 'G': case '`': set_col((uint8_t)(P(0, 1) - 1)); break;
  case 'd': set_row((uint8_t)(P(0, 1) - 1)); break;
  case 'H': case 'f': set_row((uint8_t)(P(0, 1) - 1)); set_col((uint8_t)(P(1, 1) - 1)); break;
  case 'J':
    switch (P0(0)) {
    case 0: erase(row, col, (uint8_t)(TERM_COLS - col)); if (row < LAST_ROW) erase_rows((uint8_t)(row + 1), LAST_ROW); break;
    case 1: if (row) erase_rows(0, (uint8_t)(row - 1)); erase(row, 0, (uint8_t)(col + 1)); break;
    default:                                       /* the screen background is the client's; a host's background is per cell (5.31) */
      set_screen_bg(def_bg);
      erase_rows(0, LAST_ROW);
      break;
    }
    break;
  case 'K':
    switch (P0(0)) {
    case 0: erase(row, col, (uint8_t)(TERM_COLS - col)); break;
    case 1: erase(row, 0, (uint8_t)(col + 1)); break;
    default: erase(row, 0, TERM_COLS); break;
    }
    break;
  case 'L': if (row >= top && row <= bot) scroll_down(row, bot, (uint8_t)P(0, 1)); break;
  case 'M': if (row >= top && row <= bot) scroll_up(row, bot, (uint8_t)P(0, 1)); break;
  case '@': insert_cells((uint8_t)P(0, 1)); break;
  case 'P': delete_cells((uint8_t)P(0, 1)); break;
  case 'X': n = (uint8_t)P(0, 1); erase(row, col, (uint8_t)(n > TERM_COLS - col ? TERM_COLS - col : n)); break;
  case 'S': scroll_up(top, bot, (uint8_t)P(0, 1)); break;
  case 'T': scroll_down(top, bot, (uint8_t)P(0, 1)); break;
  case 'r': {
    uint8_t t = (uint8_t)(P(0, 1) - 1), b = (uint8_t)(P(1, term_rows) - 1);
    if (b > LAST_ROW) b = LAST_ROW;
    if (t < b) { top = t; bot = b; set_row(0); set_col(0); }
    break;
  }
  case 'm': sgr(); break;
  case 'h': set_mode(1); break;
  case 'l': set_mode(0); break;
  /* 'n' (cursor position) and 'c' (identity) go unanswered: at 12 KB/s a
   * reply reaches the host after it has stopped waiting, and vim then
   * read "ESC [ 24 ; 1 R" as keys and went into replace mode (5.7). */
  case 's': save_cursor(); break;
  case 'u': restore_cursor(); break;
  default: break;
  }
}

static void escape(uint8_t c)
{
  state = S_GROUND;
  switch (c) {
  case '[': state = S_CSI; nparams = 0; priv = 0; inter = 0; digits = 0; params[0] = 0; break;
  case ']': case 'P': case '^': case '_': state = S_OSC; break;
  case '(': state = S_CHARSET; which_set = 0; break;
  case ')': state = S_CHARSET; which_set = 1; break;
  case '#': case ' ': case '%': state = S_SKIP1; break;
  case '7': save_cursor(); break;
  case '8': restore_cursor(); break;
  case 'D': linefeed(); break;
  case 'M': reverse_index(); break;
  case 'E': col = 0; wrap_pending = 0; linefeed(); break;
  case 'c': term_init(def_fg, def_bg, term_rows); break;
  default: break;                                 /* = > H Z and the rest */
  }
}

static void control(uint8_t c)
{
  switch (c) {
  case 7: break;                                  /* the bell: nothing to ring */
  case 8: if (col) col--; wrap_pending = 0; break;
  case 9: { uint8_t n = (uint8_t)((col + 8) & ~7); col = n > LAST_COL ? LAST_COL : n; wrap_pending = 0; break; }
  case 10: case 11: case 12: linefeed(); if (newline_mode) col = 0; wrap_pending = 0; break;
  case 13: col = 0; wrap_pending = 0; break;
  case 14: in_g1 = 1; break;
  case 15: in_g1 = 0; break;
  case 27: state = S_ESC; need = 0; break;
  default: break;
  }
}

static void byte(uint8_t c)
{
  switch (state) {
  case S_ESC: escape(c); return;
  case S_CSI:
    if (c >= '0' && c <= '9') { params[nparams] = (uint16_t)(params[nparams] * 10 + (c - '0')); digits = 1; return; }
    if (c == ';') { if (nparams < 15) nparams++; params[nparams] = 0; digits = 1; return; }
    if (c >= 0x3c && c <= 0x3f) { priv = c; return; }
    if (c >= 0x20 && c <= 0x2f) { inter = c; return; }
    if (c >= 0x40 && c <= 0x7e) {
      if (digits || nparams) nparams++;
      state = S_GROUND;
      csi(c);
      return;
    }
    if (c < 0x20) { control(c); return; }         /* a control inside a sequence acts; the sequence goes on */
    state = S_GROUND; return;
  case S_OSC:
    if (c == 7) state = S_GROUND;
    else if (c == 27) state = S_OSC_ESC;
    return;
  case S_OSC_ESC:
    state = (c == '\\') ? S_GROUND : S_OSC;
    return;
  case S_SKIP1:
    state = S_GROUND; return;
  case S_CHARSET:
    state = S_GROUND;
    if (which_set) g1_line = (c == '0'); else g0_line = (c == '0');
    return;
  default: break;
  }
  if (c < 0x20) { control(c); return; }
  if (c < 0x80) { if (c == 0x7f) return; need = 0; put_code(ascii_code(c)); return; }
  /* UTF-8 */
  if ((c & 0xc0) == 0x80) {
    if (!need) { put_code(0x3f); return; }
    cp = (uint16_t)((cp << 6) | (c & 0x3f));
    if (--need == 0) put_codepoint(cp);
    return;
  }
  if ((c & 0xe0) == 0xc0) { cp = (uint16_t)(c & 0x1f); need = 1; }
  else if ((c & 0xf0) == 0xe0) { cp = (uint16_t)(c & 0x0f); need = 2; }
  else if ((c & 0xf8) == 0xf0) { cp = 0; need = 3; }   /* beyond the BMP: folds to a dot */
  else put_code(0x3f);
}

/* ---- the interface ---------------------------------------------------- */

void term_init(uint8_t text_colour, uint8_t bg_colour, uint8_t rows)
{
  term_rows = rows == 50 ? 50 : 25;
  def_fg = text_colour;
  def_bg = bg_colour;
  set_attr_mode(1);                                /* VIC-III extended attributes: underline, blink */
  set_screen_bg(bg_colour);
  fg = bg = NONE; bold = rev = uline = blink = 0;
  cursor_on = 0; cursor_visible = 1;
  row = col = 0; wrap_pending = 0;
  top = 0; bot = LAST_ROW;
  autowrap = 1; insert_mode = 0; newline_mode = 0;
  g0_line = g1_line = in_g1 = 0;
  term_app_cursor = 0;
  state = S_GROUND; need = 0;
  save_cursor();
  erase_rows(0, LAST_ROW);
}

#ifdef TERM_TRACE
/* A ring of the last 64 bytes the parser was given, and how many writes
 * there were, to read back from the monitor on hardware (5.21). */
static volatile uint8_t trace[64] IN_BSS("term_trace");
static uint8_t trace_i IN_BSS("term_trace_i");
static volatile uint16_t trace_calls IN_BSS("term_trace_calls");
static volatile uint16_t trace_last_n IN_BSS("term_trace_last_n");
#endif

void term_write(const uint8_t *p, uint16_t n)
{
  const uint8_t *e = p + n;                       /* a pointer, not a countdown: 5.6 */
  uint8_t had = cursor_on;
#ifdef TERM_TRACE
  trace_calls++; trace_last_n = n;
#endif
  if (had) hide();
  while (p < e) {
    uint8_t c = *p++;
#ifdef TERM_TRACE
    trace[trace_i] = c; trace_i = (uint8_t)((trace_i + 1) & 63);
#endif
    byte(c);
  }
  if (had) show();
}
