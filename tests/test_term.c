/* The terminal against a screen made of two arrays: what each sequence
 * a real host sends must leave on the cells. Host only; `python3
 * build.py test` builds and runs it after the crypto suite. */
#include <stdio.h>
#include <string.h>
#define TERM_HOST_TEST
#include "../src/bank/term.c"

static int checks, failed;

static void feed(const char *s) { term_write((const uint8_t *)s, (uint16_t)strlen(s)); }

/* The row as ASCII, screen codes folded back through the glyph table:
 * good enough to compare letters, digits and punctuation. */
static void row_text(uint8_t r, char *out)
{
  uint8_t c;
  for (c = 0; c < TERM_COLS; c++) {
    uint8_t v = (uint8_t)(host_screen[off(r, c)] & 0x7f), ch;
    if (v == 0) ch = '@'; else if (v < 27) ch = (uint8_t)('a' + v - 1); else if (v == 0x1b) ch = '[';
    else if (v == 0x1d) ch = ']'; else if (v == 0x1e) ch = '^'; else if (v == 0x64) ch = '_';
    else if (v == 0x5d) ch = '|'; else if (v >= 0x20 && v < 0x60) ch = v; else ch = '#';
    out[c] = (char)ch;
  }
  out[TERM_COLS] = 0;
  for (c = TERM_COLS; c && out[c - 1] == ' '; c--) out[c - 1] = 0;
}

static void expect_row(const char *name, uint8_t r, const char *want)
{
  char got[TERM_COLS + 1];
  row_text(r, got);
  checks++;
  if (strcmp(got, want) == 0) { printf("  ok   %s\n", name); return; }
  failed++;
  printf("  FAIL %s\n       row %d got  '%s'\n       want '%s'\n", name, r, got, want);
}

static void expect_cursor(const char *name, uint8_t r, uint8_t c)
{
  checks++;
  if (row == r && col == c) { printf("  ok   %s\n", name); return; }
  failed++;
  printf("  FAIL %s: cursor at %d,%d, want %d,%d\n", name, row, col, r, c);
}

static void expect_cell(const char *name, uint8_t r, uint8_t c, uint8_t code, uint8_t colour)
{
  checks++;
  if (host_screen[off(r, c)] == code && host_colour[off(r, c)] == colour) { printf("  ok   %s\n", name); return; }
  failed++;
  printf("  FAIL %s: cell %d,%d is %02x/%02x, want %02x/%02x\n", name, r, c, host_screen[off(r, c)], host_colour[off(r, c)], code, colour);
}

int main(void)
{
  int i;
  char line[96];

  term_init(1, 6, 25);   /* white on the machine's blue */
  extern uint8_t host_d021, host_d031;
  feed("Hello, MEGA65 terminal.\r\n");
  expect_row("plain text lands on row 0", 0, "Hello, MEGA65 terminal.");
  expect_cursor("CR LF moves to row 1", 1, 0);

  feed("\033[5;10Hat five ten");
  expect_row("CUP places text", 4, "         at five ten");
  expect_cursor("cursor after CUP text", 4, 20);

  feed("\033[7mrev\033[0m plain");
  expect_cell("SGR 7 reverses", 4, 20, (uint8_t)('r' - 96 + 0x80), 1);
  expect_cell("SGR 0 restores", 4, 24, (uint8_t)('p' - 96), 1);
  feed("\033[31mR\033[1mB\033[44mK\033[39;49;22mN");
  expect_cell("red is palette 2", 4, 29, 'R', 2);
  expect_cell("bold red is light red", 4, 30, 'B', 10);
  expect_cell("a blue background on the blue screen draws normally", 4, 31, 'K', 10);
  expect_cell("39;49;22 back to plain", 4, 32, 'N', 1);

  feed("\033[2J\033[H");
  expect_row("ED 2 clears", 4, "");
  expect_cursor("home", 0, 0);

  for (i = 0; i < 100; i++) feed("x");
  expect_cursor("autowrap: 100 x end at row 1 col 20", 1, 20);
  expect_row("first 80 on row 0", 0, "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");
  feed("\033[2J\033[H");
  for (i = 0; i < 80; i++) feed("y");
  feed("\r\nz");
  expect_row("deferred wrap: CR LF after column 80 does not skip a row", 1, "z");

  feed("\033[2J\033[H");
  for (i = 0; i < 30; i++) { sprintf(line, "line %d\r\n", i); feed(line); }
  expect_row("scrolled: row 0 is line 6", 0, "line 6");
  expect_row("row 23 is line 29", 23, "line 29");
  expect_cursor("cursor on the last row", 24, 0);

  feed("\033[2J\033[H\033[5;10r\033[10;1Hbottom of region\r\nnext");
  expect_row("scroll region: the line above the region stays", 3, "");
  expect_row("scroll region: row 8 has what was on row 9", 8, "bottom of region");
  expect_row("scroll region: row 9 has the new line", 9, "next");
  expect_row("scroll region: row 10 untouched", 10, "");

  feed("\033[r\033[2J\033[H");
  feed("abcdefgh\033[3G\033[2@");
  expect_row("ICH inserts two blanks", 0, "ab  cdefgh");
  feed("\033[1G\033[3P");
  expect_row("DCH deletes three", 0, " cdefgh");
  feed("\033[2J\033[H1\r\n2\r\n3\r\n\033[2;1H\033[L");
  expect_row("IL inserts a blank row 1", 1, "");
  expect_row("IL pushed 2 to row 2", 2, "2");
  feed("\033[M");
  expect_row("DL pulls 2 back", 1, "2");

  feed("\033[2J\033[H");
  feed("\033(0lqk\033(Bx");
  expect_cell("DEC line drawing: top-left corner", 0, 0, 0x70, 1);
  expect_cell("DEC line drawing: horizontal", 0, 1, 0x40, 1);
  expect_cell("back to ASCII", 0, 3, (uint8_t)('x' - 96), 1);
  feed("\r\n\xe2\x94\x8c\xe2\x94\x80\xe2\x94\x90 caf\xc3\xa9");
  expect_cell("UTF-8 box top-left", 1, 0, 0x70, 1);
  expect_cell("UTF-8 box horizontal", 1, 1, 0x40, 1);
  expect_row("e acute folds to e", 1, "#@# cafe");
  feed("\r\n\xc2\xbb \xe2\x9e\x9c \xe2\x9c\x97");
  expect_row("Latin-1 punctuation and the prompt arrows fold to ASCII", 2, "> > x");

  feed("\033[?1h");
  checks++;
  if (term_app_cursor) printf("  ok   DECCKM sets application cursor keys\n"); else { failed++; printf("  FAIL DECCKM\n"); }
  feed("\033[5;7H\033]0;a window title\007after title");
  expect_row("OSC swallowed to BEL", 4, "      after title");
  feed("\033[2J\033[H\033[?25l");
  term_cursor(1);
  checks++;
  if (!cursor_on) printf("  ok   hidden cursor stays hidden\n"); else { failed++; printf("  FAIL cursor drawn while hidden\n"); }
  feed("\033[?25h");
  term_cursor(1);
  expect_cell("cursor is a reversed blank", 0, 0, 0xa0, 1);
  term_cursor(0);
  expect_cell("cursor off restores", 0, 0, 0x20, 1);

  /* underline and blink as the extended-attribute bits, and the reset */
  feed("\033[2J\033[H\033[4mU\033[24m\033[5mB\033[0mp");
  expect_cell("underline sets colour bit 7", 0, 0, 'U', (uint8_t)(1 | 0x80));
  expect_cell("blink sets colour bit 4", 0, 1, 'B', (uint8_t)(1 | 0x10));
  expect_cell("SGR 0 clears the attributes", 0, 2, (uint8_t)('p' - 96), 1);   /* lowercase p is a screen code */
  checks++;
  if (host_d031 == 0x20) printf("  ok   extended attribute mode is on\n"); else { failed++; printf("  FAIL attr mode %02x\n", host_d031); }

  /* the screen background is the client's: a host's clear in a colour leaves $D021 alone and reverses the cells (5.31) */
  feed("\033[42m\033[2J\033[H\033[31mX");
  checks++;
  if (host_d021 == 6) printf("  ok   a clear with a green bg leaves $D021 the client's blue\n"); else { failed++; printf("  FAIL $D021 %02x, want 06\n", host_d021); }
  expect_cell("red on a green bg draws reversed in green", 0, 0, (uint8_t)('X' + 0x80), 5);
  feed("\033[44mY");
  expect_cell("a blue bg on the blue screen draws the true red", 0, 1, 'Y', 2);
  term_end();
  checks++;
  if (host_d031 == 0 && host_d021 == 6) printf("  ok   term_end restores $D021 and the attributes\n"); else { failed++; printf("  FAIL end d021=%02x d031=%02x\n", host_d021, host_d031); }

  printf("%d checks, %d failed\n", checks, failed);
  return failed ? 1 : 0;
}
