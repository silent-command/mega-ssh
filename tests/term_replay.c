/* Replays a captured byte stream through the terminal on the host and
 * prints the screen: what a program's output would look like on the
 * machine, without the machine. The capture is what tools/ssh_test_server.py
 * or scratch capture scripts write: raw bytes, optionally split by
 * "\n##<anything>##" markers, each run fed as one term_write.
 *
 *   term_replay <capture> [rows]    rows: 25 (default) or 50
 *
 * Prints each row as text (graphics as '#', reverse cells in brackets
 * are not shown), then a colour map: one hex digit per cell, the
 * colour nibble, so the mapping of 256-colour and truecolor SGRs can be
 * judged. REQUIREMENTS.md 5.22. */
#define TERM_HOST_TEST
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "term.c"

static char text_of(uint8_t code)
{
  uint8_t v = (uint8_t)(code & 0x7f);
  if (v >= 1 && v <= 26) return (char)('a' + v - 1);
  if (v >= 0x41 && v <= 0x5a) return (char)v;
  if (v >= 0x20 && v <= 0x3f) return (char)v;
  if (v == 0) return '@';
  if (v == 0x1b) return '[';
  if (v == 0x1d) return ']';
  if (v == 0x1e) return '^';
  if (v == 0x1c) return '\\';
  if (v == 0x1f) return '_';
  return '#';
}

int main(int argc, char **argv)
{
  static uint8_t buf[1 << 20];
  FILE *f;
  size_t n, i, start;
  int r, c, writes = 0;
  if (argc < 2) { fprintf(stderr, "usage: term_replay <capture> [rows]\n"); return 2; }
  f = fopen(argv[1], "rb");
  if (!f) { perror(argv[1]); return 2; }
  n = fread(buf, 1, sizeof buf, f);
  fclose(f);
  term_init(1, 6, (uint8_t)(argc > 2 ? atoi(argv[2]) : 25));
  /* runs between "\n##...##" markers; a file without markers is one run */
  start = 0;
  for (i = 0; i + 2 < n; i++) {
    if (buf[i] == '\n' && buf[i + 1] == '#' && buf[i + 2] == '#') {
      size_t j = i + 3;
      while (j + 1 < n && !(buf[j] == '#' && buf[j + 1] == '#')) j++;
      if (i > start) { term_write(buf + start, (uint16_t)(i - start)); writes++; }
      start = j + 2; i = start - 1;
    }
  }
  if (n > start) { term_write(buf + start, (uint16_t)(n - start)); writes++; }
  printf("%d writes, %zu bytes; cursor %d,%d; $D021 %d\n", writes, n, row, col, host_d021);
  for (r = 0; r < term_rows; r++) {
    printf("%2d|", r);
    for (c = 0; c < TERM_COLS; c++) putchar(text_of(host_screen[off((uint8_t)r, (uint8_t)c)]));
    printf("|\n");
  }
  printf("colours (nibble per cell):\n");
  for (r = 0; r < term_rows; r++) {
    printf("%2d|", r);
    for (c = 0; c < TERM_COLS; c++) putchar("0123456789abcdef"[host_colour[off((uint8_t)r, (uint8_t)c)] & 15]);
    printf("|\n");
  }
  return 0;
}
