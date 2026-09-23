#include <string.h>
#include "mega65/memory.h"
#include "m65_cbmdos.h"
#include "marks.h"

#define MARKS_FILE "SSHMARKS"
#define MARKS_MAGIC "SSHM1"
#define MARKS_FAR 0x11800UL               /* bank 1, above the font copy at $11000 */
#define MARKS_CAP 2048

unsigned char marks_count;
char marks_h[64], marks_p[6], marks_m[2], marks_u[32];
static unsigned int text_len;
static unsigned char marks_drive;
extern char ui_scratch[81];
#define line ui_scratch                   /* one field of the file, in the screen's scratch line */

/* Copies the line at `at` into `out` (up to cap - 1 characters) and
 * returns the offset just past its newline, or 0xffff at the end. */
static unsigned int read_line(unsigned int at, char *out, unsigned char cap)
{
  unsigned int chunk = text_len - at, i;
  unsigned char n = 0;
  if (at >= text_len) return 0xffff;
  if (chunk > sizeof line) chunk = sizeof line;
  lcopy(MARKS_FAR + at, (unsigned long)(unsigned int)line, chunk);
  for (i = 0; i < chunk && line[i] != '\n'; i++)
    if (n < cap - 1) out[n++] = line[i];
  out[n] = 0;
  return (unsigned int)(at + i + 1);                /* past the newline, or past the end */
}

/* The offset of entry i's first line, or 0xffff. */
static unsigned int entry_at(unsigned char i)
{
  unsigned int at;
  unsigned char k;
  char t[2];
  at = read_line(0, t, sizeof t);                   /* the magic line */
  for (k = 0; k < i * 4 && at != 0xffff; k++) at = read_line(at, t, sizeof t);
  return at;
}

static void count_entries(void)
{
  unsigned int at = 0;
  unsigned char lines = 0;
  char t[2];
  marks_count = 0;
  while ((at = read_line(at, t, sizeof t)) != 0xffff) lines++;
  if (lines) marks_count = (unsigned char)((lines - 1) / 4);
  if (marks_count > MARKS_MAX) marks_count = MARKS_MAX;
}

void marks_load(unsigned char drive)
{
  marks_drive = drive;
  text_len = (unsigned int)cbmdos_load(MARKS_FILE, drive, MARKS_FAR, MARKS_CAP);
  marks_count = 0;
  if (!text_len) return;
  read_line(0, line, sizeof line);
  if (strcmp(line, MARKS_MAGIC)) { text_len = 0; return; }   /* not ours, or newer: ignored, not guessed */
  count_entries();
}

unsigned char marks_get(unsigned char i, char *host, char *port_s, char *method, char *user)
{
  unsigned int at;
  if (i >= marks_count) return 0;
  at = entry_at(i);
  if (at == 0xffff) return 0;
  at = read_line(at, host, 64);
  at = read_line(at, port_s, 6);
  at = read_line(at, method, 2);
  read_line(at, user, 32);
  return 1;
}

unsigned char marks_find(const char *host, const char *port_s, const char *method, const char *user)
{
  unsigned char i;
  for (i = 0; i < marks_count; i++) {
    if (!marks_get(i, marks_h, marks_p, marks_m, marks_u)) break;
    if (!strcmp(marks_h, host) && !strcmp(marks_p, port_s) && !strcmp(marks_m, method) && !strcmp(marks_u, user)) return i;
  }
  return MARKS_NONE;
}

static unsigned char write_file(void)
{
  unsigned int i;
  cbmdos_delete(MARKS_FILE, marks_drive);           /* absent the first time; fine */
  if (cbmdos_create(MARKS_FILE, marks_drive) != CBMDOS_OK) return 0;
  for (i = 0; i < text_len; i++)
    if (cbmdos_put(lpeek(MARKS_FAR + i)) != CBMDOS_OK) { cbmdos_close(); return 0; }
  return cbmdos_close() == CBMDOS_OK;
}

/* Appends one field as a line of the far text. */
static unsigned char put_field(const char *s)
{
  unsigned int n = (unsigned int)strlen(s);
  if (text_len + n + 1 > MARKS_CAP) return 0;
  if (n) lcopy((unsigned long)(unsigned int)s, MARKS_FAR + text_len, n);
  lpoke(MARKS_FAR + text_len + n, '\n');
  text_len = (unsigned int)(text_len + n + 1);
  return 1;
}

unsigned char marks_add(const char *host, const char *port_s, const char *method, const char *user)
{
  unsigned int was = text_len;
  if (marks_count >= MARKS_MAX) return 0;
  if (!text_len) { strcpy(line, MARKS_MAGIC); if (!put_field(line)) return 0; }
  if (!put_field(host) || !put_field(port_s) || !put_field(method) || !put_field(user)) { text_len = was; return 0; }
  marks_count++;
  if (write_file()) return 1;
  text_len = was; count_entries();
  return 0;
}

unsigned char marks_remove(unsigned char i)
{
  unsigned int from, to, tail;
  if (i >= marks_count) return 0;
  from = entry_at(i);
  to = entry_at((unsigned char)(i + 1));
  if (from == 0xffff) return 0;
  if (to == 0xffff) to = text_len;
  tail = text_len - to;
  if (tail) lcopy(MARKS_FAR + to, MARKS_FAR + from, tail);   /* forwards: the destination is below the source */
  text_len = (unsigned int)(text_len - (to - from));
  marks_count--;
  return write_file();
}
