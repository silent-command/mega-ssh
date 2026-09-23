#include <string.h>
#include "mega65/memory.h"
#include "m65_cbmdos.h"
#include "hosts.h"

#define HOSTS_FILE "KNOWNHOSTS"
#define HOSTS_MAX 2000

/* The file's text lives in bank 5 above mega-net's socket buffers
 * (which end at $5E8FF, its README's memory table), not in this bank:
 * two kilobytes the terminal needs more than a file read once. The
 * loader takes a 28-bit address, so it goes there straight from disk. */
#define HOSTS_FAR 0x5E900UL

static unsigned int text_len;
static unsigned char hosts_drive;
static char line[140];                /* one line of the file (at most 135), or the line being added */
static char scratch[96];              /* the prefix while finding, the hex while checking */

static const char hexd[] = "0123456789abcdef";

static void key_hex(char *out, const uint8_t key[32])
{
  unsigned i;
  for (i = 0; i < 32; i++) { out[2 * i] = hexd[key[i] >> 4]; out[2 * i + 1] = hexd[key[i] & 15]; }
  out[64] = 0;
}

static void make_prefix(char *out, const char *host, unsigned int port)
{
  char num[8];
  unsigned char n = 0;
  unsigned int v = port;
  strcpy(out, host); strcat(out, ":");
  do { num[n++] = (char)('0' + v % 10); v /= 10; } while (v);
  while (n) { char c[2]; c[0] = num[--n]; c[1] = 0; strcat(out, c); }
  strcat(out, " ");
}

void hosts_load(unsigned char drive)
{
  hosts_drive = drive;
  text_len = (unsigned int)cbmdos_load(HOSTS_FILE, drive, HOSTS_FAR, HOSTS_MAX);
}

/* Finds the line for host:port; returns the offset of its key text in
 * the far buffer, or 0xFFFF. */
static unsigned int find(const char *host, unsigned int port)
{
  char *prefix = scratch;
  unsigned int i = 0, pl, chunk, l;
  make_prefix(prefix, host, port);
  pl = (unsigned int)strlen(prefix);
  while (i < text_len) {
    chunk = text_len - i;
    if (chunk > sizeof line) chunk = sizeof line;
    lcopy(HOSTS_FAR + i, (unsigned long)(unsigned int)line, chunk);
    for (l = 0; l < chunk && line[l] != '\n'; l++) ;
    if (l > pl && memcmp(line, prefix, pl) == 0) return i + pl;
    i += l + 1;
  }
  return 0xffff;
}

unsigned char hosts_check(const char *host, unsigned int port, const uint8_t key[32])
{
  char *hex = scratch;
  unsigned int at = find(host, port);
  if (at == 0xffff) return HOSTS_UNKNOWN;
  key_hex(hex, key);
  lcopy(HOSTS_FAR + at, (unsigned long)(unsigned int)line, 64);
  return memcmp(line, hex, 64) == 0 ? HOSTS_KNOWN : HOSTS_CHANGED;
}

unsigned char hosts_add(const char *host, unsigned int port, const uint8_t key[32])
{
  unsigned int n, i;
  make_prefix(line, host, port);
  key_hex(line + strlen(line), key);
  strcat(line, "\n");
  n = (unsigned int)strlen(line);
  if (text_len + n > HOSTS_MAX) return 0;
  lcopy((unsigned long)(unsigned int)line, HOSTS_FAR + text_len, n);
  text_len += n;
  cbmdos_delete(HOSTS_FILE, hosts_drive);          /* absent the first time; fine */
  if (cbmdos_create(HOSTS_FILE, hosts_drive) != CBMDOS_OK) return 0;
  for (i = 0; i < text_len; i++)
    if (cbmdos_put(lpeek(HOSTS_FAR + i)) != CBMDOS_OK) { cbmdos_close(); return 0; }
  return cbmdos_close() == CBMDOS_OK;
}
