/* Step 1: connect to an SSH server, exchange the version strings, and
 * read the length of the server's first binary packet (its KEXINIT).
 * Proves the plumbing before any cryptography. REQUIREMENTS.md 5.1. */
#include <string.h>
#include "mega65/memory.h"
#include "meganet.h"
#include "m65_screen.h"
#include "m65_boot.h"
#include "ui.h"

#define SOCK 0
static const unsigned char server[4] = { 192, 168, 1, 232 };
#define PORT 2222

static unsigned char buf[512];
static char line[81];
static unsigned char row;
static unsigned int frames;
static unsigned char last;

static void tick(void) { unsigned char f = PEEK(0xd7fa); if (f != last) { last = f; frames++; } }

static unsigned char wait_state(unsigned char want, unsigned int limit)
{
  unsigned char st, fl;
  frames = 0; last = PEEK(0xd7fa);
  for (;;) {
    meganet_poll(); tick();
    st = meganet_tcp_state_s(SOCK, &fl, 0);
    if (st == want) return 1;
    if (st == MEGANET_TCP_CLOSED) return 0;
    if (frames > limit) return 0;
  }
}

/* Reads until a byte satisfies `stop` or the buffer fills. */
static unsigned int read_upto(unsigned int max, unsigned int limit, unsigned char stop_at_lf)
{
  unsigned int n = 0, got;
  frames = 0; last = PEEK(0xd7fa);
  while (n < max) {
    meganet_poll(); tick();
    got = meganet_tcp_recv_s(SOCK, buf + n, 1);
    if (got) { n++; if (stop_at_lf && buf[n - 1] == '\n') break; frames = 0; }
    if (frames > limit) break;
  }
  return n;
}

int main(void)
{
  const char *err;
  unsigned int n, i, len;
  char num[12];
  mega65_io_enable();
  m65_screen_init();
  ui_line(0, "ssh spike 1: version strings and the first packet", 0);
  row = 2;
  if (!m65_boot_load(&err)) { ui_line(row, "stack: ", err); for (;;) ; }
  meganet_call(MEGANET_INIT, 0, 0, 0, 0);
  meganet_dhcp_start();
  frames = 0; last = PEEK(0xd7fa);
  while (meganet_dhcp_state() != MEGANET_DHCP_BOUND) { meganet_poll(); tick(); if (frames > 1500) { ui_line(row, "no dhcp", 0); for (;;) ; } }
  ui_line(row++, "online", 0);

  meganet_tcp_abort_s(SOCK);
  meganet_tcp_connect_s(SOCK, server, PORT);
  if (!wait_state(MEGANET_TCP_ESTABLISHED, 750)) { ui_line(row, "connect failed", 0); for (;;) meganet_poll(); }
  ui_line(row++, "connected to port 2222", 0);

  /* The server speaks first: "SSH-2.0-name comment\r\n", possibly after
   * other lines that do not start with SSH- (RFC 4253 4.2). */
  for (;;) {
    n = read_upto(255, 500, 1);
    if (!n) { ui_line(row, "no version string", 0); for (;;) meganet_poll(); }
    while (n && (buf[n - 1] == '\n' || buf[n - 1] == '\r')) n--;
    buf[n] = 0;
    if (n >= 4 && !memcmp(buf, "SSH-", 4)) break;
    strcpy(line, "line: "); strncat(line, (char *)buf, 70); ui_line(row++, line, 0);
  }
  strcpy(line, "server: "); strncat(line, (char *)buf, 70); ui_line(row++, line, 0);

  {
    static const char ours[] = "SSH-2.0-mega65ssh_0.1\r\n";
    meganet_tcp_send_s(SOCK, ours, sizeof ours - 1);
    ui_line(row++, "sent: SSH-2.0-mega65ssh_0.1", 0);
  }

  /* The binary packet protocol: uint32 packet_length, then the rest.
   * Read the first packet whole; it is KEXINIT, a kilobyte or two. */
  n = read_upto(4, 500, 0);
  if (n < 4) { ui_line(row, "no packet", 0); for (;;) meganet_poll(); }
  len = ((unsigned int)buf[2] << 8) | buf[3];
  strcpy(line, "first packet: length "); ui_put_ulong(num, len); strcat(line, num);
  strcat(line, " (high bytes "); ui_put_ulong(num, buf[0]); strcat(line, num); strcat(line, " ");
  ui_put_ulong(num, buf[1]); strcat(line, num); strcat(line, ")");
  ui_line(row++, line, 0);
  n = read_upto(len < 500 ? len : 500, 500, 0);
  strcpy(line, "read "); ui_put_ulong(num, n); strcat(line, num); strcat(line, " bytes of it; padding ");
  ui_put_ulong(num, buf[0]); strcat(line, num); strcat(line, ", type ");
  ui_put_ulong(num, buf[1]); strcat(line, num); strcat(line, " (20 = KEXINIT)");
  ui_line(row++, line, 0);
  /* the first name-list after the 16-byte cookie: kex algorithms */
  if (n > 22) {
    unsigned int nl = ((unsigned int)buf[20] << 8) | buf[21];
    strcpy(line, "kex: ");
    for (i = 0; i < nl && i < 70 && 22 + i < n; i++) line[5 + i] = (char)buf[22 + i];
    line[5 + i] = 0;
    ui_line(row++, line, 0);
  }
  ui_line(row + 1, "done", 0);
  for (;;) meganet_poll();
}
