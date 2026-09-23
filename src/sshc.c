/* MEGA65 SSH client: connect, exchange keys, check the host, log in
 * with a password, open a session with a pty and a shell, and run a
 * terminal on it. REQUIREMENTS.md 4. */
#include <string.h>
#include "mega65/memory.h"
#include "meganet.h"
#include "m65_screen.h"
#include "m65_boot.h"
#include "m65_exit.h"
#include "ckit.h"
#include "ui.h"
#include "rnd.h"
#include "hosts.h"
#include "ident.h"
#include "marks.h"
#include "netutil.h"
#include "transport.h"
#include "channel.h"

#define SSHC_VERSION "0.4.4"

static char host[64];
static char port_s[6];
static char user[32];
static char pass[32];
static char auth_s[2];
#define ROW_MARKS 9
static unsigned char ip[4];
static unsigned int port;
#define line ui_scratch


static void status_cb(const char *what) { ui_status(what, 0); }
static uint8_t term_app_cursor;

static void shell_data(const uint8_t *p, uint16_t n) { ck_term_write(p, n, &term_app_cursor); }

/* ---- the keyboard ------------------------------------------------------
 * What the host gets for each key. The queue at $D610 already delivers
 * ASCII for the typewriter keys and a control code for CTRL+letter; the
 * codes it shares between a control key and a cursor key (^S and HOME,
 * ^Q and DOWN, ^T and DEL, ^] and RIGHT) are told apart by the CTRL bit
 * in $D611. HELP leaves the session; nothing on the host uses it. */
static uint8_t seq[6];

static uint16_t cursor_key(uint8_t final)
{
  seq[0] = 27; seq[1] = term_app_cursor ? 'O' : '['; seq[2] = final;
  return 3;
}

static uint16_t tilde_key(uint8_t n)
{
  uint16_t i = 2;
  seq[0] = 27; seq[1] = '[';
  if (n >= 10) seq[i++] = (uint8_t)('0' + n / 10);
  seq[i++] = (uint8_t)('0' + n % 10);
  seq[i++] = '~';
  return i;
}

static uint16_t map_key(uint8_t k, uint8_t mods)
{
  static const uint8_t fkey[12] = { 0, 0, 0, 0, 15, 17, 18, 19, 20, 21, 23, 24 };
  if (mods & MOD_CTRL) {
    if (k >= 'a' && k <= 'z') { seq[0] = (uint8_t)(k & 0x1f); return 1; }
    if (k >= '@' && k <= '_') { seq[0] = (uint8_t)(k & 0x1f); return 1; }
    if (k == ' ') { seq[0] = 0; return 1; }
    if (k < 0x20) { seq[0] = k; return 1; }       /* the queue made the control code already */
  }
  switch (k) {
  case KEY_RETURN: seq[0] = '\r'; return 1;
  case KEY_DEL: seq[0] = 127; return 1;
  case KEY_UP: return cursor_key('A');
  case KEY_DOWN: return cursor_key('B');
  case KEY_RIGHT: return cursor_key('C');
  case KEY_LEFT: return cursor_key('D');
  case KEY_HOME: return cursor_key('H');
  case KEY_CLR: return cursor_key('F');           /* SHIFT+HOME as End */
  case KEY_INS: return tilde_key(2);
  default: break;
  }
  if (k >= KEY_F1 && k < KEY_F1 + 12) {
    uint8_t n = (uint8_t)(k - KEY_F1);
    if (n < 4) { seq[0] = 27; seq[1] = 'O'; seq[2] = (uint8_t)('P' + n); return 3; }   /* F1-F4 as PF1-PF4 */
    return tilde_key(fkey[n]);
  }
  if (k < 0x80) { seq[0] = k; return 1; }         /* TAB, ESC, RUN/STOP as ^C, and the printable keys */
  return 0;
}

static const char hexd[] = "0123456789abcdef";

/* The fingerprint shown is SHA-256 of the raw 32-byte public key, in
 * hex. OpenSSH shows SHA-256 of the whole key blob in base64; the two
 * differ, so the line says which this is. */
static unsigned char ask_hostkey(const uint8_t key[32], unsigned char changed)
{
  static uint8_t fp[32];
  unsigned i, k;
  ck_sha256_init(2); ck_sha256_update(2, key, 32); ck_sha256_final(2, fp);
  ui_clear_rows(1, UI_ROW_LAST_BODY);
  ui_line(2, changed ? "WARNING: this host's key has CHANGED since it was last seen." : "This host is not in KNOWNHOSTS yet.", 0);
  ui_line(3, "Its Ed25519 key, as SHA-256 of the raw key bytes, is:", 0);
  strcpy(line, "  ");
  for (i = 0; i < 32; i++) { line[2 + 3 * i] = hexd[fp[i] >> 4]; line[3 + 3 * i] = hexd[fp[i] & 15]; line[4 + 3 * i] = ' '; }
  line[2 + 3 * 16] = 0; ui_line(5, line, 0);
  strcpy(line, "  ");
  for (i = 16; i < 32; i++) { k = i - 16; line[2 + 3 * k] = hexd[fp[i] >> 4]; line[3 + 3 * k] = hexd[fp[i] & 15]; line[4 + 3 * k] = ' '; }
  line[2 + 3 * 16] = 0; ui_line(6, line, 0);
  ui_line(8, changed ? "A changed key can mean a new server, or an attacker between you and it."
                     : "Compare it with what the server's owner published, if you can.", 0);
  ui_status(changed ? "Y to connect anyway (the key is NOT saved), anything else to refuse" : "Y to trust and remember this host, anything else to refuse", 0);
  ui_flush_keys();
  k = ui_wait_key();
  rnd_stir((uint8_t)k);
  ui_clear_rows(1, UI_ROW_LAST_BODY);
  return (k == 'y' || k == 'Y');
}

/* 1 to connect, 0 to start the prompts again, 2 to leave: RUN/STOP at the
 * Host prompt leaves whatever the field holds (it remembers the last host,
 * so "leave only when empty" kept the user at the prompt). */
/* The identity screen (F1 at the Host prompt): the public key as OpenSSH
 * writes it, its fingerprint, and the way to make a new one (5.22). */
static void show_identity(void)
{
  char *text = ui_scratch;
  ui_clear_rows(1, UI_ROW_LAST_BODY);
  if (ident_present) {
    ident_public_b64(text);
    ui_line(2, "Your identity, an Ed25519 key, as OpenSSH writes it, on two lines:", 0);
    ui_line(4, "ssh-ed25519", 0);
    ui_line(5, text, 0);
    ident_fingerprint_b64(text);
    ui_line(7, "SHA256:", text);
    ui_line(9, "Put that line in ~/.ssh/authorized_keys on a server to log in with it.", 0);
    ui_status("R replaces it (the old identity is gone for good), any other key goes back", 0);
  } else {
    ui_line(2, "There is no identity on the disk yet.", 0);
    ui_status("G generates one (about ten seconds), any other key goes back", 0);
  }
}

/* Makes a new identity after the user asked for one; 1 if it is on the disk. */
static unsigned char generate_identity(void)
{
  ui_status("generating the identity, about ten seconds...", 0);
  if (!ident_generate()) { ui_status("the identity could not be written to the disk", 0); return 0; }
  return 1;
}

static unsigned char identity_screen(void)
{
  unsigned char k;
  for (;;) {
    show_identity();
    ui_flush_keys();
    k = ui_wait_key();
    rnd_stir((uint8_t)k);
    if (ident_present ? (k == 'r' || k == 'R') : (k == 'g' || k == 'G')) { generate_identity(); continue; }
    ui_clear_rows(1, UI_ROW_LAST_BODY);
    return ident_present;
  }
}

/* The bookmarks under the prompts: number, host and port, user, method (5.27). */
#define mark_text ui_scratch
static unsigned char mark_n;
static void __attribute__((noinline)) mark_cat(const char *q, unsigned char lim)
{
  while (*q && mark_n < lim) mark_text[mark_n++] = *q++;
}

static void draw_marks(void)
{
  unsigned char i;
  if (!marks_count) return;
  ui_line(ROW_MARKS, "Bookmarks: a number at the Host prompt opens one, D and the number deletes it", 0);
  for (i = 0; i < marks_count && ROW_MARKS + 1 + i < UI_ROW_STATUS - 1; i++) {
    if (!marks_get(i, marks_h, marks_p, marks_m, marks_u)) break;
    mark_text[0] = ' '; mark_text[1] = (char)('1' + i); mark_text[2] = '.'; mark_text[3] = ' '; mark_n = 4;
    mark_cat(marks_h, 44);
    if (marks_p[0] != '2' || marks_p[1] != '2' || marks_p[2]) { mark_cat(":", 45); mark_cat(marks_p, 50); }
    mark_cat("  ", 52); mark_cat(marks_u, 74); mark_cat("  ", 76); mark_cat(marks_m, 77);
    mark_text[mark_n] = 0;
    ui_line((unsigned char)(ROW_MARKS + 1 + i), mark_text, 0);
  }
}

/* MEGA+M in a session: this host, port, method and user in, or out if
 * they are already there. The terminal owns the screen, so the answer is
 * the border: one flash for saved, two for removed, three for no room. */
static void __attribute__((noinline)) six_frames(void)
{
  unsigned char last = PEEK(0xd7fa), n = 0;
  while (n < 6) if (PEEK(0xd7fa) != last) { last = PEEK(0xd7fa); n++; }
}

static void flash_border(unsigned char times)
{
  unsigned char was = PEEK(0xd020);
  for (; times; times--) {
    POKE(0xd020, (was & 0x0f) == 1 ? 0 : 1); six_frames();
    POKE(0xd020, was); six_frames();
  }
}

static void toggle_mark(void)
{
  unsigned char at = marks_find(host, port_s, auth_s, user);
  if (at != MARKS_NONE) flash_border(marks_remove(at) ? 2 : 3);
  else if (marks_count >= MARKS_MAX) flash_border(3);
  else flash_border(marks_add(host, port_s, auth_s, user) ? 1 : 3);
}

static unsigned char session_setup(void)
{
  unsigned char i;
  const char *err;
  unsigned int v = 0;
  ui_clear_rows(1, UI_ROW_LAST_BODY);
  ui_line(0, "MEGA65 SSH Client", 0);
  ui_line(UI_ROW_KEYS, "RETURN accepts a line   RUN/STOP goes back   F1 identity   HELP ends a session", 0);
  ui_status("curve25519, ed25519, chacha20-poly1305; hosts remembered in KNOWNHOSTS", 0);
  draw_marks();
  for (;;) {
    unsigned char n = 0, del = 0, digits = 0;
    i = ui_read_line(3, "Host: ", host, sizeof host - 1, 0);
    if (!i) return 2;
    if (i == 2) { identity_screen(); ui_line(0, "MEGA65 SSH Client", 0); draw_marks(); continue; }
    if (!host[0]) continue;
    /* A number picks a bookmark; D and a number deletes one (5.27). */
    i = 0;
    if (host[0] == 'd' || host[0] == 'D') { del = 1; i = 1; }
    while (host[i] >= '0' && host[i] <= '9') { n = (unsigned char)(n * 10 + (host[i] - '0')); i++; digits++; }
    if (!digits || host[i]) break;                  /* a host name */
    if (n < 1 || n > marks_count) { ui_status("no such bookmark", 0); host[0] = 0; continue; }
    if (del) {
      ui_status(marks_remove((unsigned char)(n - 1)) ? "bookmark removed" : "could not write SSHMARKS", 0);
      ui_clear_rows(ROW_MARKS, UI_ROW_STATUS - 1); draw_marks();
      host[0] = 0; continue;
    }
    marks_get((unsigned char)(n - 1), host, port_s, auth_s, user);
    ui_line(3, "Host: ", host); ui_line(4, "Port: ", port_s); ui_line(5, "Auth (p = password, i = identity): ", auth_s); ui_line(6, "User: ", user);
    goto picked;
  }
  if (!ui_read_line(4, "Port: ", port_s, sizeof port_s - 1, 0)) return 0;
  /* The method, remembered on the disk as the next default (5.22). */
  for (;;) {
    auth_s[0] = ident_auth; auth_s[1] = 0;
    if (!ui_read_line(5, "Auth (p = password, i = identity): ", auth_s, 1, 0)) return 0;
    if (auth_s[0] == 'P') auth_s[0] = 'p';
    if (auth_s[0] == 'I') auth_s[0] = 'i';
    if (auth_s[0] == 'p' || auth_s[0] == 'i') break;
  }
  if (auth_s[0] != ident_auth) ident_set_auth(auth_s[0]);
  if (!ui_read_line(6, "User: ", user, sizeof user - 1, 0) || !user[0]) return 0;
picked:
  for (i = 0; port_s[i] >= '0' && port_s[i] <= '9'; i++) v = v * 10 + (unsigned int)(port_s[i] - '0');
  port = v ? v : 22;
  pass[0] = 0;
  if (auth_s[0] == 'p') {
    if (!ui_read_line(7, "Password: ", pass, sizeof pass - 1, 1)) return 0;
  } else if (!ident_present) {
    if (!identity_screen()) return 0;
    ui_line(0, "MEGA65 SSH Client", 0);
  }
  rnd_stir((uint8_t)PEEK(0xd012));
  ui_status("resolving host...", 0);
  if (!net_resolve(host, ip, &err)) { ui_status("resolve: ", err); return 0; }
  return 1;
}

int main(void)
{
  const char *err;
  unsigned char k;

  mega65_io_enable();
  m65_own_vectors();                              /* first: a stray ethernet event before this enters the KERNAL's handler (5.8) */
  m65_screen_init();
  scr_rows = m65_screen_rows();                   /* 25 or 50, as the machine was (5.23) */
  ch_pty_rows = scr_rows;
  ui_line(0, "MEGA65 SSH Client - version " SSHC_VERSION, 0);
  ui_status("starting the network...", 0);
  if (!net_up(&err)) { ui_status("network: ", err); for (;;) ; }
  ui_status("loading the crypto bank...", 0);
  if (!ck_boot(&err)) { ui_status("crypto: ", err); for (;;) ; }
  ui_status("gathering randomness...", 0);
  rnd_init();
  hosts_load(boot_drive);
  ident_load(boot_drive);
  marks_load(boot_drive);
  strcpy(port_s, "22");
  ssh_status = status_cb;
  ssh_ask_hostkey = ask_hostkey;

  for (;;) {
    k = session_setup();
    if (k != 1) { if (k == 2) break; continue; }
    ui_clear_rows(1, UI_ROW_LAST_BODY);
    ui_line(0, "MEGA65 SSH Client", 0);
    if (!ssh_connect(ip, port, host)) {
      ui_status("connect: ", ssh_error_text());
      ui_line(UI_ROW_KEYS, "any key to try again   RUN/STOP to quit", 0);
      if (ui_wait_key() == KEY_STOP) break;
      continue;
    }
    if (!(auth_s[0] == 'i' ? ssh_login_key(user, ident_seed, ident_pk) : ssh_login(user, pass))) {
      ui_status("login: ", ssh_error_text());
      ssh_disconnect();
      ui_line(UI_ROW_KEYS, "any key to try again   RUN/STOP to quit", 0);
      if (ui_wait_key() == KEY_STOP) break;
      continue;
    }
    memset(pass, 0, sizeof pass);
#ifndef NO_SHELL
    ch_on_data = shell_data;
    ck_term_init(m65_screen_text_colour(), m65_screen_bg_colour(), scr_rows);   /* the shell has the whole screen from here */
    ssh_status = 0;
    if (!ch_open_shell()) {
      ssh_status = status_cb;
      ui_status("session: ", ssh_error_text());
      ssh_disconnect();
      ui_line(UI_ROW_KEYS, "any key to try again   RUN/STOP to quit", 0);
      if (ui_wait_key() == KEY_STOP) break;
      continue;
    }
    ck_term_cursor(1);
    {
      unsigned char loc_fg = m65_screen_text_colour(), loc_bg = m65_screen_bg_colour();
      for (;;) {
        unsigned char mods;
        uint16_t n;
        if (!ch_poll()) break;
        k = ui_key_mods(&mods);
        if (!k) continue;
        rnd_stir(k);
        if (k == KEY_HELP) { ch_close(); break; }
        /* MEGA held plus F or B cycles the local colours, and is not sent:
         * the terminal's own default text colour, and the screen background
         * with the border, the way the gopher and FTP clients do (5.20). */
        if (mods & MOD_MEGA) {
          if (k >= 0xc1 && k <= 0xda) k = (unsigned char)(k & 0x7f);   /* MEGA+letter arrives as the capital with bit 7 set (5.29) */
          if (k == 'm' || k == 'M') { toggle_mark(); continue; }
          if (k == 'f' || k == 'F' || k == 'b' || k == 'B') {
            ck_term_cursor(0);
            if (k == 'f' || k == 'F') {
              loc_fg = (unsigned char)((loc_fg + 1) & 0x0f);
              if (loc_fg == loc_bg) loc_fg = (unsigned char)((loc_fg + 1) & 0x0f);
            } else {
              { static unsigned char pressed;     /* the first press: black, unless it is already; then the rotation (the four clients agree) */
                if (!pressed && loc_bg != 0) loc_bg = 0;
                else loc_bg = (unsigned char)((loc_bg + 1) & 0x0f);
                pressed = 1; }
              if (loc_bg == loc_fg) loc_bg = (unsigned char)((loc_bg + 1) & 0x0f);
            }
            ck_term_recolour(loc_fg, loc_bg);
            ck_term_cursor(1);
            continue;
          }
        }
        n = map_key(k, mods);
        if (n && !ch_send(seq, n)) break;
      }
    }
    ck_term_cursor(0);
    ck_term_end();                                  /* $D021 and the attributes back to the client's */
    ssh_status = status_cb;
    if (ch_closed && ssh_error == SSH_OK) {
      char num[8];
      strcpy(line, "the session ended");
      if (ch_exit_status >= 0) { strcat(line, ", exit status "); ui_put_ulong(num, (unsigned long)ch_exit_status); strcat(line, num); }
      ui_status(line, 0);
    } else ui_status("connection: ", ssh_error_text());
    ssh_disconnect();
#else
    (void)k;
    ui_status("logged in (shell compiled out for a boot test)", 0);
    ssh_disconnect();
#endif
    ui_line(UI_ROW_KEYS, "any key for the host screen   RUN/STOP to quit", 0);
    if (ui_wait_key() == KEY_STOP) break;
  }
  m65_exit_to_basic();
  return 0;
}
