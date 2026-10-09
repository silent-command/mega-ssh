#include <string.h>
#include "mega65/memory.h"
#include "meganet.h"
#include "ckit.h"
#include "wire.h"
#include "rnd.h"
#include "hosts.h"
#include "transport.h"

unsigned char ssh_error;
char ssh_reason[80];
uint8_t ssh_rx[SSH_RX_MAX];
uint16_t ssh_rx_len;
void (*ssh_status)(const char *what);
unsigned char (*ssh_ask_hostkey)(const uint8_t key[32], unsigned char changed);

#define VERSION_STRING "SSH-2.0-mega65ssh_0.4.3"
#define KEX_NAMES "curve25519-sha256,curve25519-sha256@libssh.org,kex-strict-c-v00@openssh.com"
#define HOSTKEY_NAME "ssh-ed25519"
#define CIPHER_NAME "chacha20-poly1305@openssh.com"

static uint8_t tx[SSH_TX_MAX + 5 + 16 + 16];      /* header, payload, padding, tag */
static uint32_t seq_out, seq_in;
static unsigned char encrypted, strict;
static uint8_t session_id[32], H[32];
static uint8_t ks[64];                /* one keystream block, for sending and receiving in turn (5.27) */
static uint8_t priv[32], q_c[32];
static uint8_t kmp[40];                          /* the shared secret as an mpint */
static uint16_t kmp_len;
/* The server's version line, the KEXINIT we send and the authentication
 * requests are built in ssh_rx, which is idle until the reply arrives:
 * the client's memory was full (5.22). */
#define v_s ((char *)ssh_rx)
static char host_name[64];
static unsigned int host_port;
static unsigned int frames;
static unsigned char last_frame;

/* ---- pacing ------------------------------------------------------------ */

static void tick(void)
{
  unsigned char f = PEEK(0xd7fa);
  if (f != last_frame) { last_frame = f; frames++; }
}

void ssh_poll(void) { meganet_poll(); tick(); }

static void status(const char *s) { if (ssh_status) ssh_status(s); }

static unsigned char alive(void)
{
  uint8_t fl;
  uint8_t st = meganet_tcp_state_s(SSH_SOCK, &fl, 0);
  if (st != MEGANET_TCP_ESTABLISHED) return 0;
  return (fl & (MEGANET_TCP_F_RESET | MEGANET_TCP_F_EOF)) ? 0 : 1;
}

/* Exactly n bytes, or an error; each byte resets the inactivity clock. */
static unsigned char rd_exact(uint8_t *p, uint16_t n)
{
  uint16_t got;
  frames = 0;
  while (n) {
    ssh_poll();
    got = meganet_tcp_recv_s(SSH_SOCK, p, n);
    if (got) { p += got; n = (uint16_t)(n - got); frames = 0; continue; }
    if (!alive()) { ssh_error = SSH_E_CLOSED; return 0; }
    if (frames > SSH_TIMEOUT_FRAMES) { ssh_error = SSH_E_TIMEOUT; return 0; }
  }
  return 1;
}

static unsigned char wr_all(const uint8_t *p, uint16_t n)
{
  uint16_t k;
  frames = 0;
  while (n) {
    k = meganet_tcp_send_s(SSH_SOCK, p, n);
    p += k; n = (uint16_t)(n - k);
    ssh_poll();
    if (k) frames = 0;
    if (!alive()) { ssh_error = SSH_E_CLOSED; return 0; }
    if (frames > SSH_TIMEOUT_FRAMES) { ssh_error = SSH_E_TIMEOUT; return 0; }
  }
  return 1;
}

static void nonce_of(uint8_t n[8], uint32_t seq)
{
  n[0] = n[1] = n[2] = n[3] = 0;
  n[4] = (uint8_t)(seq >> 24); n[5] = (uint8_t)(seq >> 16); n[6] = (uint8_t)(seq >> 8); n[7] = (uint8_t)seq;
}

/* ---- the packet layer -------------------------------------------------- */

/* Reads one packet; the payload lands in ssh_rx with its type byte first. */
static unsigned char recv_raw(void)
{
  static uint8_t hdr[4], tag[16], nonce[8], want[16];
  uint32_t len;
  uint8_t padlen;
  if (!rd_exact(hdr, 4)) return 0;
  if (encrypted) {
    nonce_of(nonce, seq_in);
    ck_chacha_block(3, nonce, 0, ks);               /* the length key */
    len = ((uint32_t)(hdr[0] ^ ks[0]) << 24) | ((uint32_t)(hdr[1] ^ ks[1]) << 16) |
          ((uint32_t)(hdr[2] ^ ks[2]) << 8) | (uint32_t)(hdr[3] ^ ks[3]);
    if (len < 8 || len > SSH_RX_MAX) { ssh_error = SSH_E_TOOBIG; return 0; }
    if (!rd_exact(ssh_rx, (uint16_t)len)) return 0;
    if (!rd_exact(tag, 16)) return 0;
    ck_chacha_block(2, nonce, 0, ks);               /* the Poly1305 key */
    ck_poly_init(0, ks);
    ck_poly_update(0, hdr, 4);
    ck_poly_update(0, ssh_rx, (uint16_t)len);
    ck_poly_final(0, want);
    if (!ck_equal(tag, want, 16)) { ssh_error = SSH_E_MAC; return 0; }
    ck_chacha_xor(2, nonce, 1, ssh_rx, (uint16_t)len);
    padlen = ssh_rx[0];
    if ((uint32_t)padlen + 1 > len) { ssh_error = SSH_E_PROTOCOL; return 0; }
    ssh_rx_len = (uint16_t)(len - 1 - padlen);
    memmove(ssh_rx, ssh_rx + 1, ssh_rx_len);
  } else {
    len = ((uint32_t)hdr[0] << 24) | ((uint32_t)hdr[1] << 16) | ((uint32_t)hdr[2] << 8) | hdr[3];
    if (len < 5 || len > SSH_RX_MAX) { ssh_error = SSH_E_TOOBIG; return 0; }
    if (!rd_exact(&padlen, 1)) return 0;
    if ((uint32_t)padlen + 1 > len) { ssh_error = SSH_E_PROTOCOL; return 0; }
    ssh_rx_len = (uint16_t)(len - 1 - padlen);
    if (!rd_exact(ssh_rx, ssh_rx_len)) return 0;
    if (!rd_exact(tag, 0)) return 0;
    while (padlen) {                               /* drop the padding */
      uint8_t take = padlen < 16 ? padlen : 16;
      if (!rd_exact(tag, take)) return 0;
      padlen = (uint8_t)(padlen - take);
    }
  }
  seq_in++;
  return ssh_rx_len > 0;
}

unsigned char ssh_send(const uint8_t *payload, uint16_t n)
{
  static uint8_t nonce[8];
  uint8_t pad;
  uint32_t len;
  if (n > SSH_TX_MAX) { ssh_error = SSH_E_TOOBIG; return 0; }
  /* padding: at least four bytes, to a multiple of eight; the length
   * field counts toward the alignment when it is not encrypted */
  pad = (uint8_t)(8 - ((encrypted ? 1 : 5) + n) % 8);
  if (pad < 4) pad = (uint8_t)(pad + 8);
  len = (uint32_t)1 + n + pad;
  tx[0] = (uint8_t)(len >> 24); tx[1] = (uint8_t)(len >> 16); tx[2] = (uint8_t)(len >> 8); tx[3] = (uint8_t)len;
  tx[4] = pad;
  memcpy(tx + 5, payload, n);
  rnd_fill(tx + 5 + n, pad);
  if (!encrypted) {
    seq_out++;
    return wr_all(tx, (uint16_t)(4 + len));
  }
  nonce_of(nonce, seq_out);
  ck_chacha_block(1, nonce, 0, ks);
  tx[0] ^= ks[0]; tx[1] ^= ks[1]; tx[2] ^= ks[2]; tx[3] ^= ks[3];
  ck_chacha_xor(0, nonce, 1, tx + 4, (uint16_t)len);
  ck_chacha_block(0, nonce, 0, ks);
  ck_poly_init(1, ks);
  ck_poly_update(1, tx, (uint16_t)(4 + len));
  ck_poly_final(1, tx + 4 + len);
  seq_out++;
  return wr_all(tx, (uint16_t)(4 + len + 16));
}

static unsigned char send_byte_msg(uint8_t type)
{
  return ssh_send(&type, 1);
}

/* Handles the messages any layer may see; returns 1 with a message for
 * the caller, 0 on error or disconnect. */
unsigned char ssh_recv(void)
{
  static uint8_t reply[1];
  for (;;) {
    rbuf r;
    if (!recv_raw()) return 0;
    switch (ssh_rx_type) {
    case SSH_MSG_IGNORE: case SSH_MSG_DEBUG: case SSH_MSG_EXT_INFO: case SSH_MSG_UNIMPLEMENTED:
      continue;
    case SSH_MSG_DISCONNECT: {
      const uint8_t *d; uint16_t n;
      rb_init(&r, ssh_rx + 1, (uint16_t)(ssh_rx_len - 1));
      rb_u32(&r);
      d = rb_string(&r, &n);
      if (n > 79) n = 79;
      if (d) { memcpy(ssh_reason, d, n); ssh_reason[n] = 0; } else ssh_reason[0] = 0;
      ssh_error = SSH_E_DISCONNECT;
      return 0;
    }
    case SSH_MSG_GLOBAL_REQUEST: {
      uint16_t n;
      rb_init(&r, ssh_rx + 1, (uint16_t)(ssh_rx_len - 1));
      rb_string(&r, &n);
      if (rb_byte(&r)) { reply[0] = SSH_MSG_REQUEST_FAILURE; if (!ssh_send(reply, 1)) return 0; }
      continue;
    }
    default:
      return 1;
    }
  }
}

unsigned char ssh_pending(void)
{
  uint16_t avail = 0;
  ssh_poll();
  meganet_tcp_state_s(SSH_SOCK, 0, &avail);
  return avail != 0;
}

void ssh_disconnect(void)
{
  uint8_t *msg = ssh_rx;              /* nothing more is received */
  wbuf b;
  if (encrypted) {
    wb_init(&b, msg, 64);
    wb_byte(&b, SSH_MSG_DISCONNECT); wb_u32(&b, 11);       /* by application */
    wb_cstring(&b, "bye"); wb_cstring(&b, "");
    ssh_send(msg, b.len);
  }
  meganet_tcp_close_s(SSH_SOCK);
  frames = 0;
  while (frames < 60 && meganet_tcp_state_s(SSH_SOCK, 0, 0) != MEGANET_TCP_CLOSED) ssh_poll();
  encrypted = 0;
}

/* ---- the key exchange -------------------------------------------------- */

static void hash_string(const uint8_t *p, uint16_t n)
{
  uint8_t l[4];
  l[0] = 0; l[1] = 0; l[2] = (uint8_t)(n >> 8); l[3] = (uint8_t)n;      /* n is 16 bits here */
  ck_sha256_update(0, l, 4);
  ck_sha256_update(0, p, n);
}

/* 64 bytes of key material for direction x, into the bank's key slots
 * first (the payload key) and first+1 (the length key). */
static void derive(uint8_t first, char x)
{
  static uint8_t out[64];
  ck_sha256_init(1);
  ck_sha256_update(1, kmp, kmp_len); ck_sha256_update(1, H, 32);
  ck_sha256_update(1, &x, 1); ck_sha256_update(1, session_id, 32);
  ck_sha256_final(1, out);
  ck_sha256_init(1);
  ck_sha256_update(1, kmp, kmp_len); ck_sha256_update(1, H, 32); ck_sha256_update(1, out, 32);
  ck_sha256_final(1, out + 32);
  ck_key_set(first, out);
  ck_key_set((uint8_t)(first + 1), out + 32);
  memset(out, 0, sizeof out);
}

static unsigned char read_version(void)
{
  uint8_t c;
  unsigned n;
  for (;;) {
    n = 0;
    for (;;) {
      if (!rd_exact(&c, 1)) return 0;
      if (c == '\n') break;
      if (c != '\r' && n < 254) v_s[n++] = (char)c;
    }
    v_s[n] = 0;
    if (n >= 4 && !memcmp(v_s, "SSH-", 4)) break;   /* other lines may precede it */
  }
  if (memcmp(v_s, "SSH-2.0", 7) && memcmp(v_s, "SSH-1.99", 8)) { ssh_error = SSH_E_VERSION; return 0; }
  return 1;
}

static unsigned char send_kexinit(void)
{
  uint8_t *msg = ssh_rx;
  wbuf b;
  wb_init(&b, msg, 300);
  wb_byte(&b, SSH_MSG_KEXINIT);
  rnd_fill(msg + 1, 16); b.len = 17;
  wb_cstring(&b, KEX_NAMES);
  wb_cstring(&b, HOSTKEY_NAME);
  wb_cstring(&b, CIPHER_NAME); wb_cstring(&b, CIPHER_NAME);
  wb_cstring(&b, "hmac-sha2-256"); wb_cstring(&b, "hmac-sha2-256");
  wb_cstring(&b, "none"); wb_cstring(&b, "none");
  wb_cstring(&b, ""); wb_cstring(&b, "");
  wb_byte(&b, 0);                                 /* no guess */
  wb_u32(&b, 0);
  if (!b.ok) { ssh_error = SSH_E_PROTOCOL; return 0; }
  hash_string(msg, b.len);                        /* I_C */
  return ssh_send(msg, b.len);
}

/* The server's KEXINIT: hash it, check it offers what we do. */
static unsigned char take_kexinit(void)
{
  rbuf r;
  const uint8_t *kex, *hk, *c1, *c2;
  uint16_t nkex, nhk, n1, n2, n;
  unsigned i;
  uint8_t guess;
  if (ssh_rx_type != SSH_MSG_KEXINIT) { ssh_error = SSH_E_PROTOCOL; return 0; }
  hash_string(ssh_rx, ssh_rx_len);                /* I_S */
  rb_init(&r, ssh_rx + 1, (uint16_t)(ssh_rx_len - 1));
  rb_skip(&r, 16);
  kex = rb_string(&r, &nkex);
  hk = rb_string(&r, &nhk);
  c1 = rb_string(&r, &n1);
  c2 = rb_string(&r, &n2);
  for (i = 0; i < 6; i++) rb_string(&r, &n);
  guess = rb_byte(&r);
  if (!r.ok) { ssh_error = SSH_E_PROTOCOL; return 0; }
  if (!(namelist_has(kex, nkex, "curve25519-sha256") || namelist_has(kex, nkex, "curve25519-sha256@libssh.org"))) {
    strcpy(ssh_reason, "no curve25519-sha256"); ssh_error = SSH_E_ALGORITHM; return 0;
  }
  if (!namelist_has(hk, nhk, HOSTKEY_NAME)) { strcpy(ssh_reason, "no ssh-ed25519 host key"); ssh_error = SSH_E_ALGORITHM; return 0; }
  if (!namelist_has(c1, n1, CIPHER_NAME) || !namelist_has(c2, n2, CIPHER_NAME)) {
    strcpy(ssh_reason, "no chacha20-poly1305"); ssh_error = SSH_E_ALGORITHM; return 0;
  }
  strict = (unsigned char)namelist_has(kex, nkex, "kex-strict-s-v00@openssh.com");
  if (guess) {
    /* a guessed first packet follows; it is right only if the server's
     * first choices are ours */
    unsigned char right = (nkex >= 17 && !memcmp(kex, "curve25519-sha256", 17) && (nkex == 17 || kex[17] == ',')) &&
                          (nhk >= 11 && !memcmp(hk, HOSTKEY_NAME, 11) && (nhk == 11 || hk[11] == ','));
    if (!right) { if (!recv_raw()) return 0; }     /* discard it */
  }
  return 1;
}

static unsigned char exchange(void)
{
  static uint8_t msg[40], q_s[32], k[32], pk[32], sig[64];
  static uint8_t ks_blob_len_hi;
  const uint8_t *ks, *qs, *sg, *t, *s2;
  uint16_t nks, nqs, nsg, nt, ns2;
  rbuf r, r2;
  wbuf b;
  unsigned char verdict;
  (void)ks_blob_len_hi;

  status("exchanging keys: our share");
  rnd_fill(priv, 32);
  ck_x25519_base(q_c, priv);
  wb_init(&b, msg, sizeof msg);
  wb_byte(&b, SSH_MSG_KEX_ECDH_INIT);
  wb_string(&b, q_c, 32);
  if (!ssh_send(msg, b.len)) return 0;

  if (!ssh_recv()) return 0;
  if (ssh_rx_type != SSH_MSG_KEX_ECDH_REPLY) { ssh_error = SSH_E_PROTOCOL; return 0; }
  rb_init(&r, ssh_rx + 1, (uint16_t)(ssh_rx_len - 1));
  ks = rb_string(&r, &nks);
  qs = rb_string(&r, &nqs);
  sg = rb_string(&r, &nsg);
  if (!r.ok || nqs != 32) { ssh_error = SSH_E_PROTOCOL; return 0; }
  memcpy(q_s, qs, 32);
  /* the host key blob: string "ssh-ed25519", string key */
  rb_init(&r2, ks, nks);
  t = rb_string(&r2, &nt);
  s2 = rb_string(&r2, &ns2);
  if (!r2.ok || nt != 11 || memcmp(t, HOSTKEY_NAME, 11) || ns2 != 32) { ssh_error = SSH_E_PROTOCOL; return 0; }
  memcpy(pk, s2, 32);
  /* the signature blob: string "ssh-ed25519", string sig */
  rb_init(&r2, sg, nsg);
  t = rb_string(&r2, &nt);
  s2 = rb_string(&r2, &ns2);
  if (!r2.ok || nt != 11 || ns2 != 64) { ssh_error = SSH_E_PROTOCOL; return 0; }
  memcpy(sig, s2, 64);

  status("exchanging keys: the shared secret");
  ck_x25519(k, priv, q_s);
  wb_init(&b, kmp, sizeof kmp);
  wb_mpint(&b, k, 32);
  kmp_len = b.len;
  /* H = hash(V_C, V_S, I_C, I_S, K_S, Q_C, Q_S, K); the first four are in */
  hash_string(ks, nks);
  hash_string(q_c, 32);
  hash_string(q_s, 32);
  ck_sha256_update(0, kmp, kmp_len);
  ck_sha256_final(0, H);
  memcpy(session_id, H, 32);

  /* the host: known, new, or changed */
  verdict = hosts_check(host_name, host_port, pk);
  if (verdict == HOSTS_CHANGED) {
    if (!ssh_ask_hostkey || !ssh_ask_hostkey(pk, 1)) { ssh_error = SSH_E_HOSTCHANGED; return 0; }
  } else if (verdict == HOSTS_UNKNOWN) {
    if (!ssh_ask_hostkey || !ssh_ask_hostkey(pk, 0)) { ssh_error = SSH_E_REFUSED; return 0; }
    hosts_add(host_name, host_port, pk);
  }
  status("checking the host's signature");
  if (!ck_ed25519_verify(sig, H, 32, pk)) { ssh_error = SSH_E_HOSTKEY; return 0; }

  if (!send_byte_msg(SSH_MSG_NEWKEYS)) return 0;
  if (!ssh_recv()) return 0;
  if (ssh_rx_type != SSH_MSG_NEWKEYS) { ssh_error = SSH_E_PROTOCOL; return 0; }
  derive(0, 'C');
  derive(2, 'D');
  encrypted = 1;
  if (strict) { seq_out = 0; seq_in = 0; }
  return 1;
}

unsigned char ssh_connect(const unsigned char ip[4], unsigned int port, const char *host)
{
  static const uint8_t vc[] = VERSION_STRING "\r\n";
  unsigned char st, fl;
  ssh_error = SSH_OK; ssh_reason[0] = 0;
  encrypted = 0; strict = 0; seq_in = seq_out = 0;
  strncpy(host_name, host, sizeof host_name - 1); host_name[sizeof host_name - 1] = 0;
  host_port = port;

  status("connecting");
  meganet_tcp_abort_s(SSH_SOCK);
  frames = 0; while (frames < 3) ssh_poll();
  meganet_tcp_connect_s(SSH_SOCK, ip, port);
  frames = 0;
  for (;;) {
    ssh_poll();
    st = meganet_tcp_state_s(SSH_SOCK, &fl, 0);
    if (st == MEGANET_TCP_ESTABLISHED) break;
    if (st == MEGANET_TCP_CLOSED) { ssh_error = (fl & MEGANET_TCP_F_REFUSED) ? SSH_E_REFUSED : SSH_E_CONNECT; return 0; }
    if (frames > 750) { meganet_tcp_abort_s(SSH_SOCK); ssh_error = SSH_E_CONNECT; return 0; }
  }
  status("reading the server's version");
  if (!read_version()) return 0;
  if (!wr_all(vc, sizeof vc - 1)) return 0;
  ck_sha256_init(0);
  hash_string(vc, sizeof vc - 3);                 /* V_C without CRLF */
  hash_string((const uint8_t *)v_s, (uint16_t)strlen(v_s));
  status("negotiating");
  if (!send_kexinit()) return 0;
  if (!recv_raw()) return 0;
  if (!take_kexinit()) return 0;
  return exchange();
}

/* The userauth service, then the reply loop shared by both methods. */
static unsigned char auth_service(void)
{
  uint8_t *msg = ssh_rx;
  wbuf b;
  status("requesting authentication");
  wb_init(&b, msg, 24);
  wb_byte(&b, SSH_MSG_SERVICE_REQUEST); wb_cstring(&b, "ssh-userauth");
  if (!ssh_send(msg, b.len)) return 0;
  if (!ssh_recv()) return 0;
  if (ssh_rx_type != SSH_MSG_SERVICE_ACCEPT) { ssh_error = SSH_E_PROTOCOL; return 0; }
  return 1;
}

static unsigned char auth_wait(const char *refused)
{
  for (;;) {
    if (!ssh_recv()) return 0;
    if (ssh_rx_type == SSH_MSG_USERAUTH_SUCCESS) return 1;
    if (ssh_rx_type == SSH_MSG_USERAUTH_BANNER) {
      rbuf r; const uint8_t *d; uint16_t n;
      rb_init(&r, ssh_rx + 1, (uint16_t)(ssh_rx_len - 1));
      d = rb_string(&r, &n);
      if (d) { if (n > 79) n = 79; memcpy(ssh_reason, d, n); ssh_reason[n] = 0; status(ssh_reason); }
      continue;
    }
    if (ssh_rx_type == SSH_MSG_USERAUTH_FAILURE) { strcpy(ssh_reason, refused); ssh_error = SSH_E_AUTH; return 0; }
    if (ssh_rx_type == 60) { strcpy(ssh_reason, "the server wants the password changed"); ssh_error = SSH_E_AUTH; return 0; }
    ssh_error = SSH_E_PROTOCOL; return 0;
  }
}

unsigned char ssh_login(const char *user, const char *password)
{
  uint8_t *msg = ssh_rx;
  wbuf b;
  if (!auth_service()) return 0;
  wb_init(&b, msg, 160);
  wb_byte(&b, SSH_MSG_USERAUTH_REQUEST);
  wb_cstring(&b, user); wb_cstring(&b, "ssh-connection"); wb_cstring(&b, "password");
  wb_byte(&b, 0); wb_cstring(&b, password);
  if (!b.ok) { ssh_error = SSH_E_PROTOCOL; return 0; }
  status("sending the password");
  if (!ssh_send(msg, b.len)) return 0;
  memset(msg, 0, 160);                            /* the password is not kept */
  return auth_wait("password refused");
}

/* Public-key authentication with the Ed25519 identity (RFC 4252 7): one
 * request carrying the key and a signature over the session id and the
 * request itself. No query first; the RFC allows going straight to it.
 * The signed bytes are at most 36 + 107 + the user name, within the
 * bank's 256-byte stage (5.22). */
unsigned char ssh_login_key(const char *user, const uint8_t seed[32], const uint8_t pk[32])
{
  static uint8_t sig[64];
  wbuf b, k;
  if (!auth_service()) return 0;
  /* ssh_rx: the session id as a string, then the request, which is what
   * the signature covers; the request alone is what goes out. */
  wb_init(&k, ssh_rx, 36); wb_string(&k, session_id, 32);
  wb_init(&b, ssh_rx + 36, 300);
  wb_byte(&b, SSH_MSG_USERAUTH_REQUEST);
  wb_cstring(&b, user); wb_cstring(&b, "ssh-connection"); wb_cstring(&b, "publickey");
  wb_byte(&b, 1); wb_cstring(&b, "ssh-ed25519");
  wb_u32(&b, 4 + 11 + 4 + 32); wb_cstring(&b, "ssh-ed25519"); wb_string(&b, pk, 32);   /* the key blob */
  if (!b.ok || !k.ok) { ssh_error = SSH_E_PROTOCOL; return 0; }
  status("signing with the identity");
  if (!ck_ed25519_sign(sig, ssh_rx, (uint16_t)(36 + b.len), seed, pk)) { ssh_error = SSH_E_PROTOCOL; return 0; }
  wb_u32(&b, 4 + 11 + 4 + 64); wb_cstring(&b, "ssh-ed25519"); wb_string(&b, sig, 64);  /* the signature blob */
  if (!b.ok) { ssh_error = SSH_E_PROTOCOL; return 0; }
  status("sending the signature");
  if (!ssh_send(ssh_rx + 36, b.len)) return 0;
  return auth_wait("the identity was refused: is its public key on the server?");
}

const char *ssh_error_text(void)
{
  switch (ssh_error) {
  case SSH_E_CONNECT: return "no reply from the host";
  case SSH_E_REFUSED: return "refused";
  case SSH_E_TIMEOUT: return "the server stopped answering";
  case SSH_E_CLOSED: return "the connection closed";
  case SSH_E_VERSION: return "not an SSH 2 server";
  case SSH_E_TOOBIG: return "a packet too large for this client";
  case SSH_E_PROTOCOL: return "the server broke the protocol";
  case SSH_E_ALGORITHM: return ssh_reason;
  case SSH_E_HOSTKEY: return "the host key signature is wrong: not the host it claims";
  case SSH_E_HOSTCHANGED: return "the host's key has changed; refused";
  case SSH_E_MAC: return "a packet failed its check";
  case SSH_E_DISCONNECT: return ssh_reason;
  case SSH_E_AUTH: return ssh_reason;
  default: return "unknown error";
  }
}
