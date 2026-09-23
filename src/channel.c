#include <string.h>
#include "wire.h"
#include "transport.h"
#include "channel.h"

void (*ch_on_data)(const uint8_t *p, uint16_t n);
uint8_t ch_pty_rows = 25;             /* the screen's rows, set by the client (5.23) */
unsigned char ch_closed;
int ch_exit_status;

static uint32_t remote_id;            /* the server's number for the channel */
static uint32_t remote_window;        /* bytes we may still send */
static uint32_t local_window;         /* bytes the server may still send */
static uint32_t remote_maxpkt;
static unsigned char opened, eof_sent;
#define msg ssh_rx                    /* messages are built in the receive buffer, idle by then (5.27) */

#define LOCAL_ID 0

static unsigned char request(const char *what, unsigned char want_reply, const uint8_t *extra, uint16_t n)
{
  wbuf b;
  wb_init(&b, msg, sizeof msg);
  wb_byte(&b, SSH_MSG_CHANNEL_REQUEST); wb_u32(&b, remote_id);
  wb_cstring(&b, what); wb_byte(&b, want_reply);
  if (n) wb_bytes(&b, extra, n);
  if (!b.ok) { ssh_error = SSH_E_PROTOCOL; return 0; }
  return ssh_send(msg, b.len);
}

/* Waits for a reply to a request, handling channel traffic meanwhile. */
static unsigned char wait_reply(void)
{
  for (;;) {
    if (!ssh_recv()) return 0;
    if (ssh_rx_type == SSH_MSG_CHANNEL_SUCCESS) return 1;
    if (ssh_rx_type == SSH_MSG_CHANNEL_FAILURE) { strcpy(ssh_reason, "the server refused the request"); ssh_error = SSH_E_PROTOCOL; return 0; }
    if (ssh_rx_type == SSH_MSG_CHANNEL_WINDOW_ADJUST || ssh_rx_type == SSH_MSG_CHANNEL_DATA ||
        ssh_rx_type == SSH_MSG_CHANNEL_EXTENDED_DATA) {
      /* early output: keep it */
      extern unsigned char ch_dispatch(void);
      if (!ch_dispatch()) return 0;
      continue;
    }
    ssh_error = SSH_E_PROTOCOL; return 0;
  }
}

unsigned char ch_open_shell(void)
{
  wbuf b;
  rbuf r;
  uint8_t pty[64];
  wbuf pb;
  ch_closed = 0; eof_sent = 0; opened = 0; ch_exit_status = -1;
  ssh_status ? ssh_status("opening a session") : (void)0;
  wb_init(&b, msg, sizeof msg);
  wb_byte(&b, SSH_MSG_CHANNEL_OPEN); wb_cstring(&b, "session");
  wb_u32(&b, LOCAL_ID); wb_u32(&b, CH_LOCAL_WINDOW); wb_u32(&b, CH_LOCAL_MAXPKT);
  if (!ssh_send(msg, b.len)) return 0;
  if (!ssh_recv()) return 0;
  if (ssh_rx_type == SSH_MSG_CHANNEL_OPEN_FAILURE) {
    const uint8_t *d; uint16_t n;
    rb_init(&r, ssh_rx + 1, (uint16_t)(ssh_rx_len - 1));
    rb_u32(&r); rb_u32(&r);
    d = rb_string(&r, &n);
    if (d) { if (n > 79) n = 79; memcpy(ssh_reason, d, n); ssh_reason[n] = 0; } else strcpy(ssh_reason, "session refused");
    ssh_error = SSH_E_PROTOCOL; return 0;
  }
  if (ssh_rx_type != SSH_MSG_CHANNEL_OPEN_CONFIRMATION) { ssh_error = SSH_E_PROTOCOL; return 0; }
  rb_init(&r, ssh_rx + 1, (uint16_t)(ssh_rx_len - 1));
  rb_u32(&r);                                       /* our id, echoed */
  remote_id = rb_u32(&r);
  remote_window = rb_u32(&r);
  remote_maxpkt = rb_u32(&r);
  if (!r.ok) { ssh_error = SSH_E_PROTOCOL; return 0; }
  local_window = CH_LOCAL_WINDOW;
  opened = 1;

  /* pty-req: term, cols, rows, width px, height px, modes (empty) */
  ssh_status ? ssh_status("asking for a terminal") : (void)0;
  wb_init(&pb, pty, sizeof pty);
  wb_cstring(&pb, "vt100"); wb_u32(&pb, 80); wb_u32(&pb, ch_pty_rows); wb_u32(&pb, 640); wb_u32(&pb, ch_pty_rows == 50 ? 400 : 200);
  wb_u32(&pb, 0);
  if (!request("pty-req", 1, pty, pb.len)) return 0;
  if (!wait_reply()) return 0;
  ssh_status ? ssh_status("asking for a shell") : (void)0;
  if (!request("shell", 1, 0, 0)) return 0;
  if (!wait_reply()) return 0;
  return 1;
}

unsigned char ch_send(const uint8_t *p, uint16_t n)
{
  wbuf b;
  uint16_t take;
  while (n) {
    while (remote_window == 0) {                    /* wait for the server to open its window */
      if (!ssh_pending()) { if (ch_closed) return 0; continue; }
      if (!ch_poll()) return 0;
    }
    take = n;
    if (take > remote_window) take = (uint16_t)remote_window;
    if (take > remote_maxpkt) take = (uint16_t)remote_maxpkt;
    if (take > SSH_TX_MAX - 16) take = SSH_TX_MAX - 16;
    wb_init(&b, msg, sizeof msg);
    wb_byte(&b, SSH_MSG_CHANNEL_DATA); wb_u32(&b, remote_id); wb_string(&b, p, take);
    if (!ssh_send(msg, b.len)) return 0;
    remote_window -= take; p += take; n = (uint16_t)(n - take);
  }
  return 1;
}

/* Gives the server more window once we have consumed half of ours. */
static unsigned char adjust(void)
{
  wbuf b;
  uint32_t give = CH_LOCAL_WINDOW - local_window;
  if (give < CH_LOCAL_WINDOW / 2) return 1;
  wb_init(&b, msg, sizeof msg);
  wb_byte(&b, SSH_MSG_CHANNEL_WINDOW_ADJUST); wb_u32(&b, remote_id); wb_u32(&b, give);
  if (!ssh_send(msg, b.len)) return 0;
  local_window += give;
  return 1;
}

/* The message in ssh_rx is a channel message: act on it. */
unsigned char ch_dispatch(void)
{
  rbuf r;
  const uint8_t *d; uint16_t n;
  rb_init(&r, ssh_rx + 1, (uint16_t)(ssh_rx_len - 1));
  switch (ssh_rx_type) {
  case SSH_MSG_CHANNEL_DATA:
    rb_u32(&r);
    d = rb_string(&r, &n);
    if (d && n) { if (ch_on_data) ch_on_data(d, n); local_window = n > local_window ? 0 : local_window - n; }
    return adjust();
  case SSH_MSG_CHANNEL_EXTENDED_DATA:
    rb_u32(&r); rb_u32(&r);
    d = rb_string(&r, &n);
    if (d && n) { if (ch_on_data) ch_on_data(d, n); local_window = n > local_window ? 0 : local_window - n; }
    return adjust();
  case SSH_MSG_CHANNEL_WINDOW_ADJUST:
    rb_u32(&r);
    remote_window += rb_u32(&r);
    return 1;
  case SSH_MSG_CHANNEL_EOF:
    return 1;
  case SSH_MSG_CHANNEL_CLOSE: {
    wbuf b;
    if (!ch_closed) {
      wb_init(&b, msg, sizeof msg);
      wb_byte(&b, SSH_MSG_CHANNEL_CLOSE); wb_u32(&b, remote_id);
      ssh_send(msg, b.len);
    }
    ch_closed = 1;
    return 1;
  }
  case SSH_MSG_CHANNEL_REQUEST: {
    const uint8_t *what; uint16_t wn; uint8_t want;
    rb_u32(&r);
    what = rb_string(&r, &wn);
    want = rb_byte(&r);
    if (what && wn == 11 && !memcmp(what, "exit-status", 11)) ch_exit_status = (int)rb_u32(&r);
    if (want) {
      wbuf b;
      wb_init(&b, msg, sizeof msg);
      wb_byte(&b, SSH_MSG_CHANNEL_FAILURE); wb_u32(&b, remote_id);
      if (!ssh_send(msg, b.len)) return 0;
    }
    return 1;
  }
  case SSH_MSG_CHANNEL_OPEN: {                       /* we open no channels for the server */
    wbuf b;
    uint32_t their = 0;
    rb_string(&r, &n); their = rb_u32(&r);
    wb_init(&b, msg, sizeof msg);
    wb_byte(&b, SSH_MSG_CHANNEL_OPEN_FAILURE); wb_u32(&b, their); wb_u32(&b, 1);
    wb_cstring(&b, "no"); wb_cstring(&b, "");
    return ssh_send(msg, b.len);
  }
  default:
    return 1;                                       /* anything else: ignored */
  }
}

unsigned char ch_poll(void)
{
  if (ch_closed) return 0;
  if (!ssh_pending()) return 1;
  if (!ssh_recv()) return 0;
  return ch_dispatch();
}

void ch_close(void)
{
  wbuf b;
  if (!opened || ch_closed) return;
  if (!eof_sent) {
    wb_init(&b, msg, sizeof msg);
    wb_byte(&b, SSH_MSG_CHANNEL_EOF); wb_u32(&b, remote_id);
    ssh_send(msg, b.len);
    eof_sent = 1;
  }
  wb_init(&b, msg, sizeof msg);
  wb_byte(&b, SSH_MSG_CHANNEL_CLOSE); wb_u32(&b, remote_id);
  ssh_send(msg, b.len);
  ch_closed = 1;
}
