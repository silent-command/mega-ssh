#include <string.h>
#include "wire.h"

void wb_init(wbuf *b, uint8_t *storage, uint16_t cap) { b->p = storage; b->len = 0; b->cap = cap; b->ok = 1; }

void wb_byte(wbuf *b, uint8_t v)
{
  if (b->len >= b->cap) { b->ok = 0; return; }
  b->p[b->len++] = v;
}

void wb_u32(wbuf *b, uint32_t v)
{
  wb_byte(b, (uint8_t)(v >> 24)); wb_byte(b, (uint8_t)(v >> 16));
  wb_byte(b, (uint8_t)(v >> 8)); wb_byte(b, (uint8_t)v);
}

void wb_bytes(wbuf *b, const uint8_t *p, uint16_t n)
{
  if ((uint16_t)(b->cap - b->len) < n) { b->ok = 0; return; }
  memcpy(b->p + b->len, p, n);
  b->len = (uint16_t)(b->len + n);
}

void wb_string(wbuf *b, const uint8_t *p, uint16_t n) { wb_u32(b, n); wb_bytes(b, p, n); }

void wb_cstring(wbuf *b, const char *s) { wb_string(b, (const uint8_t *)s, (uint16_t)strlen(s)); }

void wb_mpint(wbuf *b, const uint8_t *p, uint16_t n)
{
  while (n && *p == 0) { p++; n--; }               /* no leading zeros */
  if (n && (p[0] & 0x80)) { wb_u32(b, (uint32_t)n + 1); wb_byte(b, 0); wb_bytes(b, p, n); }
  else wb_string(b, p, n);
}

void rb_init(rbuf *r, const uint8_t *p, uint16_t len) { r->p = p; r->pos = 0; r->len = len; r->ok = 1; }

uint8_t rb_byte(rbuf *r)
{
  if (r->pos >= r->len) { r->ok = 0; return 0; }
  return r->p[r->pos++];
}

uint32_t rb_u32(rbuf *r)
{
  uint32_t v = (uint32_t)rb_byte(r) << 24;
  v |= (uint32_t)rb_byte(r) << 16;
  v |= (uint32_t)rb_byte(r) << 8;
  v |= rb_byte(r);
  return v;
}

const uint8_t *rb_string(rbuf *r, uint16_t *n)
{
  uint32_t len = rb_u32(r);
  const uint8_t *p;
  if (!r->ok || len > (uint32_t)(r->len - r->pos)) { r->ok = 0; *n = 0; return 0; }
  p = r->p + r->pos;
  r->pos = (uint16_t)(r->pos + len);
  *n = (uint16_t)len;
  return p;
}

void rb_skip(rbuf *r, uint16_t n)
{
  if (n > (uint16_t)(r->len - r->pos)) { r->ok = 0; r->pos = r->len; return; }
  r->pos = (uint16_t)(r->pos + n);
}

uint16_t rb_left(const rbuf *r) { return (uint16_t)(r->len - r->pos); }

int namelist_has(const uint8_t *list, uint16_t n, const char *name)
{
  uint16_t i = 0, nl = (uint16_t)strlen(name);
  while (i < n) {
    uint16_t j = i;
    while (j < n && list[j] != ',') j++;
    if (j - i == nl && memcmp(list + i, name, nl) == 0) return 1;
    i = (uint16_t)(j + 1);
  }
  return 0;
}
