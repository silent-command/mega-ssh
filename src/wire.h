/* The SSH wire types (RFC 4251 5): byte, boolean, uint32, string, mpint,
 * name-list, written into and read out of a buffer with the bounds
 * checked on every access. A reader that runs off the end reports it
 * once and answers zeros afterwards, so a caller checks `ok` at the end
 * of a message rather than after every field. */
#ifndef WIRE_H
#define WIRE_H

#include <stdint.h>

typedef struct {
  uint8_t *p;
  uint16_t len, cap;
  uint8_t ok;
} wbuf;

void wb_init(wbuf *b, uint8_t *storage, uint16_t cap);
void wb_byte(wbuf *b, uint8_t v);
void wb_u32(wbuf *b, uint32_t v);
void wb_bytes(wbuf *b, const uint8_t *p, uint16_t n);
void wb_string(wbuf *b, const uint8_t *p, uint16_t n);   /* uint32 length, then bytes */
void wb_cstring(wbuf *b, const char *s);
void wb_mpint(wbuf *b, const uint8_t *p, uint16_t n);    /* unsigned big-endian magnitude */

typedef struct {
  const uint8_t *p;
  uint16_t pos, len;
  uint8_t ok;
} rbuf;

void rb_init(rbuf *r, const uint8_t *p, uint16_t len);
uint8_t rb_byte(rbuf *r);
uint32_t rb_u32(rbuf *r);
/* Returns a pointer into the buffer and the length; null and 0 on error. */
const uint8_t *rb_string(rbuf *r, uint16_t *n);
void rb_skip(rbuf *r, uint16_t n);
uint16_t rb_left(const rbuf *r);

/* 1 when `name` (a C string) appears in the comma-separated list. */
int namelist_has(const uint8_t *list, uint16_t n, const char *name);

#endif
