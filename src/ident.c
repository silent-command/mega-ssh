#include <string.h>
#include "mega65/memory.h"
#include "m65_cbmdos.h"
#include "ckit.h"
#include "rnd.h"
#include "ident.h"

#define IDENT_FILE "IDENTITY"
#define AUTH_FILE "SSHAUTH"

uint8_t ident_seed[32], ident_pk[32];
unsigned char ident_present;
char ident_auth = 'p';
static unsigned char ident_drive;
static uint8_t buf64[64];              /* the file's bytes, in and out */

/* The key blob as SSH carries it: string "ssh-ed25519", string key. */
static const uint8_t blob_head[19] = { 0, 0, 0, 11, 's', 's', 'h', '-', 'e', 'd', '2', '5', '5', '1', '9', 0, 0, 0, 32 };
static uint8_t blob[51];

static void make_blob(void)
{
  memcpy(blob, blob_head, 19);
  memcpy(blob + 19, ident_pk, 32);
}

static const char b64d[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/* Base64 without padding, the way OpenSSH prints fingerprints; the key
 * blob is 51 bytes, a multiple of three, so its text needs none either. */
static void b64(char *out, const uint8_t *in, unsigned char n)
{
  unsigned char i;
  for (i = 0; i + 2 < n; i += 3) {
    *out++ = b64d[in[i] >> 2];
    *out++ = b64d[((in[i] & 3) << 4) | (in[i + 1] >> 4)];
    *out++ = b64d[((in[i + 1] & 15) << 2) | (in[i + 2] >> 6)];
    *out++ = b64d[in[i + 2] & 63];
  }
  if (i < n) {
    *out++ = b64d[in[i] >> 2];
    if (i + 1 < n) { *out++ = b64d[((in[i] & 3) << 4) | (in[i + 1] >> 4)]; *out++ = b64d[(in[i + 1] & 15) << 2]; }
    else *out++ = b64d[(in[i] & 3) << 4];
  }
  *out = 0;
}

void ident_public_b64(char *out)
{
  make_blob();
  b64(out, blob, 51);
}

void ident_fingerprint_b64(char *out)
{
  static uint8_t fp[32];
  make_blob();
  ck_sha256_init(2); ck_sha256_update(2, blob, 51); ck_sha256_final(2, fp);
  b64(out, fp, 32);
}

void ident_load(unsigned char drive)
{
  uint8_t *buf = buf64;
  ident_drive = drive;
  ident_present = 0;
  if (cbmdos_load(IDENT_FILE, drive, (unsigned long)(unsigned int)buf, 64) == 64) {
    memcpy(ident_seed, buf, 32); memcpy(ident_pk, buf + 32, 32);
    memset(buf, 0, 64);
    ident_present = 1;
  }
  if (cbmdos_load(AUTH_FILE, drive, (unsigned long)(unsigned int)buf, 1) == 1 && (buf[0] == 'i' || buf[0] == 'p'))
    ident_auth = (char)buf[0];
}

static unsigned char write_file(const char *name, const uint8_t *p, unsigned char n)
{
  unsigned char i;
  cbmdos_delete(name, ident_drive);                  /* absent the first time; fine */
  if (cbmdos_create(name, ident_drive) != CBMDOS_OK) return 0;
  for (i = 0; i < n; i++)
    if (cbmdos_put(p[i]) != CBMDOS_OK) { cbmdos_close(); return 0; }
  return cbmdos_close() == CBMDOS_OK;
}

unsigned char ident_generate(void)
{
  uint8_t *buf = buf64;
  rnd_fill(ident_seed, 32);
  if (!ck_ed25519_keypair(ident_pk, ident_seed)) return 0;
  memcpy(buf, ident_seed, 32); memcpy(buf + 32, ident_pk, 32);
  ident_present = write_file(IDENT_FILE, buf, 64);
  memset(buf, 0, 64);
  return ident_present;
}

unsigned char ident_set_auth(char method)
{
  uint8_t b = (uint8_t)method;
  ident_auth = method;
  return write_file(AUTH_FILE, &b, 1);
}
