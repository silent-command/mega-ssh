#include <string.h>
#include "mega65/memory.h"
#include "m65_cbmdos.h"
#include "m65_f011.h"
#include "m65_scratch.h"

/* Working buffers in low RAM, not .bss: two 256-byte buffers do not fit
 * in the ~600 bytes left below the stack. $1800-$19ff was verified free
 * on hardware -- a pattern written there survived a full DHCP bring-up,
 * menu fetch and article load with zero bytes changed. */
#define BAM_BUF ((volatile unsigned char *)0x1800)
#define BLK_BUF ((volatile unsigned char *)0x1900)

#define DIR_TRACK 40
#define BAM_SECTOR 1  /* tracks 1-40  */
#define BAM_SECTOR2 2 /* tracks 41-80 */
#define DIR_FIRST 3
#define LAST_TRACK 80
#define SECTORS_PER_TRACK 40
#define DATA_PER_BLOCK 254

/* A 1581 splits its BAM across two sectors on the directory track: (40,1)
 * covers tracks 1-40 and (40,2) covers 41-80, each holding 6 bytes per
 * track from offset 16 -- a free-block count then a 40-bit map, bit set
 * meaning free. Layout confirmed against a real image: (40,1) links to
 * (40,2), (40,2) ends the chain, and both carry the same DOS version and
 * disk ID in bytes 2-5.
 *
 * Only the first sector used to be loaded, which capped every file at
 * tracks 1-39 -- about 387KB of a disk that holds nearly 800KB. That
 * mattered little for saved articles and a great deal for downloads
 * (2.38). Both sectors are now held, and the second lives in .bss: the
 * fixed low-RAM addresses above exist because .bss was full at the time,
 * not because they are faster. A .bss array's address is just as constant
 * to the compiler. (A build may name an address for it all the same, when
 * its .bss is the scarce thing: BAM2_AT, irc step 3.) */
#ifdef BAM2_AT
#define bam2 ((unsigned char *)BAM2_AT)
#else
static unsigned char bam2[256];
#endif

/* Track 40 is the directory track and is never allocated for file data;
 * bam_find skips it. */
#define BAM_BUF_FOR(t) ((t) <= 40 ? BAM_BUF : (volatile unsigned char *)bam2)
#define BAM_ENTRY_FOR(t) ((t) <= 40 ? (16 + ((t)-1) * 6) : (16 + ((t)-41) * 6))


static unsigned char open_flag = 0;
static unsigned char cbm_type = CBMDOS_TYPE_SEQ; /* written at close */
static unsigned char cur_t, cur_s;   /* block being filled */
static unsigned char first_t, first_s;
static unsigned char pos;            /* write offset in BLK_BUF */
static unsigned int blocks;
#define fname SCR_DOS_NAME

unsigned int cbmdos_blocks(void)
{
  return blocks;
}

/* Write-protection is worth telling apart from a general I/O failure:
 * it is the one write error the user can actually do something about. */
static unsigned char map_write_err(unsigned char err)
{
  return (unsigned char)(err == F011_ERR_PROT ? CBMDOS_ERR_PROT
                                              : CBMDOS_ERR_IO);
}

static unsigned char bam_load(void)
{
  unsigned char err = f011_read_block(DIR_TRACK, BAM_SECTOR,
                                      (unsigned char *)BAM_BUF);
  if (err != F011_OK)
    return err;
  return f011_read_block(DIR_TRACK, BAM_SECTOR2, bam2);
}

static unsigned char bam_save(void)
{
  unsigned char err = f011_write_block(DIR_TRACK, BAM_SECTOR,
                                       (unsigned char *)BAM_BUF);
  if (err != F011_OK)
    return err;
  return f011_write_block(DIR_TRACK, BAM_SECTOR2, bam2);
}

/* Finds a free block, nearest the directory track first, which is what
 * CBM DOS does and keeps files from scattering to the rim. */
/* Scans one track for a free sector. */
static unsigned char bam_scan(unsigned char track, unsigned char *s)
{
  volatile unsigned char *buf = BAM_BUF_FOR(track);
  unsigned char e = (unsigned char)BAM_ENTRY_FOR(track);
  unsigned char sect, byte, bit;

  if (!buf[e])
    return 0; /* no free blocks on this track */
  for (sect = 0; sect < SECTORS_PER_TRACK; sect++) {
    byte = (unsigned char)(e + 1 + (sect >> 3));
    bit = (unsigned char)(1 << (sect & 7));
    if (buf[byte] & bit) {
      *s = sect;
      return 1;
    }
  }
  return 0;
}

/* Finds a free block: inward from the directory track first, which is what
 * CBM DOS does and keeps small files from scattering to the rim, then
 * outward across the second BAM sector. Track 40 is the directory track
 * and is never handed out. */
static unsigned char bam_find(unsigned char *t, unsigned char *s)
{
  unsigned char track;

  for (track = DIR_TRACK - 1; track >= 1; track--)
    if (bam_scan(track, s)) {
      *t = track;
      return 1;
    }
  for (track = DIR_TRACK + 1; track <= LAST_TRACK; track++)
    if (bam_scan(track, s)) {
      *t = track;
      return 1;
    }
  return 0;
}

/* Returns a block to the BAM. The inverse of bam_alloc.
 *
 * Routed by track: these are called with tracks on either side of the
 * directory track now that files can span the whole disk. */
static void bam_free(unsigned char t, unsigned char s)
{
  volatile unsigned char *buf = BAM_BUF_FOR(t);
  unsigned char e = (unsigned char)BAM_ENTRY_FOR(t);
  unsigned char byte = (unsigned char)(e + 1 + (s >> 3));
  unsigned char bit = (unsigned char)(1 << (s & 7));

  if (!(buf[byte] & bit)) {
    buf[byte] = (unsigned char)(buf[byte] | bit);
    buf[e]++;
  }
}

/* Finds a free sector on one specific track. bam_find() deliberately
 * never hands out the directory track; extending the directory chain is
 * the one case that must, so it comes through here instead. */
static unsigned char bam_find_on_track(unsigned char track, unsigned char *s)
{
  return bam_scan(track, s);
}

static void bam_alloc(unsigned char t, unsigned char s)
{
  volatile unsigned char *buf = BAM_BUF_FOR(t);
  unsigned char e = (unsigned char)BAM_ENTRY_FOR(t);
  unsigned char byte = (unsigned char)(e + 1 + (s >> 3));
  unsigned char bit = (unsigned char)(1 << (s & 7));

  if (buf[byte] & bit) {
    buf[byte] = (unsigned char)(buf[byte] & ~bit);
    if (buf[e])
      buf[e]--;
  }
}

/* Walks the directory chain looking for `fname`. Returns 1 if a file of
 * that name already exists. Names on disk are padded with $a0, so the
 * comparison pads too rather than relying on a terminator.
 *
 * Uses BLK_BUF, so it must run before any file data is buffered. */
static unsigned char dir_find_name(
    const char *want, unsigned char *ft, unsigned char *fs)
{
  unsigned char t = DIR_TRACK, s = DIR_FIRST;
  unsigned char e, i, nt, ns, match, wl;
  unsigned char c;

  for (;;) {
    if (f011_read_block(t, s, (unsigned char *)BLK_BUF) != F011_OK)
      return 0; /* unreadable: let the caller proceed and fail later */
    nt = BLK_BUF[0];
    ns = BLK_BUF[1];

    for (e = 0; e < 8; e++) {
      if (BLK_BUF[e * 32 + 2] == 0)
        continue; /* empty slot */
      /* Measure the wanted name first: directory names are padded to 16
       * with $a0, and walking `want` past its NUL to synthesise that
       * padding reads off the end of the string. */
      wl = 0;
      while (wl < 16 && want[wl])
        wl++;

      match = 1;
      for (i = 0; i < 16; i++) {
        c = (i < wl) ? (unsigned char)want[i] : 0xa0;
        if (BLK_BUF[e * 32 + 5 + i] != c) {
          match = 0;
          break;
        }
      }
      if (match) {
        if (ft) {
          *ft = BLK_BUF[e * 32 + 3];
          *fs = BLK_BUF[e * 32 + 4];
        }
        return 1;
      }
    }

    if (nt == 0)
      return 0;
    t = nt;
    s = ns;
  }
}

unsigned char cbmdos_create(const char *name, unsigned char drive)
{
  return cbmdos_create_as(name, drive, CBMDOS_TYPE_SEQ);
}

unsigned char cbmdos_create_as(const char *name, unsigned char drive,
                               unsigned char type)
{
  cbm_type = type;
  unsigned char i, err;

  open_flag = 0;
  blocks = 0;

  for (i = 0; i < 16 && name[i]; i++) {
    unsigned char c = (unsigned char)name[i];
    if (c >= 0x61 && c <= 0x7a) /* fold to upper for the directory */
      c = (unsigned char)(c - 32);
    fname[i] = (char)c;
  }
  if (i == 0)
    return CBMDOS_ERR_IO;
  for (; i < 17; i++)
    fname[i] = 0; /* no stale tail from the previous save */

  err = f011_start(drive);
  (void)err; /* spin-up never completes on a virtualised drive */

  /* Refuse to create a second file of the same name.
   *
   * CBM DOS itself does not stop you: a duplicate entry is accepted, and
   * the older file becomes unreachable by name while its blocks stay
   * allocated. Since the suggested filename is derived from the selector,
   * saving two articles from the same site can easily collide, so the
   * check matters more here than it would in a general-purpose DOS.
   *
   * Compared against the case-folded name, which is what will be written.
   * An existing lower-case entry therefore would not match -- acceptable,
   * since every entry this program creates is folded the same way. */
  if (dir_find_name(fname, 0, 0)) {
    f011_stop();
    return CBMDOS_ERR_EXISTS;
  }

  err = bam_load();
  if (err != F011_OK) {
    f011_stop(); /* never leave the motor and LED running on a failure */
    return CBMDOS_ERR_IO;
  }

  if (!bam_find(&first_t, &first_s)) {
    f011_stop();
    return CBMDOS_ERR_FULL;
  }
  bam_alloc(first_t, first_s);

  cur_t = first_t;
  cur_s = first_s;
  pos = 2; /* first two bytes of a block are the link */
  blocks = 1;
  open_flag = 1;
  return CBMDOS_OK;
}

unsigned char cbmdos_put(unsigned char b)
{
  unsigned char nt, ns, err;

  if (!open_flag)
    return CBMDOS_ERR_NOTOPEN;

  BLK_BUF[pos] = b;
  pos++;
  if (pos != 0) /* wrapped past 255 means the block is full */
    return CBMDOS_OK;

  /* Full: allocate the next block, link this one to it, flush. */
  if (!bam_find(&nt, &ns)) {
    open_flag = 0;
    f011_stop();
    return CBMDOS_ERR_FULL;
  }
  bam_alloc(nt, ns);

  BLK_BUF[0] = nt;
  BLK_BUF[1] = ns;
  err = f011_write_block(cur_t, cur_s, (unsigned char *)BLK_BUF);
  if (err != F011_OK) {
    open_flag = 0;
    f011_stop();
    return map_write_err(err);
  }

  cur_t = nt;
  cur_s = ns;
  pos = 2;
  blocks++;
  return CBMDOS_OK;
}

/* Finds a free slot in the existing directory chain. Returns 1 with the
 * block and byte offset of the slot, leaving that block in BLK_BUF. */
static unsigned char dir_find_slot(
    unsigned char *dt, unsigned char *ds, unsigned char *off)
{
  unsigned char t = DIR_TRACK, s = DIR_FIRST;
  unsigned char e, nt, ns;

  for (;;) {
    if (f011_read_block(t, s, (unsigned char *)BLK_BUF) != F011_OK)
      return 0;
    nt = BLK_BUF[0];
    ns = BLK_BUF[1];

    for (e = 0; e < 8; e++)
      if (BLK_BUF[e * 32 + 2] == 0) { /* free slot: no file type */
        *dt = t;
        *ds = s;
        *off = (unsigned char)(e * 32);
        return 1;
      }

    if (nt == 0) {
      /* End of the chain with every slot taken. Extend it rather than
       * refusing the save: a fresh .d81 has a single directory block, so
       * without this a disk fills up at 8 files while ~3000 blocks sit
       * free. CBM DOS itself extends the chain the same way.
       *
       * Directory blocks live on the directory track, which the ordinary
       * allocator never touches (bam_find stops at track 39), so this
       * uses bam_find_on_track. Track 40's BAM entry is inside the first
       * BAM sector, already loaded, so no extra sector I/O is needed. */
      unsigned char news;

      if (!bam_find_on_track(DIR_TRACK, &news))
        return 0; /* directory track full: genuinely out of slots */
      bam_alloc(DIR_TRACK, news);

      /* Link the current last block to the new one and flush it. */
      BLK_BUF[0] = DIR_TRACK;
      BLK_BUF[1] = news;
      if (f011_write_block(t, s, (unsigned char *)BLK_BUF) != F011_OK)
        return 0;

      /* Initialise the new block: end-of-chain link, all slots empty.
       * The whole block is cleared because a recycled sector can hold a
       * previous file's bytes, and a stale non-zero type byte would read
       * as an occupied slot. */
      for (e = 0; e < 255; e++)
        BLK_BUF[e] = 0;
      BLK_BUF[255] = 0;
      BLK_BUF[0] = 0;
      BLK_BUF[1] = 0xff; /* last block: link track 0, 255 bytes in use */
      if (f011_write_block(DIR_TRACK, news, (unsigned char *)BLK_BUF) != F011_OK)
        return 0;

      *dt = DIR_TRACK;
      *ds = news;
      *off = 0;
      return 1;
    }
    t = nt;
    s = ns;
  }
}

unsigned char cbmdos_close(void)
{
  unsigned char dt, ds, off, i, err;

  if (!open_flag)
    return CBMDOS_ERR_NOTOPEN;
  open_flag = 0;

  /* Last block: link track 0, and the "sector" is the index of the last
   * byte used, which is pos - 1. */
  BLK_BUF[0] = 0;
  BLK_BUF[1] = (unsigned char)(pos - 1);
  for (i = pos; i != 0; i++)
    BLK_BUF[i] = 0; /* clear the tail so stale bytes are not written */
  {
    unsigned char werr = f011_write_block(cur_t, cur_s,
                                          (unsigned char *)BLK_BUF);
    if (werr != F011_OK) {
      f011_stop();
      return map_write_err(werr);
    }
  }

  if (!dir_find_slot(&dt, &ds, &off)) {
    f011_stop();
    return CBMDOS_ERR_DIRFULL;
  }

  /* dir_find_slot left the directory block in BLK_BUF. */
  BLK_BUF[off + 2] = cbm_type; /* closed SEQ or PRG */
  BLK_BUF[off + 3] = first_t;
  BLK_BUF[off + 4] = first_s;
  /* Pad with $a0 from the terminator onwards. Testing fname[i] one byte at
   * a time looks equivalent but is not: fname is a reused scratch buffer
   * (SCR_DOS_NAME), so the bytes after the NUL are leftovers from the
   * previous save and were being written into the name verbatim. That
   * produced entries like "PROXY<a0>#J#% #" which CBM DOS cannot match,
   * so the file could not be LOADed by name. */
  {
    unsigned char pad = 0;
    for (i = 0; i < 16; i++) {
      if (!pad && fname[i] == 0)
        pad = 1;
      BLK_BUF[off + 5 + i] = pad ? 0xa0 : (unsigned char)fname[i];
    }
  }
  for (i = 21; i < 30; i++)
    BLK_BUF[off + i] = 0;
  BLK_BUF[off + 30] = (unsigned char)(blocks & 0xff);
  BLK_BUF[off + 31] = (unsigned char)(blocks >> 8);

  err = f011_write_block(dt, ds, (unsigned char *)BLK_BUF);
  if (err != F011_OK) {
    f011_stop();
    return map_write_err(err);
  }

  if (bam_save() != F011_OK) {
    f011_stop();
    return CBMDOS_ERR_IO;
  }

  f011_stop();
  return CBMDOS_OK;
}

unsigned char cbmdos_dir_open(unsigned char drive)
{
  (void)f011_start(drive);
  return f011_read_block(DIR_TRACK, DIR_FIRST, (unsigned char *)BLK_BUF);
}

unsigned char cbmdos_dir_get(unsigned char idx, char *out)
{
  unsigned char i, o = 0, c;
  unsigned int nb;

  if (BLK_BUF[idx * 32 + 2] == 0)
    return 0;

  for (i = 0; i < 16; i++) {
    c = BLK_BUF[idx * 32 + 5 + i];
    if (c == 0xa0 || c == 0)
      break;
    out[o++] = (char)c;
  }
  out[o++] = ' ';
  out[o++] = ' ';

  nb = (unsigned int)BLK_BUF[idx * 32 + 30] | ((unsigned int)BLK_BUF[idx * 32 + 31] << 8);
  if (nb >= 100) {
    out[o++] = (char)('0' + nb / 100);
    nb %= 100;
    out[o++] = (char)('0' + nb / 10);
  }
  else if (nb >= 10) {
    out[o++] = (char)('0' + nb / 10);
  }
  out[o++] = (char)('0' + nb % 10);
  out[o] = 0;
  return 1;
}

unsigned char cbmdos_delete(const char *name, unsigned char drive)
{
  unsigned char t = DIR_TRACK, s = DIR_FIRST;
  unsigned char e, i, nt, ns, wl, c, match;
  unsigned char ft = 0, fs = 0;
  unsigned char dt = 0, ds = 0, off = 0;
  unsigned char found = 0;

  for (i = 0; i < 16 && name[i]; i++) {
    c = (unsigned char)name[i];
    if (c >= 0x61 && c <= 0x7a)
      c = (unsigned char)(c - 32);
    fname[i] = (char)c;
  }
  if (i == 0)
    return CBMDOS_ERR_IO;
  for (; i < 17; i++)
    fname[i] = 0;

  (void)f011_start(drive);
  if (bam_load() != F011_OK) {
    f011_stop();
    return CBMDOS_ERR_IO;
  }

  /* Locate the entry, remembering which directory block held it. */
  for (;;) {
    if (f011_read_block(t, s, (unsigned char *)BLK_BUF) != F011_OK) {
      f011_stop();
      return CBMDOS_ERR_IO;
    }
    nt = BLK_BUF[0];
    ns = BLK_BUF[1];
    for (e = 0; e < 8; e++) {
      if (BLK_BUF[e * 32 + 2] == 0)
        continue;
      wl = 0;
      while (wl < 16 && fname[wl])
        wl++;
      match = 1;
      for (i = 0; i < 16; i++) {
        c = (i < wl) ? (unsigned char)fname[i] : 0xa0;
        if (BLK_BUF[e * 32 + 5 + i] != c) {
          match = 0;
          break;
        }
      }
      if (match) {
        ft = BLK_BUF[e * 32 + 3];
        fs = BLK_BUF[e * 32 + 4];
        dt = t;
        ds = s;
        off = (unsigned char)(e * 32);
        found = 1;
        break;
      }
    }
    if (found || nt == 0)
      break;
    t = nt;
    s = ns;
  }

  if (!found) {
    f011_stop();
    return CBMDOS_ERR_NOTFOUND;
  }

  /* Free the block chain. Bounded by the disk's block count so a corrupt
   * or self-referential chain cannot loop forever. */
  {
    unsigned int guard = 0;
    while (ft && guard < 3200u) {
      if (f011_read_block(ft, fs, (unsigned char *)BLK_BUF) != F011_OK)
        break; /* stop freeing rather than guess; the entry still goes */
      nt = BLK_BUF[0];
      ns = BLK_BUF[1];
      bam_free(ft, fs);
      ft = nt;
      fs = ns;
      guard++;
    }
  }

  /* Clear the directory entry: type 0 marks the slot free. */
  if (f011_read_block(dt, ds, (unsigned char *)BLK_BUF) != F011_OK) {
    f011_stop();
    return CBMDOS_ERR_IO;
  }
  for (i = 2; i < 32; i++)
    BLK_BUF[off + i] = 0;
  if (f011_write_block(dt, ds, (unsigned char *)BLK_BUF) != F011_OK) {
    f011_stop();
    return CBMDOS_ERR_IO;
  }
  if (bam_save() != F011_OK) {
    f011_stop();
    return CBMDOS_ERR_IO;
  }

  f011_stop();
  return CBMDOS_OK;
}

unsigned long cbmdos_load(
    const char *name, unsigned char drive, unsigned long dest, unsigned long maxlen)
{
  unsigned char t, s2, nt, ns;
  unsigned int len;
  unsigned long total = 0;

  (void)f011_start(drive); /* spin-up never completes on a virtual drive */

  if (!dir_find_name(name, &t, &s2)) {
    f011_stop();
    return 0;
  }

  for (;;) {
    if (f011_read_block(t, s2, (unsigned char *)BLK_BUF) != F011_OK) {
      f011_stop();
      return 0;
    }
    nt = BLK_BUF[0];
    ns = BLK_BUF[1];

    /* A non-zero link track means a full block: 254 data bytes after the
     * two link bytes. On the last block the link track is 0 and the
     * "sector" byte is the index of the last byte used. */
    len = nt ? DATA_PER_BLOCK : (unsigned int)(ns > 1 ? ns - 1 : 0);
    if (total + len > maxlen) {
      f011_stop();
      return 0; /* chain longer than the caller allowed for */
    }

    if (len) /* a zero-length DMA copies 64 KB (mega-net PLATFORM.md trap 7): an empty file has a last block of none (ssh 5.30) */
      lcopy((unsigned long)(unsigned int)(BLK_BUF + 2), dest + total, len);
    total += len;

    if (!nt)
      break;
    t = nt;
    s2 = ns;
  }

  f011_stop();
  return total;
}

/* ---- streaming reader ------------------------------------------------ */

static unsigned char rd_t, rd_s, rd_open;

unsigned char cbmdos_open_read(const char *name, unsigned char drive)
{
  unsigned char i;
  for (i = 0; i < 16 && name[i]; i++) {
    unsigned char c = (unsigned char)name[i];
    if (c >= 0x61 && c <= 0x7a)
      c = (unsigned char)(c - 32);
    fname[i] = (char)c;
  }
  for (; i < 17; i++)
    fname[i] = 0;
  rd_open = 0;
  (void)f011_start(drive);
  if (!dir_find_name(fname, &rd_t, &rd_s)) {
    f011_stop();
    return CBMDOS_ERR_NOTFOUND;
  }
  rd_open = 1;
  return CBMDOS_OK;
}

unsigned int cbmdos_read_next(unsigned char *out, unsigned char *err)
{
  unsigned char nt, ns;
  unsigned int len;

  *err = CBMDOS_OK;
  if (!rd_open) { *err = CBMDOS_ERR_NOTOPEN; return 0; }
  if (!rd_t) return 0;                                  /* the end */
  if (f011_read_block(rd_t, rd_s, (unsigned char *)BLK_BUF) != F011_OK) {
    *err = CBMDOS_ERR_IO;
    rd_open = 0;
    f011_stop();
    return 0;
  }
  nt = BLK_BUF[0];
  ns = BLK_BUF[1];
  len = nt ? DATA_PER_BLOCK : (unsigned int)(ns > 1 ? ns - 1 : 0);
  if (len)                                              /* zero-length DMA is 64KB */
    lcopy((unsigned long)(unsigned int)(BLK_BUF + 2), (unsigned long)(unsigned int)out, len);
  rd_t = nt;
  rd_s = ns;
  return len;
}

void cbmdos_close_read(void)
{
  rd_open = 0;
  f011_stop();
}

/* ---- the whole directory ---------------------------------------------- */

static unsigned char dw_next_t, dw_next_s, dw_idx, dw_on;

unsigned char cbmdos_dir_first(unsigned char drive)
{
  (void)f011_start(drive);
  dw_next_t = DIR_TRACK;
  dw_next_s = DIR_FIRST;
  dw_idx = 8;                                           /* nothing loaded yet */
  dw_on = 1;
  return CBMDOS_OK;
}

unsigned char cbmdos_dir_next(char *name, unsigned char *type, unsigned int *blocks)
{
  volatile unsigned char *e;
  unsigned char i, o;

  if (!dw_on) return 0;
  for (;;) {
    if (dw_idx >= 8) {
      if (!dw_next_t) { cbmdos_dir_end(); return 0; }
      if (f011_read_block(dw_next_t, dw_next_s, (unsigned char *)BLK_BUF) != F011_OK) {
        cbmdos_dir_end();
        return 0;
      }
      dw_next_t = BLK_BUF[0];
      dw_next_s = BLK_BUF[1];
      dw_idx = 0;
    }
    e = BLK_BUF + dw_idx * 32;
    dw_idx++;
    if ((e[2] & 0x0f) == 0) continue;                   /* an empty or scratched slot */
    for (i = 0, o = 0; i < 16; i++) {
      unsigned char c = e[5 + i];
      if (c == 0xa0 || c == 0) break;
      name[o++] = (char)c;
    }
    name[o] = 0;
    *type = e[2];
    *blocks = (unsigned int)(e[30] | ((unsigned int)e[31] << 8));
    return 1;
  }
}

void cbmdos_dir_end(void)
{
  if (dw_on) f011_stop();
  dw_on = 0;
}
