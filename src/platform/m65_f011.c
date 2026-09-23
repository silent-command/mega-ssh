#include "mega65/memory.h"
#include "m65_f011.h"

#define F011_CTRL (*(volatile unsigned char *)0xd080)
#define F011_CMD (*(volatile unsigned char *)0xd081)
#define F011_STAT_A (*(volatile unsigned char *)0xd082)
#define F011_STAT_B (*(volatile unsigned char *)0xd083)
#define F011_TRACK (*(volatile unsigned char *)0xd084)
#define F011_SECTOR (*(volatile unsigned char *)0xd085)
#define F011_SIDE (*(volatile unsigned char *)0xd086)
#define F011_DATA (*(volatile unsigned char *)0xd087)

/* SD controller command register. $57 opens the write gate for every
 * sector above 0 for roughly a millisecond; $4d is the separate gate for
 * the master boot record, which nothing here should ever touch. The gate
 * exists to stop stray writes corrupting the card, and closes again on
 * its own, so it is opened immediately before commanding the write. */
#define SD_CTL (*(volatile unsigned char *)0xd680)
#define SD_OPEN_WRITE_GATE 0x57

/* The controller's 512-byte sector buffer, memory mapped.
 *
 * Transfers go through this rather than streaming bytes via $d087. The
 * byte-at-a-time path relies on an internal buffer pointer, and nothing
 * in the documented sequence resets it before a write -- so a write
 * issued after a read began part-way through the buffer and stored the
 * data displaced. That is exactly what was seen on disk: valid BAM
 * entries sitting about seven bytes off.
 *
 * BUFSEL (bit 7 of $d689) must be clear so this is the floppy buffer and
 * not the SD card's; the two are aliased into the same window. */
#define F011_SECBUF 0xffd6c00UL
#ifndef F011_BUF_AT
volatile unsigned char f011_buf[512];
#endif                                /* else the header names a fixed address: a client that has spare low RAM and none in .bss (irc step 3) */

#define F011_BUFSEL (*(volatile unsigned char *)0xd689)

/* $d082 */
#define ST_BUSY 0x80
#define ST_DRQ 0x40
#define ST_EQ 0x20
#define ST_RNF 0x10
#define ST_CRC 0x08
/* $d083 */
#define ST_RDREQ 0x80
#define ST_DISKIN 0x08 /* media sense */

#define ST_PROT 0x02   /* $d082: write protected */
#define ST_WTREQ 0x40  /* $d083: sector found for writing */

#define FRAMECOUNT (*(volatile unsigned char *)0xd7fa)

/* How long to allow a real drive. ~3s at 50Hz covers motor spin-up, a
 * full-stroke auto-tune seek and at least one revolution. */
#define FDC_WAIT_FRAMES 150

/* Waits until (reg & mask) == want. Returns 0 on timeout.
 *
 * Paced on the frame counter, NOT a spin count. The original bound was
 * 60000 poll iterations -- roughly 12ms at 40MHz. That is ample for a
 * mounted .d81, which the hypervisor services instantly, and hopeless for
 * a real drive: a floppy turns at 300rpm, so a sector can take a full
 * 200ms revolution to come under the head, and the auto-tune seek
 * (enabled by default, $D696 bit 7 clear) may step across many tracks
 * first. Saving to a mounted image always worked and saving to the
 * internal drive always failed, for exactly this reason.
 *
 * The spin cap is a backstop for $D7FA stalling, which has bitten this
 * project before: without it a dead frame counter would hang here. */
static unsigned char fdc_wait(volatile unsigned char *reg, unsigned char mask,
                              unsigned char want)
{
  unsigned char last = FRAMECOUNT;
  unsigned char frames = 0;
  unsigned char wraps = 0;
  unsigned int spins = 0;
  unsigned char cur;

  for (;;) {
    if ((*reg & mask) == want)
      return 1;
    cur = FRAMECOUNT;
    if (cur != last) {
      last = cur;
      if (++frames >= FDC_WAIT_FRAMES)
        return 0;
    }
    if (++spins == 0 && ++wraps >= 200)
      return 0; /* frame counter stalled; bail on raw iterations instead */
  }
}

static unsigned char wait_not_busy(void)
{
  return fdc_wait(&F011_STAT_A, ST_BUSY, 0);
}

/* Spin-up keeps the old short bound deliberately.
 *
 * Against a mounted image BUSY never clears after SPINUP -- measured,
 * $d082 reads $b0 -- so a generous wait here would add seconds to every
 * operation on the common path for no benefit. A real drive that has not
 * finished spinning up is handled anyway: the read or write that follows
 * waits on RDREQ/WTREQ with the full allowance above, which covers the
 * motor reaching speed. */
static unsigned char wait_not_busy_briefly(void)
{
  unsigned int i;

  for (i = 0; i < 60000u; i++)
    if (!(F011_STAT_A & ST_BUSY))
      return 1;
  return 0;
}


/* $D68B: D0IMG is bit 0, D1IMG is bit 3. Set means that drive is served
 * by a disk image on the SD card; clear means real media. */
#define F011_IMGCTL (*(volatile unsigned char *)0xd68b)

/* Which physical side holds a track's first twenty logical sectors.
 *
 * A .d81 and a real disk disagree, which is why every image test passed
 * while the floppy failed. Surveyed on hardware: on a real 1581 disk the
 * directory track's header and BAM sit on physical side 1 -- side 1
 * sector 1 begins $28, the link byte pointing at track 40 -- while side 0
 * reads back as all zeros. The hypervisor's image emulation maps them the
 * other way round, and the ROM agrees with the disk: BASIC reads this
 * same sector with $D080 bit 3 set.
 *
 * So the side is chosen from the drive's own mode rather than assumed. */
unsigned char f011_drive_is_image(unsigned char drive)
{
  return (unsigned char)(drive ? ((F011_IMGCTL >> 3) & 1)
                               : (F011_IMGCTL & 1));
}

static unsigned char side_for(unsigned char ds, unsigned char logical_side)
{
  unsigned char is_image = f011_drive_is_image(ds);

  return (unsigned char)(is_image ? logical_side : (1 - logical_side));
}

/* Selected drive, folded into every $d080 write. */
static unsigned char f011_ds = 0;

unsigned char f011_start(unsigned char drive)
{
  unsigned char ok;

  f011_ds = (unsigned char)(drive & 0x07);
  F011_CTRL = (unsigned char)(0x60 | f011_ds); /* motor on, LED, drive */
  F011_CMD = 0x20;  /* SPINUP */

  /* Reported but NOT treated as fatal. Against a mounted D81 the drive is
   * virtualised by the hypervisor and there is no physical motor to come
   * up to speed: measured, BUSY stays set after SPINUP and $d082 reads
   * $b0 (BUSY|EQ|RNF), which for a real drive would be a failure and here
   * appears to mean nothing at all. The read is attempted regardless. */
  ok = wait_not_busy_briefly();


  return ok ? F011_OK : F011_ERR_SPINUP;
}

void f011_stop(void)
{
  F011_CTRL = 0x00;
}


unsigned char f011_write_sector(
    unsigned char track, unsigned char side, unsigned char sector)
{
  volatile unsigned char *src = F011_BUF;
  unsigned int i;
  unsigned char st;

  F011_CTRL = (unsigned char)(0x60 | f011_ds | (side ? 0x08 : 0x00));

  /* Fill the controller's buffer through its memory mapping, not through
   * $d087: see the note by F011_SECBUF. The byte-at-a-time variant ($85)
   * is discouraged anyway for SD-backed and virtualised images, where the
   * transfer completes instantly. */
  (void)i;
  F011_BUFSEL = (unsigned char)(F011_BUFSEL & 0x7f); /* floppy buffer */
  lcopy((unsigned long)(unsigned int)src, F011_SECBUF, 512);

  F011_TRACK = track;
  F011_SECTOR = sector;
  F011_SIDE = side;

  /* A write-protected disk reports it here rather than failing obscurely
   * further on. Only meaningful for real media; a mounted image reads
   * this as clear. */
  if (F011_STAT_A & ST_PROT)
    return F011_ERR_PROT;

  SD_CTL = SD_OPEN_WRITE_GATE;
  /* Same NOBUF bit as the read. This is also the real explanation for the
   * displaced writes recorded in 2.26, which were worked around by using
   * the memory-mapped buffer rather than fixed at source. */
  F011_CMD = 0x85; /* write sector, resetting the buffer pointers */

  /* Wait for the sector to come under the head before waiting for the
   * transfer, the write-side counterpart of RDREQ. On a real drive this
   * is where the revolution is spent. */
  if (!fdc_wait(&F011_STAT_B, ST_WTREQ, ST_WTREQ))
    return F011_ERR_RNF;

  if (!wait_not_busy())
    return F011_ERR_DATA;

  st = F011_STAT_A;
  if (st & ST_RNF)
    return F011_ERR_RNF;
  if (st & ST_CRC)
    return F011_ERR_CRC;

  return F011_OK;
}

/* One attempt. Callers go through f011_read_sector, which retries. */
static unsigned char read_sector_once(
    unsigned char track, unsigned char side, unsigned char sector)
{
  volatile unsigned char *out = F011_BUF;
  unsigned int i;
  unsigned char st;

  /* Side is selected by bit 3 of the control register and takes effect
   * immediately; it is also written to the SIDE register below, which is
   * what the sector header is matched against. */
  F011_CTRL = (unsigned char)(0x60 | f011_ds | (side ? 0x08 : 0x00));

  F011_TRACK = track;
  F011_SECTOR = sector;
  F011_SIDE = side;

  /* $01 is NOBUF, which the reference defines as "Reset the sector buffer
   * read/write pointers" -- not "do not use the buffer", as the name
   * suggests. Without it the pointer stays wherever the previous
   * operation left it, so a real drive's incoming bytes overflow the
   * buffer and are dropped: measured on hardware as LOST set with DRQ and
   * EQ clear and the buffer still empty, on a disk BASIC could read
   * perfectly well. A virtualised image is unaffected because the
   * hypervisor fills the buffer directly, which is why every test against
   * a mounted .d81 passed. */
  F011_CMD = 0x41; /* read sector, resetting the buffer pointers */

  /* Wait for the sector to be found.
   *
   * RNF is not tested inside this loop: it was already set on entry from
   * the SPINUP that a virtualised drive does not service, so treating it
   * as an error here would reject every read. It is checked after the
   * transfer instead, where it reflects this command. */
  if (!fdc_wait(&F011_STAT_B, ST_RDREQ, ST_RDREQ)) {
    return F011_ERR_RDREQ;
  }

  /* Then for the whole sector to land in the controller's buffer. */
  if (!wait_not_busy()) {
    return F011_ERR_DATA;
  }

  st = F011_STAT_A;
  if (st & ST_RNF)
    return F011_ERR_RNF;
  if (st & ST_CRC)
    return F011_ERR_CRC;

  (void)i;
  F011_BUFSEL = (unsigned char)(F011_BUFSEL & 0x7f); /* floppy buffer */
  lcopy(F011_SECBUF, (unsigned long)(unsigned int)out, 512);

  return F011_OK;
}

/* --- CBM logical block access ---------------------------------------- */

/* Retrying read.
 *
 * Real media is marginal in a way a disk image never is. Surveyed on
 * hardware, the same sector on the same disk read cleanly on one pass and
 * timed out on the next, with the drive spinning throughout. One attempt
 * per sector is simply not how a floppy is read -- the ROM retries too,
 * which is why BASIC could list a disk this driver could not.
 *
 * Retries cost nothing on a mounted image, where the first attempt always
 * succeeds. */
#define F011_READ_TRIES 6

unsigned char f011_read_sector(
    unsigned char track, unsigned char side, unsigned char sector)
{
  unsigned char err = F011_ERR_RDREQ;
  unsigned char try;

  for (try = 0; try < F011_READ_TRIES; try++) {
    err = read_sector_once(track, side, sector);
    if (err == F011_OK)
      return F011_OK;
    /* Let the disk turn before trying again: a retry issued immediately
     * lands in the same place on the track and fails the same way. */
    {
      unsigned char last = FRAMECOUNT, n = 0;
      while (n < 12) {
        if (FRAMECOUNT != last) {
          last = FRAMECOUNT;
          n++;
        }
      }
    }
  }
  return err;
}

unsigned char f011_read_block(
    unsigned char cbm_track, unsigned char cbm_sector, unsigned char *dst)
{
  volatile unsigned char *buf = F011_BUF;
  unsigned int off;
  unsigned int i;
  unsigned char err;

  err = f011_read_sector((unsigned char)(cbm_track - 1),
      side_for(f011_ds, (unsigned char)(cbm_sector / 20)),
      (unsigned char)(((cbm_sector % 20) / 2) + 1));
  if (err != F011_OK)
    return err;

  off = (unsigned int)(cbm_sector & 1) * CBM_BLOCK_LEN;
  for (i = 0; i < CBM_BLOCK_LEN; i++)
    dst[i] = buf[off + i];
  return F011_OK;
}

unsigned char f011_write_block(
    unsigned char cbm_track, unsigned char cbm_sector, const unsigned char *src)
{
  volatile unsigned char *buf = F011_BUF;
  unsigned char track = (unsigned char)(cbm_track - 1);
  unsigned char side = side_for(f011_ds, (unsigned char)(cbm_sector / 20));
  unsigned char sect = (unsigned char)(((cbm_sector % 20) / 2) + 1);
  unsigned int off;
  unsigned int i;
  unsigned char err;

  /* Read-modify-write: a CBM block is half a physical sector, so the
   * other half has to be preserved. */
  err = f011_read_sector(track, side, sect);
  if (err != F011_OK)
    return err;

  off = (unsigned int)(cbm_sector & 1) * CBM_BLOCK_LEN;
  for (i = 0; i < CBM_BLOCK_LEN; i++)
    buf[off + i] = src[i];

  return f011_write_sector(track, side, sect);
}
