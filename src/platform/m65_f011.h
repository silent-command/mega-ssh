/* Direct F011 floppy controller access.
 *
 * Exists because the KERNAL route does not work from this program: it
 * needs interrupts, interrupts need ROM mapped over our own code and
 * data, and the 45E100 storms the moment interrupts are enabled. See
 * REQUIREMENTS.md 2.11-2.17 for the seven hypotheses tested and
 * eliminated.
 *
 * F011 sidesteps all of it: no KERNAL, no interrupts, no banking changes.
 * The MEGA65 chipset reference documents the registers, and states that
 * this sequence works for D81 images mounted from the SD card as well as
 * for physical disks -- which is what device 8 is here.
 *
 * Every wait is bounded. A hang inside disk code is unrecoverable on this
 * machine and cost a great deal of time already.
 */
#ifndef M65_F011_H
#define M65_F011_H

/* 512-byte physical sector buffer. It lived at $1600 while .bss was full;
 * that page is now mega-net's trampoline (mega-net REQUIREMENTS.md 5.10),
 * and .bss has room again since the stack image is streamed from disk. */
#ifdef F011_BUF_AT
#define f011_buf ((volatile unsigned char *)F011_BUF_AT)   /* a build's own low-RAM address for it (irc step 3) */
#else
extern volatile unsigned char f011_buf[512];
#endif
#define F011_BUF f011_buf

#define F011_OK 0
#define F011_ERR_SPINUP 1  /* motor never came ready */
#define F011_ERR_RDREQ 2   /* sector never found */
#define F011_ERR_DATA 3    /* transfer did not complete */
#define F011_ERR_RNF 4     /* record not found */
#define F011_ERR_CRC 5     /* CRC failure */
#define F011_ERR_PROT 6    /* disk is write protected */

/* Selects and spins up a drive: 0 is the internal/first image (device 8),
 * 1 the second (device 9). The selection persists for subsequent reads
 * and writes, which is why it lives here rather than being passed to
 * every call -- $d080 carries drive select, motor and side together, and
 * the transfer routines rewrite it. Returns an F011_* code. */
unsigned char f011_start(unsigned char drive);

/* Stops the motor. */
void f011_stop(void);



/* Reads one 512-byte physical sector into F011_BUF.
 * track 0-79, side 0-1, sector 1-10. Returns an F011_* code. */
unsigned char f011_read_sector(
    unsigned char track, unsigned char side, unsigned char sector);

/* Writes F011_BUF back to one 512-byte physical sector. */
unsigned char f011_write_sector(
    unsigned char track, unsigned char side, unsigned char sector);

/* --- CBM logical blocks ----------------------------------------------
 *
 * A D81 is 80 tracks x 40 sectors x 256 bytes as CBM DOS sees it, laid
 * over 80 physical tracks x 2 sides x 10 sectors x 512 bytes. So one
 * physical sector holds two consecutive CBM blocks:
 *
 *   physical track  = cbm_track - 1        (CBM tracks are 1-based)
 *   side            = cbm_sector / 20
 *   physical sector = (cbm_sector % 20) / 2 + 1
 *   half            = cbm_sector % 2       (which 256 bytes)
 *
 * Writing a block is therefore read-modify-write of the physical sector.
 */
#define CBM_BLOCK_LEN 256
#define CBM_DIR_TRACK 40

/* Reads CBM block (track 1-80, sector 0-39) into `dst` (256 bytes). */
unsigned char f011_read_block(
    unsigned char cbm_track, unsigned char cbm_sector, unsigned char *dst);

/* Writes 256 bytes from `src` into CBM block (track, sector). */
unsigned char f011_write_block(
    unsigned char cbm_track, unsigned char cbm_sector, const unsigned char *src);

/* 1 if that F011 drive is backed by a disk image on the SD card, 0 if it
 * is a real floppy drive. Reads $D68B (D0IMG / D1IMG). */
unsigned char f011_drive_is_image(unsigned char drive);

#endif
