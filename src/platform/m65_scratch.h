/* Fixed-address working buffers in verified-free low RAM.
 *
 * The program's .bss has no room for these: with the disk layer wired in
 * it overflows. They therefore live below the load address ($2001), in
 * two regions confirmed free on hardware by writing a pattern and
 * checking it survived a full DHCP bring-up, menu fetch and article load
 * with zero bytes changed:
 *
 *   $1400-$15ff   512 bytes   (freed when the KERNAL writer was removed)
 *   $1a00-$1bff   512 bytes
 *
 * Between them, $1600-$16ff is mega-net's trampoline (the F011 sector
 * buffer, once at $1600, is in .bss now) and $1800-$19ff the
 * CBM DOS BAM and block buffers, so this file owns the two outer regions
 * only.
 *
 * A previous attempt aliased these onto the network stack's embedded
 * payload, which is dead after m65_boot_load() copies it to bank 4. That was a
 * mistake twice over: writing through a `const` object is undefined and
 * LTO folded the reads straight back to the payload bytes, painting them
 * on the screen; and making the payload non-const cost so much
 * optimisation that only 123 bytes of stack remained, below the measured
 * 133-byte peak.
 *
 * Constant addresses also generate better code here than .bss arrays --
 * .text fell by over 5KB when these moved.
 */
#ifndef M65_SCRATCH_H
#define M65_SCRATCH_H

/* These four are ordinary .bss arrays, NOT fixed addresses.
 *
 * They used to live at $1000-$10cf, described here as "verified free".
 * They were not. $1000 holds BASIC 65's function-key definition table
 * (DIR, "DIR \"*=PRG\"", KEY6, MONITOR, HELP, RUN "*") and $1060-$10ff
 * holds live 6502 code. Dumped from hardware to confirm.
 *
 * The collision was invisible while nothing re-initialised that area, so
 * saving to drive 8 worked for weeks. It surfaced on a failing save,
 * where the ROM rewrote the fkey table between the strcpy of the error
 * prefix and the strcat of the filename, and the status line came out as
 * `.....DIR."*=PRG"..KEY6..MONITOR..PROXY`.
 *
 * The fixed-address scheme existed only because .bss had no room. Since
 * the network stack stopped being embedded (REQUIREMENTS.md 2.29) there are ~21KB
 * free below the stack, so these 178 bytes belong in .bss where the
 * linker can guarantee they are nobody else's. The regions from $1400 up
 * were verified differently -- by writing a pattern and re-reading it
 * after a full DHCP bring-up, menu fetch and article load -- and stay put
 * for now. */
extern char scr_save_result[64];
extern char scr_save_suggest[17];
extern char scr_dos_name[17];
extern char scr_dos_line[80];
#define SCR_SAVE_RESULT scr_save_result
#define SCR_SAVE_SUGGEST scr_save_suggest
#define SCR_DOS_NAME scr_dos_name
#define SCR_DOS_LINE scr_dos_line

/* Sizes are given explicitly because these are pointers, not arrays:
 * sizeof() on them is 2, which silently truncated every bounded copy
 * that used it. */
#define SCR_LINE_LEN 160
#define SCR_URLBUF_LEN 128
#define SCR_UILINE_LEN 100
#define SCR_XLATE_LEN 81
#define SCR_SLINE_LEN 80

#define SCR_MENU_LINE ((char *)0x1400)  /* 160 */
#define SCR_TEXT_LINE ((char *)0x14a0)  /* 160 */
#define SCR_ITEM_REC ((unsigned char *)0x1540) /* 160 */
/* $15e0-$15ff spare */
#define SCR_URLBUF ((char *)0x1a00)  /* 128 */
#define SCR_URLBUF2 ((char *)0x1a80) /* 128 */
#define SCR_UILINE ((char *)0x1b00)  /* 100 */
/* $1b64-$1bff spare */

/* $1c00-$1fff, verified free the same way. */
#define SCR_XLATE ((char *)0x1c00)   /* 81  */
#define SCR_SLINE ((char *)0x1c60)   /* 80  */
#define SCR_HOME_LOC ((struct location *)0x1cc0)    /* 115 */
#define SCR_CUR_LOC ((struct location *)0x1d40)     /* 115 */
/* DNS cache: 4 entries of 37 bytes. Declared as a type here so the
 * module can point at fixed RAM instead of .bss. */
struct dns_cache_entry {
  char host[32];
  unsigned char ip[4];
  unsigned char used;
};
#define SCR_DNS_CACHE ((struct dns_cache_entry *)0x1dc0) /* 148 */
#define SCR_FOLDED ((char *)0x1e60)   /* 72: menu display folding  */
#define SCR_FOLDBUF ((char *)0x1eb0)  /* 80: text line folding     */
#define SCR_COMBINED ((char *)0x1f00) /* 81: search selector+query */
#define SCR_SHOWN ((char *)0x1f60)  /* 80: read_line echo buffer */
/* $1fb0-$1fff spare */

/* Second region leftovers */
#define SCR_VIEWLINE ((char *)0x1b64) /* 80: pager line */
/* $1bb4-$1bff spare */

#endif
