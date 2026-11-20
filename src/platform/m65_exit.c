/* Copyright 2026 Justin Cameron
 * SPDX-License-Identifier: Apache-2.0 */
/* Leaving for BASIC.
 *
 * Returning from main() cannot get there: this llvm-mos runtime's exit()
 * is `jsr fini; bra .` (found by disassembling libcrt0.a and by the CPU
 * parked on that branch after Q). And even a return would land in a
 * BASIC whose zero page $02-$8F the program's own zero-page sections
 * sit on top of, which is what the gopher client saw as "break" after
 * every typed line (gopher REQUIREMENTS.md, "Quit to BASIC 65").
 *
 * So the way out is the KERNAL's own reset entry, reached by software:
 * the ROM re-initialises the screen editor, the DOS and BASIC's zero
 * page exactly as at power-on, but Hyppo does not run again, so the
 * disk image mounted from BASIC stays mounted (measured: `RUN` of the client
 * works straight after, no MOUNT). The jump must be made from outside
 * $2000-$BFFF, because mapping the BASIC ROM back over that window
 * hides this program's own code from the CPU (found on hardware: the
 * first attempt did it in place and parked the CPU at $908D in ROM).
 * Hence a stub copied to $1FB0, in the low RAM the platform scratch map
 * lists as spare: clear the MAP, restore $01 and $D030 to the values
 * the runtime's .fini uses, jump through the reset vector.
 *
 * That reset uses the IEC serial bus whenever a disk image is mounted,
 * and here one always is. A drive on the IEC port that is switched off
 * holds the bus lines low, and the ROM waits forever: the banner, a
 * blinking drive light, no READY. Switch the drive on or unplug it
 * (mega-net PLATFORM.md, trap 17).
 *
 * Before that: the 45E100 is held in reset (on this core its events
 * reach the IRQ vector past the enables, mega-net 5.16, and nothing
 * will service them), and the keyboard queue is drained. */
#include <string.h>
#include "mega65/memory.h"
#include "meganet.h"
#include "m65_exit.h"

#define STUB_AT 0x1fb0

static const unsigned char stub[] = {
  0x78,                               /* sei */
  0xa9, 0x00, 0xaa, 0xa8, 0x4b,       /* lda #0 ; tax ; tay ; taz */
  0x5c, 0xea,                         /* map ; eom  -- no MAP anywhere */
  0xa9, 0x3f, 0x85, 0x01,             /* $01 = $3f   (as .fini) */
  0xa9, 0x64, 0x8d, 0x30, 0xd0,       /* $D030 = $64 (as .fini: ROM at $C000 and $E000) */
  0xa9, 0x00, 0x8d, 0x6a, 0xd0,       /* $D06A = 0: the font's bank, after every other write */
  0x6c, 0xfc, 0xff                    /* jmp ($fffc): the KERNAL's reset entry */
};

/* The collection's handoff block, "MNC" at $FF87FF0 (mega-menu/src/handoff.h):
 * its state byte (1-4), or 0 when there is no block. One copy and no
 * inlining: three lpeeks inlined at each use cost Gemini 300 bytes. */
static unsigned char hb[4];
__attribute__((noinline)) static unsigned char handoff_state(void)
{
  lcopy(0xff87ff0UL, (unsigned long)hb, 4);
  return hb[0] == 77 && hb[1] == 78 && hb[2] == 67 ? hb[3] : 0;
}
#define in_collection() (handoff_state() != 0)

/* Launched by the collection's menu: its dispatcher sets RETURN (3) just
 * before running a program. The program before left the ethernet
 * controller running (below), so INIT_WARM can skip the controller reset
 * and the PHY's 3.5 s (mega-net REQUIREMENTS.md 5.23). */
unsigned char m65_launched_from_menu(void)
{
  return handoff_state() == 3;
}

/* For the network's start: hold the controller in reset as always, unless
 * launched from the menu; and the INIT to call after. Functions, not
 * inline tests: the bring-up is inlined into main, and a test there
 * reshaped all of main (Gemini: 280 bytes). */
__attribute__((noinline)) void m65_net_hold(void)
{
  if (handoff_state() != 3) POKE(0xd6e0, 0x00);
}

__attribute__((noinline)) unsigned int m65_net_init_entry(void)
{
  return handoff_state() == 3 ? MEGANET_INIT_WARM : MEGANET_INIT;
}

/* Black between programs (the Net-Tools collection, mega-menu/README.md).
 *
 * The ROM's reset paints the screen and border colour 6 and reloads the
 * palette, so every exit flashed blue until the collection's dispatcher
 * ran and set black. The reset loads the palette into the bank $D070
 * selects for writing and leaves $D070 alone (ROM 920413, read from the
 * image and seen on the machine). So: colour 6 is made black here in
 * bank 3, the one BASIC draws from ($D070 = $FF as the machine starts),
 * and the ROM's writes are sent to bank 0. The dispatcher sets real
 * black, then puts $D070 and the palette back. It has to be bank 3:
 * shown from bank 0 the reset screen stayed blue (the BBS client, which
 * left on bank 0), the ROM's palette setting drawing from 3 regardless.
 *
 * Only when the collection's handoff block is there, since without the
 * dispatcher nothing would put them back. */
static void black_until_dispatch(void)
{
  if (!in_collection()) return;
  POKE(0xd070, 0xff);                                      /* show and write bank 3 */
  POKE(0xd106, 0); POKE(0xd206, 0); POKE(0xd306, 0);
  POKE(0xd070, 0x3f);                                      /* the ROM's writes: bank 0 */
}

void m65_exit_to_basic(void)
{
  unsigned char frames, last;
  /* The ethernet controller: held in reset, unless the collection's
   * dispatcher runs next. Then it is left running, link and all, for the
   * next program's INIT_WARM (mega-net 5.23); BASIC's own handler takes
   * any event it raises meanwhile, as in a BASIC program (mega-net 5.18). */
  if (!in_collection()) POKE(0xd6e0, 0x00);
  /* Settle for half a second, interrupts still on: an event the
   * controller had in flight is taken by the program's own handler, and
   * the key that asked for this is released. The ROM enters its
   * machine-language monitor when RUN/STOP is held at reset (seen in the
   * gopher client, whose exit key was RUN/STOP), so the quit key is Q and
   * the reset waits for fingers anyway. */
  last = PEEK(0xd7fa);
  for (frames = 0; frames < 25; ) {
    if (PEEK(0xd7fa) != last) { last = PEEK(0xd7fa); frames++; }
  }
  while (PEEK(0xd610)) POKE(0xd610, 0);            /* nothing left in the keyboard queue */
  /* The font. conioinit() pointed the character set at the ROM's copy in
   * bank 2 ($D06A = 2) and turned the VIC-IV hot registers off, so the
   * ROM's reset, which rewrites the classic $D018, no longer recomputes
   * that pointer: BASIC came back typing fine into an unreadable screen
   * (measured: the one video register differing from a clean boot).
   * Bank 0 again, and the hot registers on so the ROM's writes count. */
  /* Hot registers first: turning them on can re-derive the font pointer
   * from the classic registers, which undid a bank write made before it
   * (found in the gopher client, whose menu screen left the bank at 2
   * again). So the bank goes to 0 after, and once more inside the stub,
   * last thing before the jump. */
  POKE(0xd05d, (unsigned char)(PEEK(0xd05d) | 0x80));
  POKE(0xd068, 0x00); POKE(0xd069, 0xd8);          /* the ROM's lowercase set again, not the copy at $11000 (5.25) */
  POKE(0xd06a, 0x00);
  black_until_dispatch();
  memcpy((void *)STUB_AT, stub, sizeof stub);
  __asm__ volatile("jmp $1fb0");
  for (;;) ;                                       /* not reached */
}
