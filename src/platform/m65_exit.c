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
 * Before that: the 45E100 is held in reset (on this core its events
 * reach the IRQ vector past the enables, mega-net 5.16, and nothing
 * will service them), and the keyboard queue is drained. */
#include <string.h>
#include "mega65/memory.h"
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

void m65_exit_to_basic(void)
{
  unsigned char frames, last;
  POKE(0xd6e0, 0x00);                              /* ethernet controller: held in reset */
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
  memcpy((void *)STUB_AT, stub, sizeof stub);
  __asm__ volatile("jmp $1fb0");
  for (;;) ;                                       /* not reached */
}
