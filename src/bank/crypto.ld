/* The crypto bank: a raw, headerless image in bank 1 at physical
 * $12000, executed with bank 1 mapped over CPU $2000-$BFFF (and its top
 * 8 KB, $1E000-$1FFFF, over $E000-$FFFF for the interrupt vectors in
 * force during a call). The same shape as mega-net's image in bank 4,
 * for the same reasons (mega-net REQUIREMENTS.md 5.7, 5.10, 5.11).
 *
 * $2000-$BDFF is code and data; $BE00-$BFFF the bank's own soft stack;
 * $E000-$F7FF, the top of the bank, holds the terminal's parser
 * (src/bank/term.c), which arrived when the rest was already full. It
 * is a second image, TERM, loaded to $1E000. The window ends at $F7FF
 * because physical $1F800-$1FFFF is the 2 KB colour RAM mirror: the
 * first TERM image reached $FE61 and every colour write erased its
 * tail (REQUIREMENTS.md 5.7). The vectors at $FFF0 sit in that mirror
 * too, past the 2000 cells of an 80x25 screen, which is why they
 * survive. term.o is compiled without LTO so the linker script can
 * name it. */
MEMORY {
    ram (rw) : ORIGIN = 0x2000, LENGTH = 0x9E00
    hi (rwx) : ORIGIN = 0xE000, LENGTH = 0x1800
}

/* Zero page $70-$FF, swapped with the caller's on every call, as
 * mega-net does with $90-$FF. The prologue saves this whole range on
 * entry and restores it on exit, so it nests inside the client (which
 * keeps full zero page) exactly as mega-net's trampoline nests inside
 * either: each saves what it finds and puts it back. The bank needs
 * about 110 bytes for the frames the compiler keeps in zero page. */
__rc0 = 0x70;
INCLUDE imag-regs.ld
MEMORY { zp : ORIGIN = __rc31 + 1, LENGTH = 0x100 - (__rc31 + 1) }

REGION_ALIAS("c_readonly", ram)
REGION_ALIAS("c_writeable", ram)

__stack = 0xC000;

SECTIONS {
    .jumptable : { KEEP(*(.jumptable)) } > ram
    /* The terminal's parser in the top window; its tables and the colour
     * matching, which only SGR reaches, in the main region, where the
     * hashes' rotates made room (5.22). */
    .text.lo : { *term.o(.text.nearest .text.chan_d .text.colour256 .text.cube .text.m65_of) } > ram
    .text.hi : { *term.o(.text .text.*) } > hi
    INCLUDE c.ld
}

/* The whole first region, then the second trimmed: build.py splits the
 * file at 0x9E00 into CRYPTO and TERM. */
OUTPUT_FORMAT { FULL(ram) TRIM(hi) }
