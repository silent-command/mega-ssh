/* The crypto trampoline: a raw binary at $1700, the page after mega-net's
 * trampoline. Pure assembly: no C runtime, no libraries. */
MEMORY { ram (rwx) : ORIGIN = 0x1700, LENGTH = 0x100 }
SECTIONS { .text : { KEEP(*(.text)) } > ram }
OUTPUT_FORMAT { TRIM(ram) }
