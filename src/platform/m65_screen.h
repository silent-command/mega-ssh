/* 80-column screen setup, from the FTP client, which had it from the
 * gopher client. See REQUIREMENTS.md section 7 of the gopher client for
 * why each step in m65_screen_init exists: skipping any of them causes
 * screen corruption (bad screen RAM placement) or a visual 40-column
 * wrap despite 80-column pixel mode (missing row-width register pokes).
 *
 * Text output is not here any more: the SSH client writes screen codes
 * straight into screen memory through screen.c, both for its prompts
 * and for the terminal, so the console library's output routines stay
 * out of the link. What remains of it is the mode setup and the colours. */
#ifndef M65_SCREEN_H
#define M65_SCREEN_H

void m65_screen_init(void);
/* 25 or 50: the rows the machine was showing when the program started (5.23). */
unsigned char m65_screen_rows(void);

#include "glyph.h"

/* Colour handling: border and background are inherited from whatever the
 * user had set before running (the program never writes $d020/$d021), and
 * the text colour starts white, which is what the machine itself shows. */
unsigned char m65_screen_text_colour(void);
unsigned char m65_screen_bg_colour(void);
void m65_screen_cycle_text_colour(void);

/* Advances background and border together, keeping them identical. */
void m65_screen_cycle_background(void);

#endif
