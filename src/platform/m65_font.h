/* The lowercase font in RAM, with the six glyphs ASCII has and the
 * machine's character set lacks drawn in: backslash, caret, backtick,
 * the braces and the tilde. The ROM's set is copied to $11000 (bank 1,
 * which mega-net leaves to the program) and the VIC pointed at it; the
 * six go into graphics codes nothing maps to. Same file in the gopher,
 * FTP and SSH clients. ssh REQUIREMENTS.md 5.25. */
#ifndef M65_FONT_H
#define M65_FONT_H

#define M65_FONT_RAM 0x11000UL

/* After conioinit and setlowercase, before anything is drawn. */
void m65_font_install(void);

/* The screen codes the six live at, for the ASCII mapping. */
#define M65_CODE_BACKSLASH 0x5c
#define M65_CODE_CARET 0x5e
#define M65_CODE_BACKTICK 0x60
#define M65_CODE_LBRACE 0x68
#define M65_CODE_RBRACE 0x69
#define M65_CODE_TILDE 0x6f

#endif
