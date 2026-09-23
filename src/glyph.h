/* Glyphs: what one character becomes on this machine's screen. Shared
 * by the client (its prompts) and the bank (the terminal), so it is
 * compiled into both images. From the FTP client's screen module. */
#ifndef GLYPH_H
#define GLYPH_H

/* One ASCII byte to a screen code; anything the charset lacks is a dot. */
char m65_ascii_to_screencode(char c);

/* One Unicode code point to the ASCII byte that best stands in for it:
 * accented letters to their base, typographic punctuation to the plain
 * kind, anything else to a dot. */
char m65_fold_codepoint(unsigned int cp);

#endif
