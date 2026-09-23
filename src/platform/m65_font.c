#include "mega65/memory.h"
#include "m65_font.h"

#define ROM_LOWERCASE 0x2D800UL          /* what setlowercase() points the VIC at */

/* Drawn in the set's own style, read from the character ROM: diagonals
 * and verticals two pixels wide (half that on the 80-column screen),
 * horizontals one. The codes are graphics the clients never map to. */
static const unsigned char glyphs[6][9] = {
  { M65_CODE_BACKSLASH, 0x00, 0x60, 0x30, 0x18, 0x0c, 0x06, 0x03, 0x00 },   /* the slash, mirrored */
  { M65_CODE_CARET,     0x18, 0x3c, 0x66, 0x00, 0x00, 0x00, 0x00, 0x00 },   /* the arrow's head alone */
  { M65_CODE_BACKTICK,  0x60, 0x30, 0x18, 0x00, 0x00, 0x00, 0x00, 0x00 },   /* the apostrophe, mirrored */
  { M65_CODE_LBRACE,    0x0e, 0x18, 0x18, 0x70, 0x18, 0x18, 0x0e, 0x00 },
  { M65_CODE_RBRACE,    0x70, 0x18, 0x18, 0x0e, 0x18, 0x18, 0x70, 0x00 },
  { M65_CODE_TILDE,     0x00, 0x00, 0x00, 0x32, 0x4c, 0x00, 0x00, 0x00 }    /* on the hyphen's rows */
};

void m65_font_install(void)
{
  unsigned char i, j;
  lcopy(ROM_LOWERCASE, M65_FONT_RAM, 2048);
  for (i = 0; i < 6; i++)
    for (j = 0; j < 8; j++)
      lpoke(M65_FONT_RAM + (unsigned long)glyphs[i][0] * 8 + j, glyphs[i][j + 1]);
  POKE(0xd068, M65_FONT_RAM & 0xff); POKE(0xd069, (M65_FONT_RAM >> 8) & 0xff); POKE(0xd06a, (M65_FONT_RAM >> 16) & 0xff);
}
