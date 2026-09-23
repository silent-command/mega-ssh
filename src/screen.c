#include "mega65/memory.h"
#include "glyph.h"
#include "screen.h"

#define CRAM 0xFF80000UL
uint8_t scr_rows = 25;

void scr_put(uint8_t row, uint8_t col, uint8_t code, uint8_t colour)
{
  uint16_t o = (uint16_t)((uint16_t)row * SCR_COLS + col);
  lpoke(SCR_BASE + o, code);
  lpoke(CRAM + o, colour);
}

void scr_text(uint8_t row, uint8_t col, const char *s, uint8_t colour, uint8_t rev)
{
  uint8_t r = rev ? 0x80 : 0;
  while (*s && col < SCR_COLS) {
    scr_put(row, col, (uint8_t)((uint8_t)m65_ascii_to_screencode(*s) | r), colour);
    s++; col++;
  }
}
