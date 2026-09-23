/* The cell screen: 80 columns of screen codes at $10000 (bank 1, below
 * the crypto image, where 50 rows fit: at $0800 they would run over the
 * trampolines at $1600), colours at $FF80000, written directly, so the
 * console library's output routines and their 765-byte escape buffer
 * stay out of the link. 25 or 50 rows, whichever the machine was in when
 * the program started (5.23). The terminal has its own copy of this in
 * the bank (src/bank/termscr.c). */
#ifndef SCREEN_H
#define SCREEN_H

#include <stdint.h>

#define SCR_COLS 80
#define SCR_BASE 0x10000UL
extern uint8_t scr_rows;              /* 25 or 50, set before anything is drawn */

/* One cell: a screen code (bit 7 reverses it) and a colour 0-15. */
void scr_put(uint8_t row, uint8_t col, uint8_t code, uint8_t colour);
/* ASCII text, translated to screen codes, stopping at NUL or column 80. */
void scr_text(uint8_t row, uint8_t col, const char *s, uint8_t colour, uint8_t rev);

#endif
