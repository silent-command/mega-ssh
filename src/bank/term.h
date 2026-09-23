/* The terminal, in the bank: a VT100 (with the xterm additions programs
 * actually use) on the 80x25 cell screen at $10000, 25 or 50 rows, with
 * colours at $FF80000, both reached by DMA. The client hands it the
 * host's bytes through ck_term_write. It answers no queries: a reply
 * from a 12 KB/s terminal arrives after the host stopped waiting.
 *
 * Handled: the C0 controls; cursor movement, absolute and relative;
 * erase in line and display; insert and delete of lines and characters;
 * scroll regions; SGR colours, bold and reverse; save and restore
 * cursor; the alternate screen as a clear; application cursor keys;
 * the DEC line-drawing set and the Unicode box-drawing block, mapped to
 * the machine's own graphics; other UTF-8 folded to a base letter or a
 * dot. Ignored, quietly: titles, mouse modes, bracketed paste, blink,
 * underline, 256-colour and truecolour beyond their nearest of sixteen.
 * REQUIREMENTS.md section 4, step 6. */
#ifndef BANK_TERM_H
#define BANK_TERM_H

#include <stdint.h>

#define TERM_COLS 80
#define TERM_ROWS_MAX 50                /* 25 or 50 rows, chosen at term_init (5.23) */

void term_init(uint8_t text_colour, uint8_t bg_colour, uint8_t rows);
void term_end(void);   /* restore $D021 and turn the extended attributes off */
void term_recolour(uint8_t text_colour, uint8_t bg_colour);   /* live local colours (5.20) */
void term_write(const uint8_t *p, uint16_t n);
/* Shows or hides the cursor (a reversed cell). The host can also hide it
 * (DECTCEM); then term_cursor(1) draws nothing until it is shown again. */
void term_cursor(uint8_t on);

/* Set when the host asked for application cursor keys (DECCKM). */
extern uint8_t term_app_cursor;

#endif
