/* The terminal's screen primitives: the five calls through which
 * everything in term.c reaches the cells. They live in the bank's main
 * region (LTO, with the DMA helpers) so the parser alone has to fit
 * the 6 KB window at $E000. The host test supplies its own five. */
#ifndef TERMSCR_H
#define TERMSCR_H
#include <stdint.h>
uint8_t sc_peek(uint16_t o);
void sc_poke(uint16_t o, uint8_t v);
void fill_both(uint16_t o, uint8_t code, uint8_t colour, uint16_t n);
void copy_both(uint16_t from, uint16_t to, uint16_t n);
void move_cells(uint16_t from, uint16_t to, uint8_t n);
#endif
