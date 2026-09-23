#include <stdint.h>
#include "dma.h"
#include "termscr.h"

#define POKE(a, v) (*(volatile uint8_t *)(a) = (uint8_t)(v))
#define PEEK(a) (*(volatile uint8_t *)(a))
#define PHYS(p) ((uint32_t)(uintptr_t)(p) + CK_PHYS_BASE)
#define SCREEN 0x10000UL              /* bank 1 below the image: not a CPU address from here, so every access is DMA (5.23) */
#define COLRAM 0xFF80000UL
#define COLS 80

static uint8_t scratch[COLS] __attribute__((section(".bss.term_scratch")));

uint8_t sc_peek(uint16_t o) { ck_dma_copy(SCREEN + o, PHYS(scratch), 1); return scratch[0]; }
void sc_poke(uint16_t o, uint8_t v) { scratch[0] = v; ck_dma_copy(PHYS(scratch), SCREEN + o, 1); }

void fill_both(uint16_t o, uint8_t code, uint8_t colour, uint16_t n)
{
  if (!n) return;                                 /* a zero-length DMA is 64 KB */
  ck_dma_fill(SCREEN + o, code, n);
  ck_dma_fill(COLRAM + o, colour, n);
}

void copy_both(uint16_t from, uint16_t to, uint16_t n)
{
  if (!n) return;
  ck_dma_copy(SCREEN + from, SCREEN + to, n);
  ck_dma_copy(COLRAM + from, COLRAM + to, n);
}

/* Within a row, in either direction: a rightward move overlaps itself
 * and the DMA copies ascending, so it goes through a row of scratch. */
void move_cells(uint16_t from, uint16_t to, uint8_t n)
{
  if (!n) return;
  if (to <= from) { copy_both(from, to, n); return; }
  ck_dma_copy(SCREEN + from, PHYS(scratch), n); ck_dma_copy(PHYS(scratch), SCREEN + to, n);
  ck_dma_copy(COLRAM + from, PHYS(scratch), n); ck_dma_copy(PHYS(scratch), COLRAM + to, n);
}
