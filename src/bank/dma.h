/* DMAgic copy between 28-bit addresses, for the bank: the caller's
 * memory is hidden while the bank is mapped, so every byte in or out
 * moves this way. mega-net's mn_dma.c, with this bank's base. */
#ifndef DMA_H
#define DMA_H
#include <stdint.h>
#define CK_PHYS_BASE 0x10000UL          /* the bank: CPU $2000 is physical $12000 */
void ck_dma_copy(uint32_t src, uint32_t dst, uint16_t count);
void ck_dma_fill(uint32_t dst, uint8_t value, uint16_t count);
#endif
