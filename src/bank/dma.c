#include "dma.h"

#define POKE(a, v) (*(volatile uint8_t *)(a) = (uint8_t)(v))
#define PEEK(a) (*(volatile uint8_t *)(a))

static volatile uint8_t job[18] __attribute__((section(".bss.ck_dma_job")));

static void run(uint16_t count)
{
  uint16_t list = (uint16_t)(uintptr_t)job;
  /* The list address registers belong to whoever called us (mega-net
   * REQUIREMENTS.md 5.10): save them, restore them. */
  uint8_t save_msb = PEEK(0xD701), save_bank = PEEK(0xD702), save_mb = PEEK(0xD704);
  job[6] = (uint8_t)(count & 0xff); job[7] = (uint8_t)(count >> 8);
  job[14] = 0x00; job[15] = 0x00; job[16] = 0x00;
  POKE(0xD702, (uint8_t)(CK_PHYS_BASE >> 16));  /* the list is in our own bank */
  POKE(0xD704, (uint8_t)(CK_PHYS_BASE >> 20));
  POKE(0xD701, (uint8_t)(list >> 8));
  POKE(0xD705, (uint8_t)(list & 0xff));
  POKE(0xD702, save_bank);
  POKE(0xD704, save_mb);
  POKE(0xD701, save_msb);
}

void ck_dma_fill(uint32_t dst, uint8_t value, uint16_t count)
{
  if (!count) return;                            /* a zero-length job is 64 KB */
  job[0] = 0x80; job[1] = 0x00;
  job[2] = 0x81; job[3] = (uint8_t)(dst >> 20);
  job[4] = 0x00;
  job[5] = 0x03;                                 /* fill: the source's low byte is the value */
  job[8] = value; job[9] = 0; job[10] = 0;
  job[11] = (uint8_t)(dst & 0xff); job[12] = (uint8_t)((dst >> 8) & 0xff); job[13] = (uint8_t)((dst >> 16) & 0x0f);
  run(count);
}

void ck_dma_copy(uint32_t src, uint32_t dst, uint16_t count)
{
  if (!count) return;                            /* a zero-length job is 64 KB */
  job[0] = 0x80; job[1] = (uint8_t)(src >> 20);
  job[2] = 0x81; job[3] = (uint8_t)(dst >> 20);
  job[4] = 0x00;
  job[5] = 0x00;
  job[8] = (uint8_t)(src & 0xff); job[9] = (uint8_t)((src >> 8) & 0xff); job[10] = (uint8_t)((src >> 16) & 0x0f);
  job[11] = (uint8_t)(dst & 0xff); job[12] = (uint8_t)((dst >> 8) & 0xff); job[13] = (uint8_t)((dst >> 16) & 0x0f);
  run(count);
}
