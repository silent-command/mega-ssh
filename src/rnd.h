/* Random bytes from timing jitter, hashed. See rnd.c for what it is and
 * is not. */
#ifndef RND_H
#define RND_H

#include <stdint.h>

void rnd_init(void);                  /* about a second of sampling */
void rnd_stir(uint8_t v);             /* fold in a keystroke or an event */
void rnd_fill(uint8_t *out, unsigned n);

#endif
