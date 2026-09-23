/* Puts the machine back the way BASIC expects before main() returns:
 * ethernet controller quiet, keyboard queue empty, ROM map and VIC-IV hot
 * registers restored, screen editor re-initialised through the KERNAL.
 * See m65_exit.c for what each step answers. */
#ifndef M65_EXIT_H
#define M65_EXIT_H

void m65_exit_to_basic(void);

#endif
