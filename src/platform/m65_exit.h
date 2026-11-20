/* Copyright 2026 Justin Cameron
 * SPDX-License-Identifier: Apache-2.0 */
/* Puts the machine back the way BASIC expects before main() returns:
 * ethernet controller quiet, keyboard queue empty, ROM map and VIC-IV hot
 * registers restored, screen editor re-initialised through the KERNAL.
 * See m65_exit.c for what each step answers. */
#ifndef M65_EXIT_H
#define M65_EXIT_H

void m65_exit_to_basic(void);

/* 1 if the Net-Tools menu launched this program: the network controller
 * is then left running for INIT_WARM (mega-net 5.23). */
unsigned char m65_launched_from_menu(void);
void m65_net_hold(void);                 /* $D6E0 = 0, unless launched from the menu */
unsigned int m65_net_init_entry(void);   /* MEGANET_INIT_WARM if launched from the menu, else MEGANET_INIT */

#endif
