/* Copyright 2026 Justin Cameron
 * SPDX-License-Identifier: Apache-2.0 */
/* The fixed low-RAM scratch the CBM DOS and screen modules expect. */
#include "m65_scratch.h"
char scr_save_result[64];
char scr_save_suggest[17];
char scr_dos_name[17];
char scr_dos_line[80];
