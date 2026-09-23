/* Keys, lines and prompts on the 80-column screen, from the FTP client.
 * Every wait in here polls the stack, so a connection stays alive while
 * the user thinks. */
#ifndef UI_H
#define UI_H

/* Codes as the MEGA65 keyboard queue ($D610) delivers them. */
#define KEY_NONE 0
#define KEY_STOP 3
#define KEY_RETURN 13
#define KEY_HOME 19
#define KEY_DEL 20
#define KEY_DOWN 17
#define KEY_UP 145
#define KEY_RIGHT 29
#define KEY_LEFT 157
#define KEY_TAB 9
#define KEY_ESC 27
#define KEY_HELP 0x1f
#define KEY_CLR 0x93                  /* SHIFT + HOME */
#define KEY_INS 0x94                  /* SHIFT + DEL */
#define KEY_F1 0xf1                   /* F1..F14 are $F1..$FE */

/* Modifier bits in $D611, read alongside a key. */
#define MOD_SHIFT 0x03
#define MOD_CTRL 0x04
#define MOD_MEGA 0x08
#define MOD_ALT 0x10

#include "screen.h"
#define UI_ROW_TITLE 0
#define UI_ROW_STATUS ((unsigned char)(scr_rows - 2))
#define UI_ROW_KEYS ((unsigned char)(scr_rows - 1))
#define UI_ROW_LAST_BODY ((unsigned char)(scr_rows - 3))

/* ui_read_line: 1 RETURN, 0 RUN/STOP, 2 F1 (only the Host prompt acts on it; the rest take the line). */
extern char ui_scratch[81];          /* a line being built: prompts, lists, fingerprints; never two at once */
unsigned char ui_key(void);          /* the next key, or KEY_NONE; never waits */
unsigned char ui_key_mods(unsigned char *mods);   /* the same, with the modifiers held */
unsigned char ui_wait_key(void);     /* waits, polling; ui_idle runs once per frame */
void ui_flush_keys(void);

/* Runs once per video frame inside every wait; the browser uses it to
 * keep the control connection alive. May be null. */
extern void (*ui_idle)(void);

/* Writes `a` then `b` (either may be null) padded to the full row. */
void ui_line(unsigned char row, const char *a, const char *b);
void ui_line_rev(unsigned char row, const char *a, const char *b);   /* highlighted */
void ui_status(const char *a, const char *b);
void ui_clear_rows(unsigned char from, unsigned char to);

/* Line editor at `row`. `out` holds a default and receives the result;
 * RETURN keeps the default, typing replaces it, INST/DEL edits it.
 * `maxlen` excludes the NUL. With `hide`, echoes asterisks. Returns 0 on
 * STOP, 1 on RETURN (the line may be empty; the caller decides whether
 * that is allowed). */
unsigned char ui_read_line(unsigned char row, const char *prompt, char *out,
                           unsigned char maxlen, unsigned char hide);

/* One character in the top-right corner, stepped every eighth call. */
void ui_spin(void);
void ui_spin_clear(void);

void ui_put_ulong(char *p, unsigned long v);       /* decimal, NUL terminated */
void ui_put_size(char *p, unsigned long v);        /* "123456" or "1234K", right-aligned in 7 */

#endif
