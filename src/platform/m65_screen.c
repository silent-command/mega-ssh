#include "mega65/memory.h"
#include "m65_screen.h"
#include "m65_font.h"

static unsigned char start_border = 6;
static unsigned char start_bg = 6;
static unsigned char start_text = 1;
/* Set once m65_screen_init() has inherited the machine's colours; from
 * then on this program is the authority, not the hardware registers. */
static unsigned char colours_known = 0;
static unsigned char rows = 25;

unsigned char m65_screen_rows(void) { return rows; }

/* Pushes the background and border out to the hardware; the text colour
 * is this module's own, read by whoever draws. */
static void apply_colours(void)
{
  POKE(0xd021, start_bg);
  POKE(0xd020, start_border);
}

void m65_screen_init(void)
{
  /* What the console library's conioinit and setscreensize did, by
   * register, so none of the library links: its output routines are not
   * used and their 765-byte escape buffer was the room the SSH client
   * needed (5.27). The VIC-IV I/O personality; the hot registers off,
   * so the classic registers stop recomputing the ones set below; the
   * keyboard queue emptied. */
  POKE(0xd02f, 0x47); POKE(0xd02f, 0x53);
  POKE(0xd05d, PEEK(0xd05d) & 0x7f);
  while (PEEK(0xd610)) POKE(0xd610, 0);

  /* The rows the machine was in: the ROM's 80x50 (ESC 5) sets the
   * display-rows register to 49. Kept, so a 50-row user gets 50; the
   * screen itself moves to $10000, where 4000 cells fit below the
   * crypto image and clear of the trampolines at $1600 (5.23). mega-net
   * keeps its socket buffers at $50000-$5E8FF, so nothing of ours goes
   * there. 80 columns is the H640 bit and the horizontal position the
   * library compensates; 50 rows is the V400 bit. */
  rows = (PEEK(0xd07b) == 49) ? 50 : 25;
  POKE(0xd031, PEEK(0xd031) | 0x80); POKE(0xd04c, 0x50);
  if (rows == 50) POKE(0xd031, PEEK(0xd031) | 0x08); else POKE(0xd031, PEEK(0xd031) & 0xf7);
  POKE(0xd060, 0x00); POKE(0xd061, 0x00); POKE(0xd062, 0x01);
  POKE(0xd063, PEEK(0xd063) & 0xf0);
  m65_font_install();                              /* the lowercase font with \ ^ ` { } ~ drawn in (5.25) */

  /* With the hot registers off, the H640 flip alone does not recalculate
   * these row-width registers; by hand. */
  POKE(0xd058, 80);
  POKE(0xd059, 0);
  POKE(0xd05e, 80);

  /* Establish the colours once.
   *
   * This function is called again after every disk write, which tears the
   * 80-column mode down, so anything decided here must not be re-decided
   * later -- doing so discarded whatever the user had chosen with F.
   *
   * Border and background ARE inherited: the program has never set them,
   * and PEEK from inside the program reads them accurately (blue on blue,
   * matching what the ROM leaves).
   *
   * The text colour is NOT inherited. This used to read $0286, on the
   * assumption that the MEGA65 ROM keeps the current text colour there.
   * It does not. Measured at the BASIC 65 prompt: the screen plainly
   * shows white text, while $0286 reads 14 (light blue) -- and other
   * values at other times, which is why the client started light grey or
   * light blue depending on what had run before. White is what the
   * machine itself displays, so start there. */
  if (!colours_known) {
    start_border = PEEK(0xd020) & 0x0f;
    start_bg = PEEK(0xd021) & 0x0f;
    start_text = 1;                                /* white, what the machine itself shows */
    /* Never start invisible, however odd the inherited background is. */
    if (start_text == start_bg)
      start_text = (unsigned char)((start_text + 1) & 0x0f);
    colours_known = 1;
  }

  apply_colours();
  lfill(0x10000UL, 0x20, 4000); lfill(0xff80000UL, start_text, 4000);   /* clear: 50 rows' worth, either mode */
}

unsigned char m65_screen_text_colour(void)
{
  return start_text;
}

unsigned char m65_screen_bg_colour(void)
{
  return start_bg;
}

void m65_screen_cycle_text_colour(void)
{
  start_text = (unsigned char)((start_text + 1) & 0x0f);
  /* Skip the background colour, or the text would vanish. */
  if (start_text == start_bg)
    start_text = (unsigned char)((start_text + 1) & 0x0f);
  apply_colours();
}

/* Advance background and border together, keeping them identical.
 *
 * The border is set from the background rather than tracked separately:
 * the point is that the two always match, so the screen reads as one
 * surface. Skips the current foreground for the same reason the
 * foreground cycle skips the background -- otherwise text disappears. */
void m65_screen_cycle_background(void)
{
  /* The first press goes to black unless the background is black already
   * (the machine boots blue, and a first press wants dark far more often
   * than the next colour up, yellow); the rotation continues from there. */
  static unsigned char pressed;
  if (!pressed && start_bg != 0) start_bg = 0;
  else start_bg = (unsigned char)((start_bg + 1) & 0x0f);
  pressed = 1;
  if (start_bg == start_text)
    start_bg = (unsigned char)((start_bg + 1) & 0x0f);
  start_border = start_bg; /* they are kept identical; see above */
  apply_colours();
}
