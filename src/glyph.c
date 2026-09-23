#include "glyph.h"
#include "m65_font.h"

/* Map one ASCII byte to a screen code, substituting anything we cannot
 * safely display.
 *
 * Text off the network is arbitrary bytes, not ASCII: real gopherpedia
 * articles carry UTF-8 (so bytes >= 0x80) and stray control codes. These
 * used to be passed straight through to screen memory, which corrupted
 * the display and hung the client when a text file was opened. Anything
 * outside the printable ASCII range is now shown as '.' -- a wrong glyph
 * is a cosmetic problem, an unfiltered byte is a crash. */

/* Fold UTF-8 text down to one displayable byte per character.
 *
 * Gopherpedia serves UTF-8, so an accented letter is two bytes. The
 * byte-wise sanitiser turned each of those into '.', which is why
 * "Muhren" appeared as "M..hren" -- two dots for one character. Decoding
 * first means one substitution per character, and letters that have an
 * obvious unaccented form are shown as that letter rather than as a dot.
 *
 * Folding happens before storage so stored line lengths match what is
 * displayed, which keeps truncation and paging honest.
 *
 * Returns the number of bytes written (excluding the terminator). */
/* Latin-1 $C0-$FF to the unaccented letter, '.' where there is none. */
static const char latin1[64] = {
  'A','A','A','A','A','A','A','C','E','E','E','E','I','I','I','I',
  '.','N','O','O','O','O','O','.','O','U','U','U','U','Y','.','s',
  'a','a','a','a','a','a','a','c','e','e','e','e','i','i','i','i',
  '.','n','o','o','o','o','o','.','o','u','u','u','u','y','.','y'
};

/* Latin-1 punctuation $A1-$BF: the nearest ASCII, '.' where there is none. */
static const char latin1_punct[31] = {
  '!', 'c', 'L', '.', 'Y', '|', '.', '.', 'c', '.', '<', '-', '-', 'r', '-',
  'o', '+', '2', '3', '\'', 'u', '.', '.', ',', '1', '.', '>', '.', '.', '.', '?'
};

char m65_fold_codepoint(unsigned int cp)
{
  if (cp >= 0xc0 && cp <= 0xff) return latin1[cp - 0xc0];
  if (cp >= 0xa1 && cp <= 0xbf) return latin1_punct[cp - 0xa1];   /* an oh-my-zsh prompt's >> was two dots (5.10) */
  if (cp == 0xa0) return 0x20;                     /* nbsp */
  if (cp == 0x2190) return '<';                    /* the arrows, plain and heavy */
  if (cp == 0x2191) return '^';
  if (cp == 0x2192 || (cp >= 0x2794 && cp <= 0x279f)) return '>';
  if (cp == 0x2193) return 'v';
  if (cp == 0x2713 || cp == 0x2714) return '*';    /* tick */
  if (cp == 0x2717 || cp == 0x2718) return 'x';    /* cross */
  if (cp == 0x2018 || cp == 0x2019) return 0x27;   /* curly quotes -> ' */
  if (cp == 0x201c || cp == 0x201d) return 0x22;   /* curly quotes -> " */
  if (cp == 0x2013 || cp == 0x2014) return 0x2d;   /* en/em dash -> - */
  if (cp == 0x2026) return 0x2e;                   /* ellipsis -> . */
  if (cp == 0x2022) return 0x2a;                   /* bullet -> * */
  if (cp == 0x266a || cp == 0x266b) return 'n';    /* notes, as late.sh's radio shows them (5.22) */
  if (cp == 0x25cb || cp == 0x25e6 || cp == 0x25ef) return 'o';   /* circles */
  if (cp == 0x2605 || cp == 0x2606) return '*';    /* stars */
  if (cp == 0x263d) return ')';                    /* the moon, both ways */
  if (cp == 0x263e) return '(';
  if (cp == 0x039b) return 'A';                    /* lambda */
  return 0x2e;                                     /* anything else we cannot draw */
}

char m65_ascii_to_screencode(char c)
{
  unsigned char u = (unsigned char)c;

  if (u >= 0x41 && u <= 0x5a) /* 'A'-'Z' */
    return (char)u;
  if (u >= 0x61 && u <= 0x7a) /* 'a'-'z' -> screen codes 1-26 */
    return (char)(u - 96);
  if (u >= 0x20 && u <= 0x3f) /* space, digits, common punctuation */
    return (char)u;
  /* Punctuation above 'Z' is NOT screen code = ASCII. In this charset
   * $40/$5b/$5d are the graphics glyphs horizontal-line, '+' and '|', so
   * passing ASCII straight through printed "[DIR]" as "+DIR|" on every
   * menu line and an email address as "mega65<line>use...". Confirmed by
   * PNG capture from hardware, not by the ASCII screenshot round-trip,
   * which maps these back and hides the fault. */
  if (u == 0x40) /* '@' */
    return (char)0x00;
  if (u == 0x5b) /* '[' */
    return (char)0x1b;
  if (u == 0x5d) /* ']' */
    return (char)0x1d;
  if (u == 0x5f) /* '_': no true underscore exists; $64 is a low bar */
    return (char)0x64;
  if (u == 0x5e) /* '^': a caret of its own now (5.25) */
    return (char)M65_CODE_CARET;
  if (u == 0x7c) /* '|' -> the vertical bar at $5d (what ']' used to hit) */
    return (char)0x5d;
  /* '\\', '`', '{', '}' and '~' have no glyph in the ROM's set; the font
   * in RAM draws them, and the caret, at these codes (m65_font.c, 5.25). */
  if (u == 0x5c) return (char)M65_CODE_BACKSLASH;
  if (u == 0x60) return (char)M65_CODE_BACKTICK;
  if (u == 0x7b) return (char)M65_CODE_LBRACE;
  if (u == 0x7d) return (char)M65_CODE_RBRACE;
  if (u == 0x7e) return (char)M65_CODE_TILDE;
  return 0x2e; /* '.' for control codes, high-bit bytes, everything else */
}
