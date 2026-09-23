/* Bookmarks: SSHMARKS on the disk the client booted from, the shape the
 * FTP client's FTPC.CFG has. A line "SSHM1", then four lines per entry:
 * host, port, the method (p or i), user. No passwords. The text stays in
 * bank 1 above the font copy and is read field by field into the
 * caller's buffers. REQUIREMENTS.md 5.27. */
#ifndef MARKS_H
#define MARKS_H

#define MARKS_MAX 8
#define MARKS_NONE 0xff

extern unsigned char marks_count;
/* Scratch for one entry's fields, shared with the host screen's list. */
extern char marks_h[64], marks_p[6], marks_m[2], marks_u[32];

void marks_load(unsigned char drive);
unsigned char marks_get(unsigned char i, char *host, char *port_s, char *method, char *user);
unsigned char marks_find(const char *host, const char *port_s, const char *method, const char *user);
unsigned char marks_add(const char *host, const char *port_s, const char *method, const char *user);
unsigned char marks_remove(unsigned char i);

#endif
