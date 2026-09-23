#ifndef M65_BOOT_H
#define M65_BOOT_H

/* Loads mega-net's image and the far-call trampoline from the boot disk
 * into the fixed addresses they run at, so the program can be run on
 * its own. Returns 1 on success, 0 on failure (with *err pointing at a
 * short reason). Must be called before any meganet_call(). */
unsigned char m65_boot_load(const char **err);

/* F011 drive number (0 or 1, i.e. device 8 or 9) that ETHBIN was loaded
 * from. Only meaningful after a successful m65_boot_load(). */
extern unsigned char boot_drive;


/* The kit's meganet_own_vectors(): first thing in main (5.8; mega-net 5.18). */
void m65_own_vectors(void);


#endif
