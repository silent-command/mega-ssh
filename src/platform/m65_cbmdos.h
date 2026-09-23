/* Minimal CBM DOS writer for 1581 / .d81 images, on top of m65_f011.c.
 *
 * Streaming, because an article can reach ~316KB and cannot be buffered:
 *
 *   cbmdos_create("NAME", drive);
 *   cbmdos_put(b);   ... for every byte ...
 *   cbmdos_close();
 *
 * Scope deliberately narrow:
 *   - allocates across the whole disk: tracks 1-39 and 41-80, skipping
 *     the directory track. Both BAM sectors are held, so capacity is
 *     3160 blocks (~782KB) rather than the ~387KB of the first sector
 *     alone.
 *   - reuses free slots in the existing directory chain; it does not
 *     extend the chain, and reports a full directory instead.
 */
#ifndef M65_CBMDOS_H
#define M65_CBMDOS_H

#define CBMDOS_OK 0
#define CBMDOS_ERR_IO 1        /* an F011 read or write failed */
#define CBMDOS_ERR_FULL 2      /* no free blocks */
#define CBMDOS_ERR_DIRFULL 3   /* no free directory slot */
#define CBMDOS_ERR_NOTOPEN 4   /* put/close without a successful create */
#define CBMDOS_ERR_EXISTS 5    /* a file of that name is already there */
#define CBMDOS_ERR_NOTFOUND 6  /* delete: no such file */
#define CBMDOS_ERR_PROT 7      /* the disk is write protected */

/* CBM file types, as they appear in a directory entry: bit 7 set means
 * "closed", i.e. not left open by a crash. */
#define CBMDOS_TYPE_SEQ 0x81
#define CBMDOS_TYPE_PRG 0x82

/* Opens a new file of a given type. PRG matters for downloads: LOAD reads
 * the first two bytes of a PRG as its load address, so labelling arbitrary
 * data as PRG makes LOAD scatter it. Only mark a file PRG when it really
 * is one. */
unsigned char cbmdos_create_as(const char *name, unsigned char drive,
                               unsigned char type);

/* Opens a new sequential file. `name` is used as given, upper-cased and
 * padded internally; at most 16 characters. */
unsigned char cbmdos_create(const char *name, unsigned char drive);

/* Appends one byte. */
unsigned char cbmdos_put(unsigned char b);

/* Finalises: writes the last block, the directory entry and the BAM. */
unsigned char cbmdos_close(void);

/* Blocks written so far, for reporting. */
unsigned int cbmdos_blocks(void);

/* Removes a file: frees its blocks in the BAM and clears its directory
 * entry. Returns CBMDOS_ERR_NOTFOUND if there is no such name. Needed
 * because cbmdos_create refuses duplicates, so rewriting a file (the
 * config, for instance) means deleting it first. */
unsigned char cbmdos_delete(const char *name, unsigned char drive);

/* Streams a file's contents from `drive` to a 28-bit destination address,
 * following its block chain. Returns bytes loaded, or 0 if the file was
 * not found or a sector could not be read. `maxlen` bounds the transfer
 * so a corrupt chain cannot run away over memory it should not touch. */
unsigned long cbmdos_load(
    const char *name, unsigned char drive, unsigned long dest, unsigned long maxlen);


/* Streaming reader, the mirror of create/put/close: opens a file by name
 * and hands back its data one block at a time (up to 254 bytes per call)
 * for an upload that cannot hold the whole file. Returns CBMDOS_OK,
 * CBMDOS_ERR_NOTFOUND or CBMDOS_ERR_IO. */
unsigned char cbmdos_open_read(const char *name, unsigned char drive);

/* Next block's data into `out` (at least 254 bytes). Returns the count,
 * 0 at the end of the file or on error; *err says which. */
unsigned int cbmdos_read_next(unsigned char *out, unsigned char *err);
void cbmdos_close_read(void);

/* The whole directory chain, one entry per call: cbmdos_dir_first, then
 * cbmdos_dir_next until it returns 0, or cbmdos_dir_end to stop early.
 * `name` needs 17 bytes; `type` is the raw type byte (bit 7 = closed,
 * low nibble 1 SEQ, 2 PRG, 3 USR, 4 REL). */
unsigned char cbmdos_dir_first(unsigned char drive);
unsigned char cbmdos_dir_next(char *name, unsigned char *type, unsigned int *blocks);
void cbmdos_dir_end(void);

/* Diagnostic: reads the first directory block of `drive` so the entries can
 * be listed. Boot failures have twice turned out to be the wrong disk image
 * mounted rather than a fault in the loader, and the only way to tell from
 * the machine itself is to see what the mounted disk actually contains. */
unsigned char cbmdos_dir_open(unsigned char drive);

/* Formats entry `idx` (0-7) of that block into `out` as "NAME  nnn", at most
 * 23 characters plus a NUL. Returns 0 for an unused slot. */
unsigned char cbmdos_dir_get(unsigned char idx, char *out);

#endif
