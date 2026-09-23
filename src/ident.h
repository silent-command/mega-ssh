/* The client's identity for public-key authentication: an Ed25519 seed
 * and its public key, 64 bytes in IDENTITY on the boot disk, made on the
 * machine from the client's own randomness. The default authentication
 * method the user last chose is one byte in SSHAUTH. REQUIREMENTS.md 5.22. */
#ifndef IDENT_H
#define IDENT_H

#include <stdint.h>

extern uint8_t ident_seed[32], ident_pk[32];
extern unsigned char ident_present;               /* IDENTITY was on the disk, or was just made */
extern char ident_auth;                            /* 'p' password (the default) or 'i' identity */

void ident_load(unsigned char drive);              /* IDENTITY and SSHAUTH, if present */
unsigned char ident_generate(void);                /* a fresh seed from the randomness, the key, the file; 1 on success */
unsigned char ident_set_auth(char method);         /* remembers 'p' or 'i' in SSHAUTH; 1 on success */
/* The public key as OpenSSH writes it, without the "ssh-ed25519 " prefix:
 * base64 of the key blob, 68 characters. */
void ident_public_b64(char *out);
/* The fingerprint as OpenSSH shows it: base64 of SHA-256 of the blob, 43 characters. */
void ident_fingerprint_b64(char *out);

#endif
