/* Known hosts: trust on first use. KNOWNHOSTS on the boot disk holds one
 * line per host, "host:port <64 hex digits of the Ed25519 public key>".
 * Loaded once at start; a host accepted at the prompt is appended and
 * the file rewritten. */
#ifndef HOSTS_H
#define HOSTS_H

#include <stdint.h>

#define HOSTS_UNKNOWN 0
#define HOSTS_KNOWN 1
#define HOSTS_CHANGED 2

void hosts_load(unsigned char drive);
/* Compares the 32-byte key against the entry for host:port. */
unsigned char hosts_check(const char *host, unsigned int port, const uint8_t key[32]);
/* Adds host:port with the key and rewrites the file; 1 on success. */
unsigned char hosts_add(const char *host, unsigned int port, const uint8_t key[32]);

#endif
