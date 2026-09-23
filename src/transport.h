/* The SSH transport (RFC 4253) and user authentication (RFC 4252) on
 * mega-net socket 0: version exchange, KEXINIT, curve25519-sha256, an
 * ssh-ed25519 host key checked against KNOWNHOSTS, NEWKEYS,
 * chacha20-poly1305@openssh.com both ways, then a password. Every wait
 * is bounded; the stack is polled throughout, including inside the
 * arithmetic through crypto_yield. */
#ifndef TRANSPORT_H
#define TRANSPORT_H

#include <stdint.h>

#define SSH_SOCK 0
#define SSH_RX_MAX 2048               /* the largest packet accepted; a KEXINIT is about 1.3 KB (5.22) */
#define SSH_TX_MAX 512                /* the largest payload sent: keystrokes, and a KEXINIT of 300 (5.22, 5.27) */
#define SSH_TIMEOUT_FRAMES 1500       /* 30 s of nothing */

/* Message numbers used here. */
#define SSH_MSG_DISCONNECT 1
#define SSH_MSG_IGNORE 2
#define SSH_MSG_UNIMPLEMENTED 3
#define SSH_MSG_DEBUG 4
#define SSH_MSG_SERVICE_REQUEST 5
#define SSH_MSG_SERVICE_ACCEPT 6
#define SSH_MSG_EXT_INFO 7
#define SSH_MSG_KEXINIT 20
#define SSH_MSG_NEWKEYS 21
#define SSH_MSG_KEX_ECDH_INIT 30
#define SSH_MSG_KEX_ECDH_REPLY 31
#define SSH_MSG_USERAUTH_REQUEST 50
#define SSH_MSG_USERAUTH_FAILURE 51
#define SSH_MSG_USERAUTH_SUCCESS 52
#define SSH_MSG_USERAUTH_BANNER 53
#define SSH_MSG_GLOBAL_REQUEST 80
#define SSH_MSG_REQUEST_SUCCESS 81
#define SSH_MSG_REQUEST_FAILURE 82
#define SSH_MSG_CHANNEL_OPEN 90
#define SSH_MSG_CHANNEL_OPEN_CONFIRMATION 91
#define SSH_MSG_CHANNEL_OPEN_FAILURE 92
#define SSH_MSG_CHANNEL_WINDOW_ADJUST 93
#define SSH_MSG_CHANNEL_DATA 94
#define SSH_MSG_CHANNEL_EXTENDED_DATA 95
#define SSH_MSG_CHANNEL_EOF 96
#define SSH_MSG_CHANNEL_CLOSE 97
#define SSH_MSG_CHANNEL_REQUEST 98
#define SSH_MSG_CHANNEL_SUCCESS 99
#define SSH_MSG_CHANNEL_FAILURE 100

/* Errors; ssh_error_text gives words. */
#define SSH_OK 0
#define SSH_E_CONNECT 1
#define SSH_E_TIMEOUT 2
#define SSH_E_CLOSED 3
#define SSH_E_VERSION 4
#define SSH_E_TOOBIG 5
#define SSH_E_PROTOCOL 6
#define SSH_E_ALGORITHM 7
#define SSH_E_HOSTKEY 8
#define SSH_E_MAC 9
#define SSH_E_DISCONNECT 10
#define SSH_E_AUTH 11
#define SSH_E_HOSTCHANGED 12
#define SSH_E_REFUSED 13

extern unsigned char ssh_error;
extern char ssh_reason[80];           /* the server's words, when it gave any */
const char *ssh_error_text(void);

/* The last received message: type and payload (after the type byte). */
extern uint8_t ssh_rx[SSH_RX_MAX];
extern uint16_t ssh_rx_len;           /* payload length including the type byte */
#define ssh_rx_type (ssh_rx[0])

/* A status callback for the long steps ("exchanging keys...") */
extern void (*ssh_status)(const char *what);
/* Called with the host key when the host is new (0) or changed (1);
 * returns 1 to accept. The client shows the fingerprint and asks. */
extern unsigned char (*ssh_ask_hostkey)(const uint8_t key[32], unsigned char changed);

/* Connects and completes the key exchange. Host and port name the
 * known-hosts entry; ip is where to connect. */
unsigned char ssh_connect(const unsigned char ip[4], unsigned int port, const char *host);
/* Password authentication after ssh_connect. */
unsigned char ssh_login(const char *user, const char *password);
/* Public-key login with the Ed25519 identity (seed and public key). */
unsigned char ssh_login_key(const char *user, const uint8_t seed[32], const uint8_t pk[32]);

/* After that: send a message (payload built by the caller, type first)
 * and receive the next one. ssh_recv skips IGNORE/DEBUG/EXT_INFO and
 * answers GLOBAL_REQUESTs, and returns 0 on error or disconnect. */
unsigned char ssh_send(const uint8_t *payload, uint16_t n);
unsigned char ssh_recv(void);
/* Nonzero if a packet is waiting or in progress; polls the stack. */
unsigned char ssh_pending(void);
void ssh_disconnect(void);
void ssh_poll(void);

#endif
