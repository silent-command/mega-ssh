/* Bringing the link up and turning a host name into an address. */
#ifndef NETUTIL_H
#define NETUTIL_H

/* Loads mega-net, runs DHCP. Returns 0 with a message in *err. */
unsigned char net_up(const char **err);

/* Dotted quad or DNS. Returns 0 with a message in *err. */
unsigned char net_resolve(const char *host, unsigned char *ip, const char **err);


/* Loads of the network image attempted: 1 when it came first time. */
extern unsigned char net_load_tries;

#endif
