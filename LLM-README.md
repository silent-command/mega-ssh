# mega-ssh

An SSH client for the [MEGA65](https://mega65.org): a real SSH-2
transport with modern cryptography, written in C for llvm-mos, running
in native MEGA65 mode on the [mega-net](../mega-net) stack, with a
VT100 on the 80-column screen. It logs into OpenSSH with a password or
an Ed25519 key made on the machine, and it runs vim, top and a
full-screen chat client.

**Status: in use.** Verified on hardware against the Mac's OpenSSH, an
asyncssh test server with adversarial variants, and a public service
that authenticates by key. Connect to shell in about twenty seconds.
One disk, `SSH.D81`, carries the client, the stack and the crypto.

## Using it

Mount the disk and `RUN "SSH"`. The host screen asks for a host, a
port, the authentication method (`p` for a password, `i` for the
identity on the disk; the choice is remembered), a user name, and a password if password authentication is selected. The first connection to a host shows
its key's fingerprint and asks whether to trust it; the answer is
kept in `KNOWNHOSTS` on the disk, and a host whose key changes later
is refused with a warning.

Bookmarks are listed under the prompts; MEGA+M in a session adds the
current host, or removes it. They live in `SSHMARKS` on the disk, without
passwords, eight at most.

F1 at the Host prompt is the identity screen. G makes an Ed25519 key
on the machine and saves it in `IDENTITY`; the screen shows the public
key as OpenSSH writes it and its fingerprint, which `ssh-keygen -lf`
confirms. Put that line in a server's `authorized_keys` and log in
with `i`. R replaces the key.

If the machine is in its 80x50 mode when the client starts, the
session is 80x50.

On the host screen:

| Key | Does |
|---|---|
| RETURN | accept the line |
| INST/DEL | delete a character |
| RUN/STOP | back to the previous prompt; at the Host prompt, leave for BASIC |
| F1 | the identity screen: G makes a key, R replaces it, any other key returns |
| a number | open that bookmark: the prompts fill in, only the password is asked |
| D and a number | delete that bookmark |
| Y | at the fingerprint prompt, trust this host |

In a session every key goes to the host except the three the host
never needs:

| Key | Does |
|---|---|
| HELP | end the session |
| MEGA + F | next text color |
| MEGA + B | next background and border color (the first press: black) |
| MEGA + M | bookmark this host, port, method and user, or remove the bookmark if it is one; the border flashes once for saved, twice for removed, three times for no room |

What the host receives:

| Key | Sent as |
|---|---|
| letters, digits, punctuation | themselves, including the characters the MEGA65 keyboard reaches through SHIFT and ← |
| RETURN | carriage return |
| INST/DEL | DEL (127) |
| SHIFT + INST/DEL | Insert |
| cursor keys | the arrow sequences, application mode when the host asks |
| HOME, SHIFT + HOME | Home, End |
| CTRL + letter | the control character |
| RUN/STOP | Control-C |
| ESC, TAB | themselves |
| F1 to F4 | PF1 to PF4 |
| F5 to F12 | F5 to F12 |

```
python3 build.py test     the crypto suite and the terminal suite on the host
python3 build.py          the client, the crypto bank, and bin/SSH.D81
python3 tools/deploy.py   SSH.D81 onto the MEGA65 over serial, keeping IDENTITY, SSHAUTH and KNOWNHOSTS
```

The build needs [llvm-mos](https://llvm-mos.org), CMake, `c1541` from
VICE, Python 3, and two sibling checkouts: `../mega-net` and
`../mega65-libc` (github.com/MEGA65/mega65-libc). `tools/deploy.py`
matters: replacing the disk with a plain copy loses the identity, and
the identity is your account on a key-authenticated server.

Symbols the C64 keyboard never had, on the keys the MEGA65 gives them:

| Symbol | Key |
|---|---|
| `\` | `£` |
| `^` | `↑` |
| `{` `}` | MEGA with `:` and `;` (SHIFT there gives `[` and `]`) |
| `\|` | MEGA with `/` |
| `~` | MEGA with `←` (SHIFT there gives the backtick) |

## What it speaks

The client implements SSH-2 as the RFCs define it, with one algorithm
of each kind: the ones every current OpenSSH offers by default. The
negotiation is real, so a server that lacks one is refused with the
reason on screen rather than silently downgraded.

| Layer | Standard | What the client does |
|---|---|---|
| Transport | RFC 4253 | Version exchange, KEXINIT negotiation, NEWKEYS, binary packet protocol, sequence numbers, DISCONNECT with the reason shown. IGNORE, DEBUG, EXT_INFO and UNIMPLEMENTED are skipped; a GLOBAL_REQUEST is answered with failure. |
| Key exchange | `curve25519-sha256`, RFC 8731, and its `@libssh.org` alias | X25519 over the exchange, SHA-256 for the exchange hash and the key derivation of RFC 4253 7.2. |
| Strict key exchange | `kex-strict-c-v00@openssh.com` | Offered; when the server answers with its half, sequence numbers reset at NEWKEYS as the extension requires, which closes the Terrapin class of attacks. |
| Host key | `ssh-ed25519`, RFC 8709 | The server's signature over the exchange hash is verified with Ed25519, RFC 8032, before anything is trusted. |
| Host key policy | Trust on first use | The SHA-256 fingerprint of the raw key is shown on the first connection and kept per host and port in `KNOWNHOSTS`; a changed key is refused. |
| Encryption and integrity | `chacha20-poly1305@openssh.com`, OpenSSH's `PROTOCOL.chacha20poly1305` | Two ChaCha20 keys per direction, the packet length encrypted separately, a Poly1305 tag over the whole packet, the sequence number as the nonce. RFC 8439 primitives. No separate MAC and no compression, by design of the AEAD. |
| Authentication | RFC 4252 | `password` (section 8), and `publickey` (section 7) with an `ssh-ed25519` signature over the session id and the request. Banners are shown; a request for a new password is reported. |
| Connection | RFC 4254 | One `session` channel: `pty-req` with `TERM=vt100` and the screen's size, `shell`, data both ways with stderr merged, window adjustment (a 4 KB window and 1 KB packets, so the server never sends more than the client can hold), EOF, close, `exit-status`. Requests from the server are refused, channel opens likewise. |
| Cryptography | RFC 7748, RFC 8032, RFC 8439, FIPS 180-4 | X25519, Ed25519 signing and verification, ChaCha20, Poly1305, SHA-256 and SHA-512, written here from the RFCs and proved against their published test vectors on the host before running on the machine. |

Not implemented, and refused rather than faked: RSA and ECDSA host
keys, AES and HMAC suites, compression, certificates,
keyboard-interactive login, agents, port forwarding, X11, SFTP and
SCP. Re-keying is not implemented either: OpenSSH asks for one after
an hour or a gigabyte, and a session will end there. Constant time is
not a goal; the threat on this machine is not a local side channel.

## The terminal

A VT100 with the parts of ECMA-48 and xterm that programs actually
use, proved on the host by a suite of 47 checks and by replaying
captured sessions (`tests/term_replay.c`) before hardware:

- Cursor addressing, relative moves, erase in line and display, insert
  and delete of lines and characters, scroll regions, save and restore
  cursor, the alternate screen, application cursor keys, tabs.
- SGR: sixteen colors, bold as bright, reverse, underline and blink
  through the VIC-III extended attributes, and 256-color and truecolor
  sequences mapped to the nearest of the machine's sixteen, so a
  ratatui or ncurses program comes out in color. The screen background
  is yours, inherited from BASIC or cycled with MEGA+B, and a host's
  background is drawn per cell as reverse video where it differs, since
  `$D021` is the one background the VIC has.
- The DEC line-drawing set and the Unicode box-drawing and block
  elements, mapped to the machine's own graphics; UTF-8 decoded and
  folded to a base letter where the set has no glyph. A copy of the
  ROM font in RAM adds backslash, caret, backtick, the braces and the
  tilde, which the set lacks.
- Queries are deliberately unanswered: a reply from a 12 KB/s terminal
  arrives after the host has stopped waiting, and vim once entered
  replace mode on a late one.
- 25 or 50 rows, whichever mode the machine was in at start.

## How it fits, and how it is fast enough

A MEGA65 program has 44 KB of RAM below the I/O area, a 6502-family
CPU with no 32-bit registers, and a compiler that expands every
64-bit operation inline. SSH needs a 255-bit field, two hash
functions, an AEAD cipher, the transport, a terminal and a network
stack. The findings in `REQUIREMENTS.md` record how each piece was
made to fit; the summary:

**The memory: three programs in one machine.** The client proper,
prompts, transport and channel, is a native program at `$2001`. The
cryptography and the terminal parser live in bank 1 as a second
headerless image with a jump table at its first bytes, reached through
a trampoline in one page of bank 0. The trampoline saves the caller's
zero page, switches to the bank's own soft stack, maps the bank over
`$2000-$BFFF` and its top over `$E000-$FFFF`, and puts everything back
on return, so the client keeps its whole zero page and never sees a
key. Parameters cross as 28-bit pointers to blocks the bank reads by
DMA through a staging buffer; contexts and keys stay in the bank by
slot. The terminal parser sits in the bank's top window, above the
crypto and below the color RAM mirror at `$1F800`, which ate the
first attempt. The screen itself moved to `$10000` and the font copy
to `$11000`, both in the same bank below the image. mega-net is a
third image in bank 4 with its buffers in bank 5, reached the same
way. Nothing overlaps, and `tools/sizes.py` says where every byte is.

**The arithmetic: no 64-bit, and the hardware multiplier.** The first
build of the field arithmetic in TweetNaCl's 64-bit form was 43 KB of
code. It became sixteen 16-bit limbs with 32-bit accumulators, then
its inner loops moved to assembly on the 45GS02's math unit at
`$D770`, then the multiply became eight 32-bit limbs with the 72-bit
accumulator kept in the Q register, the four registers A, X, Y and Z
used as one. The C is unchanged and the host suite still checks it.
Measured on the frame counter:

| Primitive | Compiled C | Assembly loops | Now |
|---|---|---|---|
| X25519, one shared secret | 14.2 s | 7.4 s | 3.5 s |
| Ed25519, one verification | 48 s | 24 s | 12.4 s |
| Poly1305, 4 KB | 3.8 s | 0.32 s | 12 KB/s |
| ChaCha20, 4 KB | 0.10 s | | 40 KB/s |
| Connect to shell | | 26 s | 10 s |

Signing with the identity is one more base-point multiply, about ten
seconds, so a key login takes twenty. The hashes were shrunk for room
rather than speed: rolling sixteen-word schedules, rotates as calls,
their few uses per login unaffected.

**The waits: everything polled, nothing hung.** Every wait is bounded
on the machine's frame counter, and mega-net is polled from every
loop, including from inside the crypto: a multiply that takes seconds
yields to the stack between rounds, with the memory map swapped to
the bank's own around the poll, so the connection stays alive through
the handshake and a server's keepalive is answered. The stack's
ethernet events reach the interrupt vector even with interrupts
masked on this core, so the client takes its vectors from the KERNAL
as its first instruction and quiets the controller before the stack's
first call; that ended a start-up hang that took half of all boots.

**The compiler and the assembler, watched.** llvm-mos once compiled a
`while (n--)` loop to decrement the wrong zero-page word; the loops
are pointer walks now and `tools/orphan_rmw.py` scans every linked
binary for the shape, refusing the build on a hit. The assembler
emits a 16-bit relative branch for a far target that this core does
not take, and gives a Q instruction on a symbol a zero-page form the
linker cannot fit; both have rules and macros in `mulacc_m65.S`.
Every such finding is numbered in `REQUIREMENTS.md` with what was
seen and what it cost.

**Proof before hardware.** Nothing runs on the machine until it has
passed on the host: the primitives against the RFC vectors, the
terminal against its suite and against byte streams captured from real
sessions, the transport against an asyncssh server whose flags make it
adversarial: a wrong host key, an oversized banner, a drop mid-exchange,
no common algorithm. Then the Mac's OpenSSH by hand, and a polling test
driver that types into the MEGA65 over serial and reads its screen.

**Randomness.** The MEGA65 has no random-number hardware this program
can reach. The seed is timing jitter: the raster position, a CIA timer
and the ethernet controller's counters sampled at every frame for a
second, then keystrokes and network replies stirred in, all hashed.
Good for an ephemeral exchange key; for a long-lived identity it is a
hobbyist's source, and the identity screen says so by what it is.

## Layout

| Path | What |
|---|---|
| `src/sshc.c` | The client: the host screen, the identity screen, the session loop, the keyboard map. |
| `src/transport.c` | RFC 4253: the packet layer, the exchange, the host key check, both logins. |
| `src/channel.c` | RFC 4254: the session channel, the pty, data and windows. |
| `src/crypto/` | The primitives from the RFCs, and `mulacc_m65.S`, the field and Poly1305 loops on the math unit. |
| `src/bank/` | The crypto bank: jump table, trampoline, linker script, the entries, the terminal (`term.c`) and its screen layer. |
| `src/ckit.c` | The client's side of the bank: one C function per entry. |
| `src/ident.c`, `src/hosts.c` | The identity on the disk; the known hosts. |
| `src/platform/` | Screen, font, F011, CBM DOS, boot and exit, shared with the FTP and gopher clients. |
| `tests/` | The crypto suite, the terminal suite, the replay tool. |
| `tools/` | The test server, the deploy tool, the miscompile checker, the size report. |
| `REQUIREMENTS.md` | The decisions, the plan, and every hardware finding, numbered. |

## License

0BSD, see `LICENSE`. mega-net is a separate project under the same
license; mega65-libc is under its own. The screen, F011, CBM DOS, boot
and exit modules under `src/platform/` come from the MEGA65 FTP client,
under the same license. The field arithmetic follows the shape of
TweetNaCl, which is public domain.
