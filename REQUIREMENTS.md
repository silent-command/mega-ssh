# ssh: requirements, decisions, and record

## 1. Goal

An SSH client for the MEGA65 on mega-net: connect to a server by name
or address, prove the server's identity, log in, and run a shell in a
terminal good enough for the programs people use over SSH. The MEGA65
becomes an 80-column terminal to any modern machine, and that machine
does everything the MEGA65 cannot.

## 2. Decisions

| Decision | Choice, and why |
|---|---|
| **Protocol** | SSH 2 only (RFC 4250-4254). One algorithm of each kind, the ones every current OpenSSH offers by default: key exchange `curve25519-sha256` (and its `@libssh.org` alias), host key `ssh-ed25519`, cipher `chacha20-poly1305@openssh.com` both ways, no compression. Negotiation is real, but the client offers one choice; a server that lacks it is refused with the reason on screen. |
| **Host keys** | Trust on first use. The fingerprint of each host is kept in `KNOWN_HOSTS` on the boot disk; a new host is shown and accepted with a keypress, a changed key is refused with a warning. No certificate authorities: SSH has none. |
| **Authentication** | Password first. Public-key login later: it needs Ed25519 signing and a key file on the disk, and the same arithmetic, so nothing is closed off. |
| **Cryptography** | Written here, in C99, from the RFCs: SHA-256, SHA-512, ChaCha20, Poly1305, X25519, Ed25519 verification. Proved on the host against the published test vectors before anything runs on the machine. The field arithmetic follows the compact 16-limb form of TweetNaCl (public domain), which is small and well understood; the 45GS02's hardware multiplier is used where the timing says it must be. Constant time is not a goal: the threat here is not a local side channel. |
| **Terminal** | A VT100 with the common ANSI extensions: cursor addressing, erase, insert and delete line, scrolling region, 16 colours, bold as bright. `TERM` is `vt100`; the screen is 80 by 25, the MEGA65's native text mode. Keys: arrows, Control combinations, Escape, Tab, Backspace and Delete. Local functions (quit, colours, a help line) live on keys the remote never needs, the function keys. |
| **Windows and packets** | The client advertises a small channel window and a small maximum packet, so the server never sends more than the client can hold; the transport still accepts the server's own packets up to the size of its key exchange, about 2 KB. |
| **Network** | mega-net socket 0 for the connection. Every wait bounded on the frame counter; the stack polled from every loop, including while the crypto runs, in slices, so the connection stays alive through a long handshake. |
| **Platform code** | The FTP client's platform modules (screen, F011, CBM DOS, boot, exit), copied as before. |
| **Build** | `build.py`, Python, all three hosts, the mega-net rule. A `test` target builds and runs the host crypto suite; `spike`, `client`, `clean` as before. |
| **Testing** | An `asyncssh` server on the Mac for controlled and adversarial cases (`tools/ssh_test_server.py`); the Mac's own OpenSSH for the real thing; every claim verified on the MEGA65. |

## 3. Requirements

- **F-1** Connect to a named or numbered host and port; show the server's version string.
- **F-2** Complete the key exchange and verify the host key; remember hosts; warn on change.
- **F-3** Log in with a password typed on the machine, never echoed.
- **F-4** Open a session with a pseudo-terminal and a shell; send keys; show output.
- **F-5** Terminal emulation good enough for `ls --color`, `vim`, `top`, `less`, `irssi`, `lynx`.
- **F-6** Every failure explained in words on screen; nothing hangs; disconnects noticed.
- **F-7** Quit to BASIC with the disk still mounted, and a readable screen.
- **N-1** No wait unbounded; the frame counter paces everything.
- **N-2** Runs from one `.d81` carrying the client and `MEGANET`.
- **N-3** A handshake in well under a minute; typing at wire speed once connected.

## 4. Plan

Ordered by what kills the project earliest.

| Step | What | Status |
|---|---|---|
| 1 | Skeleton; platform modules; a spike that connects, exchanges version strings and reads the size of the server's first packet | **Done** — 5.1 |
| 2 | The primitives on the host, against the RFC vectors: SHA-256, SHA-512, ChaCha20, Poly1305, X25519, Ed25519 verify | **Done** — 5.2 |
| 3 | The same primitives on the MEGA65, timed on the frame counter. The go/no-go: X25519 and an Ed25519 verification must fit a handshake people will wait for. Optimise with the hardware multiplier until they do | **Done** — 5.3: a handshake of about half a minute |
| 4 | The transport: KEXINIT, the exchange, host key verification and `KNOWN_HOSTS`, NEWKEYS, encryption on; then password authentication. Against the test server, then the Mac's OpenSSH | **Done** against the test server — 5.4, 5.5 |
| 5 | The connection: a session channel, `pty-req`, `shell`, data both ways, window adjust, exit status, disconnect | **Done** against the test server — 5.6 |
| 6 | The terminal: the escape parser and the cell screen, the keyboard map, local keys | **Done** — 5.7 |
| 7 | The long run: hours connected, big outputs, `vim` and `top` and `irssi`, the adversarial server, quit to BASIC | |

## 5. Findings

### 5.1 The version strings and the first packet (2026-09-05)

`src/spike/spike_banner.c` against `tools/ssh_test_server.py` (asyncssh,
port 2222, restricted to the client's algorithms): connected, read the
server's `SSH-2.0-...` line, sent `SSH-2.0-mega65ssh_0.1`, read the
first binary packet: length 900, padding 10, type 20 (KEXINIT), and its
first name-list `curve25519-sha256,curve25519-sha256@libssh.org,
ext-info-s,kex-strict-s`. So the plumbing is fine and the server offers
what the client will ask for; `kex-strict-s` is the strict-kex
extension of 2023, which the client should answer with `kex-strict-c`
when it sends its own KEXINIT.

### 5.2 The primitives: right on the host, right on the machine, and how long they take (2026-09-05)

The host suite (`python3 build.py test`, 19 checks) passed on the first
run for everything but Ed25519, whose point decompression used den^5
where the formula wants den^6; the derived-public-key probe and a
Python check of each intermediate found it in minutes. Rule confirmed:
prove the arithmetic on the host before the machine sees it.

**The first target build did not fit.** TweetNaCl's form keeps limbs in
`int64_t`; llvm-mos emulates every 64-bit operation inline, and the
crypto alone came to 43 KB of code and 7 KB of data (`llvm-size` on the
objects: curve 15 KB text, 7 KB bss; poly1305 8.7 KB; sha512 8.5 KB)
for a machine with 44 KB below the stack. The field arithmetic was
rewritten in sixteen 16-bit limbs, fully reduced, with 32-bit
accumulators and one 16x16 multiply hook (`fe_mul16`) that the MEGA65
build points at the 45GS02's math unit (`$D770`-`$D77B`) and the host
at a plain multiply; Poly1305 was rewritten in TweetNaCl's 8-bit-limb
form with 32-bit sums. Same algorithms, same 19 checks, and with `-Oz`
the timing spike links at 28 KB of code. Rule: on this CPU, no
`int64_t` in anything that must be small or fast; `uint32_t`
sparingly, and only in accumulators.

**Measured on the machine** (`src/spike/spike_crypto.c`, the same
vectors, PAL frames): every primitive correct, and

| Primitive | Time | Rate |
|---|---|---|
| SHA-256, 10 KB | 0.72 s | 14 KB/s |
| SHA-512, one block | 0.2 s | |
| ChaCha20, 4 KB | 0.10 s | 40 KB/s |
| Poly1305, 4 KB | 3.8 s | 1 KB/s |
| X25519, one shared secret | 14.2 s | |
| Ed25519, one verification | 48 s | |

A handshake would be about a minute: usable for a first connection,
not what N-3 asks. The multiply-accumulate is costing about 780 cycles
per 16x16 product in compiled C (32-bit array elements indexed by
`i+j`, read-modify-write per product), where a loop on the hardware
multiplier should need about fifty; and Poly1305's products are
software multiplies. Both inner loops move to assembly next, with the
same vectors as the proof.

Process note: the screenshot tool's raw stream wraps every character in
colour codes, so a poll that greps the raw text for a word never
matches; strip the codes first.

### 5.3 The inner loops in assembly, and two things the assembler does (2026-09-05)

`src/crypto/mulacc_m65.S`: the 16x16 multiply-accumulate of the field
multiply (column scanning, a 40-bit accumulator, 256 products) and the
17-column sum of Poly1305, both on the math unit at `$D770`, both
reading and writing fixed buffers the C side owns, so no zero page and
no calling convention. `spike_mul` and `spike_poly` check them on the
machine against C references and trivial products; `spike_crypto` runs
the RFC vectors and the field identities and times everything:

| Primitive | C only | With the loops |
|---|---|---|
| Poly1305, 4 KB | 3.8 s | 0.32 s (12 KB/s) |
| X25519 | 14.2 s | 7.4 s |
| Ed25519 verify | 48 s | 24 s |

A handshake is about half a minute. The loop itself is now a quarter
of the X25519 time; the rest is the C around it (the fold by 38, the
two conditional subtractions, add, sub, swap, and the copies into the
loop's buffers), which is the next thing to move when the transport
exists to measure end to end.

**Two things the assembler does that cost a day between them.** First,
numeric local labels (`1:` and `bcs 1f`) assembled without complaint
and branched somewhere else: the first sixteen product columns were
right and the seventeenth on were garbage, exactly the columns whose
start index came from that branch. Named labels only. Second, and
worse: when a conditional branch's target is out of the 8-bit range
the assembler emits the 65CE02's 16-bit relative branch (`$93 lo hi`)
without a word, and on this core it did not land where the assembler
placed it: the Poly1305 routine finished its first column and then the
CPU was found executing the soft stack. The bytes in memory decoded to
the right target by the usual rule, so the disagreement is between the
assembler's and the core's idea of the base, not settled here. Rule:
in assembly for this machine, no branch may reach further than 127
bytes; write `bcs done` / `jmp loop` and let the assembler have nothing
to relax.

Also on the way: a stale disk twice showed the previous build's screen
after a rebuild that had failed to compile, which cost an hour of
chasing a fixed bug. Every spike now prints `__TIME__` on its title
line, and a screen without the expected stamp is not evidence. And
adding a second probe to `spike_mul` made an earlier, passing step in
the same program crash, the layout sensitivity recorded twice before
in this family; probes stay small and separate.

### 5.4 The crypto in a second bank (2026-09-05)

The client with the transport did not fit: 58 KB of code and 14 KB of
data by `tools/sizes.py`, against 44 KB of RAM, and the terminal still
to come. The cryptography, 31 KB, now lives in bank 1 at `$12000` as a
headerless image behind a jump table (`src/bank/`), reached through a
trampoline at `$1700`, the page after mega-net's; the client calls it
through `src/ckit.c` with parameter blocks the bank reads by DMA, and
the bank moves data in and out through a 512-byte stage in chunks.
The shape is mega-net's, copied deliberately: the same prologue that
saves the caller's zero page and switches to the bank's own soft
stack, the same INIT-as-crt0, the same interrupt-vector stub at the
top of the bank, the same DMA copy with the list registers put back.
Contexts and keys stay in the bank, named by slot; the client never
holds a key.

Zero page is the one place the design changed under test. The bank
wants about 110 bytes for the frames the compiler keeps in zero page
(a link-time decision, invisible per file), which the $90-$FF that
mega-net uses cannot hold, so the bank owns $70-$FF while it runs. A
first attempt capped the client's zero page at $6F to keep the two
apart and overflowed the client; the cap was wrong in principle: the
bank's prologue saves and restores its whole range, so it nests inside
the client exactly as mega-net's trampoline nests inside either, and
the client keeps full zero page. When the bank yields to mega-net's
poll during a long operation, it first sets mega-net's mailbox map to
its own map and puts the client's back after, or the poll would
return to a window that had been unmapped.

Two pins were still needed on the client side: the compiler had put an
81-byte screen row buffer and a 32-byte random block into zero page,
which the bank's range covers; both carry a section attribute now.

### 5.5 Step 4 on the machine: a full handshake and a password login (2026-09-05)

Against `tools/ssh_test_server.py` (asyncssh, restricted to the
client's algorithms, `kex-strict-s` on), twice from a fresh disk:

| Stage | After connect |
|---|---|
| KEXINIT both ways, our share of the exchange | 0 s |
| the shared secret (X25519 in the bank, polling the stack) | 6 s |
| host key prompt (first time), Y, saved to `KNOWNHOSTS` | 12 s |
| the host's signature checked (Ed25519 verify) | 14 s to 32 s |
| NEWKEYS, keys derived, chacha20-poly1305 on both ways | |
| `ssh-userauth`, password sent encrypted, `USERAUTH_SUCCESS` | 32 s |

The second connection, with the host known, logged in at 30 s. The
server's log shows the negotiation exactly as sent, the exchange
completed, and "Auth for user mega65 succeeded": our encrypted
packets decrypt on its side and its encrypted replies on ours, so the
key derivation, the nonce and sequence handling under strict kex, the
length encryption and the Poly1305 tags all agree with a second
implementation. The exchange hash was already known to be right when
the host's signature over it verified.

One run before these two ended with "the connection closed" after the
signature check. My automation had left the host key prompt unanswered
for over two minutes and the server's login grace period ran out; it
is not a client fault, but it is a fact of the protocol worth knowing:
the prompt and the verification both spend the server's login budget,
which OpenSSH sets at two minutes by default.

Not yet: the Mac's own OpenSSH, and step 5's session channel, so the
client so far logs in and then shows the message types the server
sends.

### 5.6 Step 5 on the machine: the compiler decrements the wrong word (2026-09-05)

The first shell session filled the screen with the program's own code
and scrolled without end. The serial monitor's watchpoint and a stack
walk put the CPU in `term_write`, called correctly from the channel
with the server's 43-byte welcome, and showed what the loop was doing:

```
6447  sta $61 / stx $62      n, in the function's zero-page slot
...
6460  lda $62 ; bne body     the test reads $61/$62
653a  dew $16                the decrement hits __rc20, never $61
```

So `while (n--) term_putc(*p++);` never ended: the count stayed 43
and the pointer walked the whole address space onto the screen. The
same bytes are in the ELF, so it is llvm-mos (c798c314, clang 23)
generating the read-modify-write against the register the variable
had before it was given a zero-page slot. Rewriting the loop as a
counted `for` produced the identical `dew $16`; a pointer walk
(`while (p < e)`) compiles to `inw $61` against a stored end, and is
what `term_write` does now. The two other loops of that shape,
`ck_equal` and the padding in `ui.c`, are rewritten too.

`tools/orphan_rmw.py` scans a linked ELF for the signature (an
`inw`/`dew` on a zero-page word above the argument registers that the
function never otherwise touches), and `build.py` runs it after every
client link and refuses the build on a hit. `memcpy`, `memcmp` and
`memset` legitimately increment their argument registers, which is
why the scan starts at `$10`.

Two smaller things from the same day. The shell build once hung at
"starting the network" with the CPU in the stack region; the same
binary booted cleanly on the next two runs and the hang has not
recurred, so it is recorded, not explained. And the linker put the
disk module's sector buffer above `$C000` in this build, which the
gopher client's notes call a hidden window; it is not hidden here (the
runtime unmaps that ROM and the loader reads through it fine), but a
build whose `.bss` crosses `$C000` is worth a glance whenever start-up
misbehaves.

### 5.7 Step 6 on the machine: the terminal, and where the top of bank 1 really goes (2026-09-05)

The terminal (the escape parser, colours, scroll regions, insert and
delete, line drawing, UTF-8, the replies a host asks for) is written
once, `src/bank/term.c`, and proved on the host first: `tests/test_term.c`
includes it with `TERM_HOST_TEST`, under which the screen is two
arrays, and puts forty sequences through it. `python3 build.py test`
runs it after the crypto suite. Everything found on the machine after
that was below the parser.

It did not fit anywhere. With the terminal, the client overflowed its
44 KB by 4.4 KB even after the console library's output routines and
their 765-byte escape buffer were dropped (the prompts write cells
through `screen.c` now) and the known-hosts text moved to bank 5 above
mega-net's sockets (`$5E900`). And the crypto bank had 500 bytes free,
not the 8 KB estimated. So the bank grew a second region: its map
already puts `$E000-$FFFF` over `$1E000`, and the parser lives there
as a second image, TERM, compiled without LTO so `crypto.ld` can name
the object. The screen primitives (`termscr.c`) and the glyphs stay in
the main region; the client hands the terminal the host's bytes
through three new jump-table entries and carries its replies back.

Two things the machine then taught:

- **`$1F800-$1FFFF` is the colour RAM.** The first TERM image ran to
  `$FE61`, and everything from `$F800` up read back as a solid run of
  `$01`: the mirror of the first 2 KB of colour RAM, white cells,
  overwriting the parser's tail. The symptom was a terminal that
  drew nothing and left the CPU in the bank's bss; the proof was the
  image compared against the file at eight points. The window is
  `$E000-$F7FF` now, 6 KB, and the bank's vectors at `$FFF0` survive
  only because an 80x25 screen ends at `$1FFD0`. Fitting 6 KB took
  the soft stack down to 512 bytes, the stage to 256, the glyph
  folding to a 64-byte table, and 256-colour SGR to "consumed".
- **The stage size is the ChaCha20 counter step.** With the stage at
  256 the in-place decrypt still advanced the block counter by eight
  per chunk, so the tail of every packet over 256 bytes was garbage:
  four lines of `ls -l /` right, the rest noise. `sizeof stage / 64`.

The boot probe (`EXTRA_CFLAGS=-DTERM_DEMO`) draws a fixed sequence at
start-up; its screen is exactly the host test's prediction, colours
included (reverse, light red for bold red, green, the box corners),
except that a blue background on the blue screen is invisible by
construction.

Then a real shell: `tools/ssh_test_server.py 2223 --shell` runs zsh on
a pseudo-terminal sized from the pty request. On the machine, from a
fresh boot: login, `ls -l /` complete and right (sixteen entries; a
backtick after some permission strings is macOS's `@` for extended
attributes, screen code 0 as the screenshot tool shows it), reverse,
bold, colours and the box-drawing line through a Mac-side script,
vim opening a file with its tildes and status line, an edit written
and read back with `cat`, `top` running full screen and refreshing,
`q`, `exit`, "the session ended, exit status 0" and the client's own
screen back. About two minutes end to end with polling waits.

Vim also taught the terminal its last lesson: it asks for the cursor
position and the terminal's identity, and the answers came back late,
the whole screen decrypted first at 12 KB/s, after vim had stopped
waiting; vim then read `ESC [ 24 ; 1 R` as keys, and the `R` put it in
replace mode with the next command typed into the buffer. The
terminal answers no queries now, as any VT100 without the option, and
vim is content. That took 385 bytes out of the window too.

Three things about driving the machine, all costly: `m65 -T` hangs for
ever on a character the MEGA65 keyboard lacks (a backslash, anything
non-ASCII) and on a long line, and drops capital letters; killing the
hung tool leaves the serial monitor waiting mid-command, after which
every tool hangs until the machine is power-cycled. So a test types
only short lowercase commands and puts anything else in a file on the
Mac to run with `sh`. And the monitor script's port glob can pick the
wrong FTDI port after a re-enumeration: `MEGA65_PORT` pins it.

The start-up hang first noted in 5.6 recurred: eight of sixteen boots
this session stopped at "starting the network", the CPU in mega-net's
stray-interrupt stub or the KERNAL's, the mailbox showing DHCP_START,
once with the decimal flag set. It happened with no serial traffic
during the start and once straight after a cold boot, and the same
disk then booted five times running. It is mega-net's, at DHCP, and
is the first item of step 7.

### 5.8 The start-up hang: a stray ethernet event and the KERNAL's handler (2026-09-05)

Half of all boots (eight of sixteen in 5.7, then five of ten, five of
ten, four of eight with the same disk) stopped at "starting the
network". Every catch looked different: the CPU in mega-net's
stray-interrupt stub with the decimal flag set; in the KERNAL's
handler with the stack filling; at address zero in mega-net's map; in
the client's own error loop with "TERM not found (or wrong size)"
where the status rows had been overwritten. They were one fault.

mega-net 5.16 found that on this core the ethernet controller's
events reach the CPU's IRQ vector past the controller's enables and
past the I flag, and gave its own window a stub for them. Between
calls the client's map was in force, and its vectors were the C65
KERNAL's (`$E000` from bank 3 by the MAP, and again by HIRAM in
`$01`). So a stray event, tens of microseconds after a transmit,
dropped the KERNAL's interrupt handler into the middle of the client
with the client's zero page and stack, and the handler's own MAP
brought the ROM in under the program: the next fetch after its return
came from ROM, and everything above followed. Which transmit did it
was chance, hence one boot in two.

The client owns its vectors now: `m65_own_vectors()` is the first
thing `main` does. A stub in bank 0 RAM under `$E000` (at `$FF00`; it
records the first interrupted PC and flags at `$FF80`), the three
vectors pointing at it, the MAP with nothing above `$8000`, HIRAM off
in `$01`, and both trampoline mailboxes told the new map so every
call returns to it (mega-net's is re-told after `m65_boot_load`
copies the trampoline over it). The exit stub is unchanged: it maps
the ROM back itself before jumping through the reset vector, measured
still working. Since then, twenty-two boots in a row, five seconds
each. Installing the stub after mega-net's INIT was not enough: INIT
resets the controller, and its event came before the install.

Two things that were not it, kept anyway: the image loads retry three
times with the count on record (never needed once the vectors were
right), and the recording stub, 27 bytes, for the next time.

**Correction (5.11's day).** "Twenty-two boots in a row" was a lucky
streak. The vector fix is real and verified: across dozens of boots the
recording stub's `$FF80` stays zero, no interrupt reaches it, and the
"CPU in the KERNAL, different every time" corruption is gone for good.
But a second, milder fault remained under it and the streak hid it:
about one boot in three still sticks at "starting the network", and
this time the sampled PC is inside mega-net's own `mn_api_poll`, the
event record zero, the map mega-net's. net_up's DHCP budget is three
attempts of 400 frames, 24 s, after which it shows "no DHCP lease" —
but a stuck boot sits past 45 s without that message, so a single
`poll()` call is not returning: the client never advances its frame
counter. It is a spin inside mega-net's poll during DHCP, not the
vector fault and not the client's. Recorded honestly here; the fix is
mega-net's and is the open item.

### 5.9 Step 7, the first evening: idle, adversaries, and the way out (2026-09-05)

With the start-up hang gone (5.8), the long run began. Each of these
is one command from the polling driver, two minutes with the
handshake included.

- **Idle.** A session on the real shell left untouched for twenty
  minutes, not a byte either way; the next command answered at once,
  `exit` ended it with status 0. Nothing in the stack or the client
  times out an idle connection.
- **The way out.** `exit` from the shell, then RUN/STOP at "any key
  for the host screen": BASIC 65's READY in two seconds, and the
  program runs again from `RUN` without a mount. HELP as the key that
  ends a session is in the code and not yet pressed by a finger; the
  typing tool cannot send it.
- **Adversaries**, `tools/ssh_test_server.py` with one flag each, on
  ports 2223 to 2226:
  - a server offering only `ecdh-sha2-nistp256` and `aes128-ctr`:
    "connect: no curve25519-sha256" in a second;
  - a server that drops the connection four seconds in, inside the
    exchange: "connect: the connection closed";
  - a login banner of 3990 bytes, over the client's 2560-byte packet:
    "login: a packet too large for this client", after the handshake,
    nothing worse;
  - the port the client already trusts, served with a fresh key: the
    WARNING screen, the new fingerprint, "Y to connect anyway (the key
    is NOT saved)", and on N "connect: the host's key has changed;
    refused". A new host's prompt refused with N says "connect:
    refused".

One thing seen once and not again: the first connect after the idle
session, made moments after the server process it had been attached
to was killed, ended "connect: no reply from the host" without
reaching the server; a session ended with `quit` followed by an
immediate connect, and another ten seconds later, both reached the
server normally.

Still to do in step 7: the Mac's own OpenSSH (Remote Login is off on
this Mac), hours rather than minutes, and a finger on HELP.

### 5.10 The Mac's own OpenSSH, by hand (2026-09-06)

Remote Login on, the user at the MEGA65's keyboard, the client's
`KNOWNHOSTS` without this host. The fingerprint the client showed
(SHA-256 of the raw key bytes) matched the one computed here from
`ssh-keyscan`; Y; password; the Mac's log: "Accepted password for
<user> from 192.168.1.252 port 50336 ssh2", OpenSSH 10.3. Then
`ls -l`, vim and top in the user's own zsh, HELP to end the session,
RUN/STOP to BASIC, all as designed. The password had an underscore,
which the MEGA65 keyboard types with ←: the queue delivers `$5F`.

Two things from it. The first attempt ended "connect: the connection
closed" at the fingerprint prompt after a pause to read messages:
OpenSSH allows two minutes from connect to a finished login, the
prompt arrives fifteen seconds in, and the Mac's log kept no verdict
line for it within reach, so the grace period is the likely cause and
not the proven one. And the oh-my-zsh prompt's » came out as a dot:
the glyph fold began at U+00C0, and now covers Latin-1 punctuation,
the arrows and the tick and cross. Every non-ASCII character a host
sends is a stand-in on this screen; the Unicode box-drawing block is
the one range with real glyphs.

Step 7 as planned is done except for hours rather than minutes:
twenty minutes idle held (5.9), a two-hour run was started and stopped
for these tests, and is the next thing to leave running.

### 5.11 The handshake halved: 32-bit limbs and the Q register (2026-09-06)

Where the time went, measured on the frame counter with hooks in the
spike (`crypto_fe_bench`): a field multiply cost 1.3 ms, of which the
assembly loop was 1.2, and everything around it, the fold by 38 and
the two reductions in C, the adds and subs in C, was the rest. Moving
the fold, the reductions, the add and the sub into `mulacc_m65.S`
took a quarter off (X25519 7.4 s to 5.6 s). The multiply itself was
then the cost: 256 products of 16-bit limbs at about 190 cycles each.

The math unit multiplies 32 bits by 32 bits, and the field element's
32 bytes read as eight 32-bit limbs exactly as they read as sixteen
16-bit ones, so the multiply is now 64 products with the 72-bit
accumulator added by the Q instructions (LDQ/ADCQ/STQ, which take
A, X, Y and Z as one register: the indices live in memory and Z is
zeroed before returning). The C side is untouched and the host
suite still checks it. A multiply is 0.6 ms.

| Primitive | C only (5.2) | 16-bit loops (5.3) | now |
|---|---|---|---|
| X25519 | 14.2 s | 7.4 s | 3.5 s |
| Ed25519 verify | 48 s | 24 s | 12.4 s |
| connect to shell, echo server | | 26 s | 10 s |

Two assembler lessons, one old and one new. The fold's loop is 155
bytes long, and its `bcc` back to the top became a 16-bit branch
that this core does not take (5.3 again): the loop ran once and the
hand-picked cases in `spike_mul` (t=5, 2^255, 2^256) showed it. A
short branch over a `jmp`. And the assembler gives a Q instruction on
a symbol the zero-page form, which the linker cannot fit; the two
prefix bytes before the plain instruction are the same thing and it
encodes those absolute (`LDQA`/`STQA` macros).

### 5.19 The DHCP-start hang chased down: a stray event during INIT (2026-09-06)

5.8's honest correction named a spin that stuck about one boot in
three at "starting the network". Chased here. The raster counter
`$D7FA` kept advancing on a stuck boot while the client's own frame
count stayed zero, so the client never returned from one `meganet_call`;
the sampled PC was inside mega-net at INIT, with the decimal flag set
and the stack pointer moved to `$04xx`, the stack full of code
fragments. It was not a legitimate loop: `mn_api_init`'s bss clear is
4219 bytes and bounded, but the CPU had jumped into it with stale
registers (Y counting from an impossible value), then run away zeroing
memory through the wrap at `$FFFF` onto its own counter.

The trigger is 5.16's stray ethernet event, in flight from a previous
run, arriving during INIT before INIT resets the controller. Two fixes,
measured:

- the client holds the controller in reset (`$D6E0 = 0`) before the
  first call, as the exit path does, so the window is empty when INIT
  runs. 8 of 12 boots became 42 of 44.
- INIT installs the window's interrupt vectors as its first action,
  before it brings the controller up, so an event during the bring-up
  is caught by the stack's own stub, not fetched through a stale
  vector (`install_window_vectors()` moved to the top of `mn_api_init`).

Together, 19 of 20 and then a longer run at about the same rate. The
residual, roughly one boot in twenty, is a different and rarer crash:
the PC is in the C65 KERNAL's own code in the client's context, not in
mega-net, and mega-net's `window_irqs` shows its stub handled a dozen
events cleanly during the run. So it is an interrupt landing in the
KERNAL through a window in the trampoline's map transition, where the
caller's map is briefly in force with the KERNAL still reachable, not
the INIT fault. A reset and another run clears it; `boot_ssh` in the
test harness reaches the prompt in one or two tries. Left open, and
the transmit-done experiment of 5.18 is the way to attack the class at
its source.

### 5.20 Terminal colours: backgrounds, attributes, and a local cycle (2026-09-06)

Foreground colours worked from the start (5.7). Three additions, all
proved on the host (`tests/test_term.c`, now 27 checks) and on the
machine against the real shell.

- **The screen background follows a full clear.** The VIC text mode
  gives every cell its own foreground but one global background at
  `$D021`, so a cell cannot carry an arbitrary foreground and
  background at once. When the host clears the whole display with a
  background set (`ESC [ 2 J`, what a full-screen program does first),
  the terminal writes that colour to `$D021`. So the whole screen
  takes the program's background and ordinary cells then show their
  true foreground on it. A cell whose background differs from the
  screen's is still drawn as a reversed block in its colour, the old
  approximation, now needed only for spans that disagree with the
  screen. On the machine: `printf` of a blue clear turned the whole
  screen blue, coloured text drew true on it, and a green span drew as
  blue-on-green.
- **Underline and blink**, which the host sends as SGR 4 and 5 and the
  terminal had ignored. The VIC-III extended attributes (`$D031` bit
  5) put four attributes in the colour byte's high nibble; the low
  nibble stays the sixteen colours, so every existing colour write is
  unchanged and underline (bit 7) and blink (bit 4) just OR in.
  `underlined` came back underlined on hardware. Bold stays the bright
  half of the palette, reverse stays the screen-code high bit.
- **A local colour cycle.** During a session every key goes to the
  host, so, as HELP ends the session, MEGA held with F or B is kept by
  the client: F cycles the terminal's default text colour, B the
  screen background and border together, the way the gopher and FTP
  clients cycle with F and B. `ck_term_recolour` in the bank applies
  them live. Not driven from the test harness, which has no MEGA
  modifier; for a finger.

`term_end` puts `$D021` and the attribute mode back to the client's at
session end, verified by the host test and by the host screen
returning after `exit`.

### 5.21 Vim's commands at the top, top ignoring q: the test server, not the terminal (2026-09-06)

Reported against the real-shell test server on port 2223: in vim a
typed `:` and the command after it appeared at the top of the screen,
mixed with buffer text, Escape did nothing, and `q` did not quit
`top`. The same on the day's build and on the previous day's (a
worktree build of the commit before the handshake, vector and colour
changes), so not a regression, though it looked like one because the
earlier hand test had been against the Mac's OpenSSH.

The hunt, which cost two hours, went through the terminal first: the
parser replays the exact byte stream correctly on the host, so a ring
of the last 64 bytes given to the parser was added to the bank
(`TERM_TRACE=1 python3 build.py`, read from the monitor), then a ring
of received packet types and lengths in the client. Those showed the
truth: after the `:` the client received one 1-byte data packet, and
the pty log on the server showed vim writing nothing at all until
RETURN. The byte came from asyncssh itself. Its server-side line
editor is on by default for a pty session: it echoes each key at the
cursor and holds the line until RETURN before the shell sees it. So
`:` was drawn where the cursor was (row 0 after vim's home), vim got
`:q` and RETURN as one line, Escape was swallowed, and `top` saw `q`
only with the RETURN after it. The doubled first characters in the
shell (`vvim`) were the editor's echo plus the shell's.

`line_editor=False` in `create_server` ends it. Verified on the
machine: `:` draws on row 24, `q` returns the prompt from `top` in
under a second. The trace ring stays under its define, off by default;
the packet ring was removed. A related note for the test driver: the
typing tool cannot deliver capitals, and a line with them left the
serial monitor wedged until a power cycle; type lowercase only.

While Escape was blamed, `ui_key` gained a PETSCII fallback for a key
event whose ASCII reads `$FF`. A key probe (interrupts off, printing
`$D610`, `$D619`, `$D611` per physical key) then measured Escape as
`$1B`, colon `$3A`, `q` `$71`, RETURN `$0D`, all with no modifier: the
fallback was a no-op and was removed. The Escape that "stopped working"
had been eaten by the same line editor.

### 5.22 Public-key authentication, an identity on the disk, and late.sh (2026-09-06)

late.sh is a clubhouse in a terminal (russh, a ratatui interface) where
"your ssh key is your identity": no passwords, a random username on the
first connection from a new key, only the key's fingerprint stored. Its
server offers exactly the client's three algorithms, so the transport
needed nothing; the work was authentication, the key, and the picture.

- **Signing.** `ed25519_keypair` and `ed25519_sign` join the verify in
  `curve25519.c`, from the same pieces (SHA-512, the base-point
  multiply, the mod-L reduction) plus one multiply-add, carried down to
  byte limbs before `modL`, which was written for byte limbs in 32-bit
  arithmetic. Proved against RFC 8032 7.1 tests 1 to 3 from their seeds
  (12 more host checks). On the machine a signature is one base-point
  multiply, about ten seconds.
- **The login.** `ssh_login_key` sends one USERAUTH_REQUEST of type
  publickey with the key blob and the signature over the session id
  and the request (RFC 4252 7), no query first. Verified against the
  test server's new `--pubkey` mode (any key accepted), then late.sh.
- **The identity.** IDENTITY on the boot disk: the 32-byte seed and
  the public key, made on the machine from the client's timing-jitter
  randomness (a hobbyist's source: a throwaway-grade identity, which
  is what late.sh suggests anyway). F1 at the Host prompt shows the key
  as OpenSSH writes it and its SHA-256 fingerprint, base64 without
  padding, which `ssh-keygen -lf` confirmed byte for byte; R there
  replaces it, G makes the first one. The Auth prompt after User takes
  p or i, and the choice is the next default, one byte in SSHAUTH.
- **The disk is the identity's home, so replacing the disk loses it**,
  as the first redeploy of the day proved. `tools/deploy.py` fetches
  the disk on the card, carries IDENTITY, SSHAUTH and KNOWNHOSTS into
  the new image with c1541, and puts that. The test driver uses it.
- **Room.** Signing overflowed both the bank and the client. The bank
  gave up the field self-test entry (1.2 KB, only the spikes used it),
  shares one set of scratch between verify and sign, keeps the group
  operations out of line, and rolls both hashes' message schedules
  through sixteen words (700 bytes of variables; the rotates became
  calls, which mattered less than expected: the 64-bit arithmetic
  itself is the bulk of SHA-512's 5.7 KB). The client builds its
  version line, KEXINIT and both authentication requests in `ssh_rx`,
  idle until the reply, and the transport buffers shrank (RX 2048, TX
  768). Free now: 300 bytes in the bank, 200 in its terminal window,
  1.2 KB in the client.
- **The picture.** ratatui sends truecolor (`38;2;r;g;b`) for
  everything and up to ten parameters per SGR; the parser held eight,
  so the pairs were misread. Sixteen parameters now, and truecolor and
  256-colour indices map to the nearest of the machine's sixteen (green
  weighted double, quarter-scaled squares in 16 bits: the bank links no
  32-bit multiply). More block elements (halves, eighths, quadrants,
  the rounded corners) and folds for notes, circles, stars. A colour
  value is now ANSI 0-15, or 16 plus a machine colour. `tests/term_replay.c`
  replays a captured stream on the host and prints the screen and the
  colour nibbles, which is how the mapping was judged before hardware.
  Captured with a throwaway key from the Mac (`asyncssh` client, 80x25
  and 80x50): CSI H, SGR, the alternate screen, cursor hide, mouse and
  bracketed-paste modes, a DA query, OSC and APC strings, box drawing,
  shades, no wide characters. On the MEGA65 the clubhouse renders in
  colour with its frame, scrolls with j and k, and pages with the digits.

Not yet: the 80x50 mode the machine offers (the screen would overlap
the trampolines at $1600; it needs a far screen), and a hand test
against a server with the key in `authorized_keys`.

### 5.23 The screen in bank 1, and 50 rows when the machine is in them (2026-09-06)

The MEGA65 offers an 80x50 text mode (ESC 5 at the BASIC prompt); the
ROM sets the VIC-IV's display-rows register `$D07B` to 49 for it. The
client now reads that register at start and keeps whichever mode it
finds, 25 or 50 rows, for its own screen, the terminal, and the pty
request (rows and pixel height), so a host lays out 80x50.

Fifty rows are 4000 cells, and at the default `$0800` they would run
to `$17A0`, over mega-net's trampoline at `$1600` and the crypto
bank's at `$1700`. So the screen moved: `$10000`, the bottom of bank
1, below the crypto image at `$12000`, where nothing lived. The VIC
takes it from `$D060-$D063`; the client draws through `lpoke`, the
bank through DMA (its single-cell peek and poke went through a byte of
scratch), the colour RAM stays at `$FF80000`. One layout for both
modes. The old worry from the gopher client, that a relocated screen
"fought the ROM's setup", was conio's doing in C64 mode; here the ROM
is not running and the pointer holds. The row count is a variable in
the terminal (`term_init` takes it in Y), `LAST_ROW` follows it, the
host arrays hold fifty, and the UI's status and key rows are the last
two of whatever there are.

On the machine, forced with `POKE 53371,49` and the V400 bit: the host
screen renders with its key row on line 50, and a login and a shell
work. The 80x50 late.sh capture replays on the host with its bars on
rows 45 to 49. A full-screen program at 50 rows is not yet confirmed
by eye: any screenshot (`-S0` text as well as `-S file.png`) hangs the
tool and wedges the serial monitor once a 50-row SSH session is
actively driving the screen, which cost three power cycles. Reading the
far screen for a 50-row program needs a method that does not contend
with the session's DMA; for now the host replay is the evidence and the
user can eyeball a live session.

### 5.24 Hand-test feedback on the identity work (2026-09-06)

Four things seen by eye, fixed: a session's last column survived the
return to the host screen, because the row painter padded to 79
columns, a habit from the console library's wrapping days (now 80);
the Auth prompt comes before User, as the choice decides what follows;
"RUN/STOP to quit"; and the identity screen's two longest lines were
over 80 columns and lost their ends. The late.sh mention left that
screen. Built and deployed, not yet seen on the machine: the text
screenshot hung the tool once more, this time in a 25-row session with
the screen at `$10000`, so the wedge is not about 50 rows. It is a
screenshot taken while a session drives the far screen, in any mode;
the client UI between sessions polls fine. Four power cycles today.
No screenshots during sessions from here on.

### 5.25 Six glyphs the character set lacks, drawn into a font in RAM (2026-09-06)

ASCII has backslash, caret, backtick, the braces and the tilde; the
machine's lowercase set has none of them, and the clients showed a dot
(the caret an arrow). `src/platform/m65_font.c`, the same file in the
gopher, FTP and SSH clients: the ROM's lowercase set (2 KB at `$2D800`,
where `setlowercase` points) is copied to `$11000`, bank 1 below the
crypto image, which mega-net leaves to the program; the six are drawn
into graphics codes nothing maps to (`$5C $5E $60 $68 $69 $6F`, chosen
so the first three match their ASCII values); the VIC's `$D068-$D06A`
point at the copy. Drawn in the set's own style, read from VICE's copy
of the character ROM: diagonals and verticals two pixels wide,
horizontals one, the tilde on the hyphen's rows, the backtick the
apostrophe mirrored, the caret the arrow's head. The exit paths of all
three now put `$D068/$D069` back to the ROM's set as well as the bank,
since the copy's address differs in more than the bank byte. The
gopher client had the mapping in `gopher_screen.c`, the FTP client in
its `m65_screen.c`, the SSH client in `glyph.c`, which the bank also
compiles, so the bank's include path gained `src/platform`. Seen on
the machine in all three: an FTP listing of files named `back\slash`,
`brace{y}`, `caret^z`, `` tick`q `` and `tilde~x` draws every glyph as
itself in the set's weight, the SSH and gopher screens are unchanged,
and each client quits to a readable BASIC. One side effect for the
test driver: the tool's text screenshot decides upper or lower case
from the VIC's font pointer, so with the copy at `$11000` it renders
every screen as the uppercase set, capitals as `?`; patterns must
match case-insensitively and avoid capitals. The PNG screenshot reads
the real font and is right.

### 5.26 An empty IDENTITY ships on the disk (2026-09-06)

Reported by the user from a hand test: on a disk with no IDENTITY, the
first G on the identity screen did not create the file; a later
attempt did. The automated run of 5.22 had generated on a fresh disk
at the first try, so the failure was not reproduced here, and the
machine was off when it was reported. The disk now carries an empty
`IDENTITY` (a sequential file of no bytes, written by `build.py`),
which `ident_load` reads as no identity and `ident_generate` replaces
by delete and create, the path the KNOWNHOSTS write has always taken.
`tools/deploy.py` carries a real identity over the placeholder as
before. To be watched for: whether a first write to a disk fails on
the missing-file delete, which would touch `hosts_add` too.

### 5.27 Bookmarks, and the room for them: the console library out (2026-09-07)

Bookmarks as the FTP client has them (ftpc 5.10): `SSHMARKS` on the
boot disk, host, port, method and user per entry, no passwords, eight
at most; listed under the prompts, a number at the Host prompt opens
one (the prompts fill in, only the password is asked), D and the
number deletes one, MEGA+M in a session toggles the current host, with
the border flashing once for saved, twice for removed, three times for
no room, since the terminal owns the screen. `tools/deploy.py` carries
the file. Verified on the machine from a seeded file: listed, opened,
logged in, deleted. MEGA+M itself waits for a finger.

The code did not fit: 739 bytes free before, 1.6 KB over after. The
room came from four places. The console library left the client: its
five setup calls became register writes in `m65_screen.c` and the font
module, and with no call left, its 765-byte escape buffer and its code
went with it (1 KB back; the screen verified in both row modes). The
send payload went from 768 to 512, which a terminal's keystrokes and a
300-byte KEXINIT never approach. The channel builds its messages in
`ssh_rx`, idle by the time any reply is built, as the transport already
did for its own. One 81-byte scratch line serves the line editor, the
fingerprint lines, the identity screen and the bookmark list, none of
which are drawn at once, and the bookmark module reads its fields
through it too; the known-hosts line shrank to what a line can be and
its prefix and hex share a buffer; the identity's two file buffers
became one; one keystream block serves sending and receiving. The line
editor lost its string-library calls for two loops. 534 bytes free.

### 5.28 One set of keys for the three clients (2026-09-07)

The gopher, FTP and SSH clients grew their keys one at a time, and the
seams showed: RUN/STOP meant back in two places and quit in one, Q
meant quit in two and was a letter for the host in the third, H meant
the host screen in one, and bookmarks existed in two. The scheme now,
in all three: cursor keys, RETURN and HOME move, select and open;
RUN/STOP backs out one level at a time and, from the start screen,
quits; HELP is the way to the start screen from anywhere, ending a
session or a listing first; MEGA+M bookmarks the current place and
MEGA+F and MEGA+B cycle the colours; plain letters act on the content
and stay app-specific (the gopher client's A and G, the FTP client's
U, G, P, D and R). The principle behind it is this client's: in a
session every plain key belongs to the host, so the application's own
functions live on HELP, RUN/STOP at its own screens, and MEGA with a
letter, and any terminal-shaped program to come inherits the same
keys. The one bend is RUN/STOP inside a session, which must reach the
host as Control-C; HELP is back there. This client needed only
bookmarks (5.27); the FTP client's changes are ftpc 5.11, the gopher
client's gopher 2.52, and each README carries the same tables.

### 5.29 MEGA with a letter, measured; and a card that came back empty (2026-09-07)

The FTP client's MEGA+M did nothing for the user (ftpc 5.12). The key
probe with MEGA held: M alone is `$6D` with no modifier; MEGA+M is
`$CD`, MEGA+F `$C6`, MEGA+B `$C2`, each with `$D611` bit 3 set. So
MEGA with a letter delivers the capital letter with bit 7 set, and
this client's MEGA+F, MEGA+B and MEGA+M had never matched their
letters (5.20 said the cycle waited for a finger, and the finger's
report had covered other things). All three clients now mask the bit
off when MEGA is held, before comparing; the platform notes record
the codes. Version 0.4.1 here, gopher 0.4.1, FTP 0.4.2.

The same afternoon the deploy tool reported carrying only the identity,
and the identity it carried was the build's empty placeholder: the
card's SSH.D81 had become a fresh image with no KNOWNHOSTS, SSHAUTH,
SSHMARKS or key before the tool fetched it. The deploy before had
carried all four. What replaced the disk between is not known here; a
release image copied to the card by hand would do it, and so would a
damaged FAT. The tool kept no copy of what it fetched, so the key is
gone. From now on `tools/deploy.py` saves every image it fetches under
`build/deploy/card-<date>.d81`, says which of the four files it did not
find, and does not count the placeholder as an identity.

### 5.30 The empty file that copied 64 KB (2026-09-07)

The user copied the release image to the card and the screen came up as
junk after "gathering randomness", every cell a broken glyph. The font
copy at `$11000` read back as garbage with the pointer still on it, and
the status row had held junk for a moment before the client redrew it.
Reproduced here with the same copy. The cause is the disk loader,
`cbmdos_load`: it works out the bytes in a file's last block from the
block's link bytes, and for an empty file that number is zero, which it
handed to `lcopy`. A DMA of length zero copies 64 KB (mega-net
PLATFORM.md, trap 7), here from the loader's sector buffer in bank 0
over the client's own variables, the I/O area, the screen, the font and
most of the crypto image; the client limped to the host screen because
the bank is not called again until connect. The streaming reader in the
same file had the guard from the FTP client's day; the whole-file
loader never did, and the three clients share it. Guarded in all three.

Every disk deployed with `tools/deploy.py` carried a real 64-byte
IDENTITY, so the count was never zero for me; the empty placeholder of
5.26 is what made it zero, and 5.26's own report, the first generation
on a bare disk creating no file, was this bug and not the disk write.
The placeholder stays: with the guard it loads as nothing, as it was
meant to. Verified: the release image copied plainly to the card, the
host screen drawn with the right glyphs, the font bytes read back as
the ROM's. Version 0.4.2; gopher 0.4.2; FTP 0.4.3.

### 5.35 285 bytes of stack: the receive buffer to $0800 (2026-09-29)

Measured from the map while planning SFTP: the data ended at $CEE3,
leaving 285 bytes for the soft stack above it, where the family's
floor is 1,024 (gemini 5.6's boot crash, mega-irc 5.16). This build
never checked; `build.py` now does, with the IRC client's
`check_headroom`, and dies under the floor.

Two moves, both the IRC client's. `ssh_rx`, the 2 KB receive buffer,
is the ROM's old screen page, $0800-$0FFF: the screen is at $10000,
the KERNAL and its interrupts are mapped out, and nothing else here
touches the page. The disk layer's sector buffer and BAM copy go to
$1100 and $1300 (`-DF011_BUF_AT`, `-DBAM2_AT`), which is safe because
this client leaves through the ROM's reset, which rebuilds that page.
Room now 3,190 bytes.

One bug on the way, found on the machine: channel.c built its
messages with `sizeof msg`, and `msg` is `ssh_rx`, now a pointer, so
every message was two bytes long and the server hung up with
"Incomplete packet" after the login. `SSH_RX_MAX` at all nine sites,
and a note beside the macro.

Verified on the machine against the test server with a real shell:
password login, commands run on the Mac and their files checked,
2,000 lines of output scrolled with the session still answering
after, and a bookmark saved with MEGA-M whose SSHMARKS on the disk
read back correctly with IDENTITY, KNOWNHOSTS and SSHAUTH unchanged.

The deploy tool stalled twice on its upload, a second card session
straight after the first (a fetch); it deleted SSH.D81 first each
time, and the card was left with an empty one. The identity came back
from the tool's own backup under build/deploy. Every deploy tool in
the family now resets before the upload and bounds each card command
at 300 s, and mega-net's `stage_d81` resets between its fetch and its
upload.

### 5.34 SSHCRYPTO: one disk for the family (2026-09-25)

The user asked for a single `net-tools.d81` carrying the SSH, FTP,
Gopher, IRC and NTP clients. This client and the IRC client each loaded
a different program called `CRYPTO`, so they could not share a disk.
The bank is `SSHCRYPTO` now (loader and build; 0.4.7), the IRC client's
is `IRCCRYPTO`. The combined disk lives at `Original/net-tools.d81`:
five programs, one `meganet` (byte-identical on every disk), and each
client's own files. All five booted from it on the machine.

### 5.33 The symbols a hidden prompt hides: \ ^ { } | ~ (2026-09-25)

A user reported that typing a password to `sudo -i` inside a session
"isn't recognised", though the shell itself works. The client never
recognises a password; it forwards keystrokes. So either some keys
arrive as the wrong bytes, or not at all, and a prompt with echo off
is where that goes unseen.

Measured at the consumer: every key pressed plain and shifted through
the keyboard-matrix injector, into `cat > file` on the test server,
one key a line, and the file read on the Mac. Letters, digits, and
every shifted digit and punctuation mark arrive as their legends say.
Five did not: `£` and `↑` sent **nothing**, and so did SHIFT with `+`,
`-`, `@` and `*`. The controller reports Latin-1 `$A3` for the pound
key and `$AF` for the up-arrow, and `$FF` (no ASCII) for the C64
graphics chords; `map_key` dropped everything at or above `$80`. So
`\ ^ | ~ }` could not be typed at all, and `{` only by SHIFT+0. A
hidden prompt as sudo does it (`stty -echo; read`) then received
`p^sw{}` for `p^s|w~{}`, exactly the reporter's symptom.

**The keys now.** `£` is `\`, `↑` is `^`, MEGA with `:` and `;` are
`{` and `}` as SHIFT gives `[` and `]`, MEGA with `/` is `|`, and MEGA
with `←` is `~` (SHIFT there is the backtick, as on a PC). All seven
verified into `cat`, and the hidden prompt now receives `p^s|w~{}`
whole. Released as 0.4.6.

**Why not SHIFT or MEGA with `£` and `↑`.** With any modifier held
those two keys deliver nothing to a running program, though the
halted-CPU probe (`tap.py --probe`) shows `$A3` and `$AF` queued for
them, and shows MEGA+`/` as `/` where the client actually receives
`\`. **The probe misreports modifier chords; measure at the
consumer.** Two builds went out on the probe's word before that was
learned.

**Two harness faults on the way.** A Python patch whose assertion
failed stopped before writing, and the unguarded shell chain built,
deployed and tested the old code as if it were new; guard the patch.
And `stage_d81` called `mega65_ftp` without a reset or a time bound:
with the machine left in a program it hung ten minutes holding the
port, and ending it wedged the FTDI adapter until a power cycle. It
now resets first, truncates its staging file, and is bounded, in
mega-net's `m65lib.sh`.

### 5.32 The background changed on connect: one colour with two owners (2026-09-23)

The user reported it: the background changes when a session opens.
Measured inside their live session, the registers read border `$00`,
background `$06` -- a pair this client never sets on purpose, since it
keeps the two identical (5.31).

The in-session MEGA+B handler in `sshc.c` cycled a *local* `loc_bg` and
called `ck_term_recolour`, which wrote both registers and the
terminal's `def_bg` -- but never told `m65_screen.c`. The module's
`start_bg` kept the value it had inherited at start. On the next
connect `ck_term_init` was seeded from `m65_screen_bg_colour()`, the
stale value, and `term_init` stamped it into `$D021`, while `$D020`,
which `term_init` never writes, kept the colour MEGA+B had chosen. Two
owners of one colour, agreeing until the first press and never again.

Reproduced against `tools/ssh_test_server.py` on 2223, the registers
read through the monitor at each step (never a screen capture in a
session, 5.24): `06/06` at the Host prompt, `06/06` connected, `00/00`
after MEGA+B, `00/00` back at the prompt, **`00/06` after
reconnecting**. That mismatched pair is the whole proof.

**The fix.** The handler cycles through `m65_screen_cycle_text_colour()`
and `m65_screen_cycle_background()` and reads the values back into
`loc_fg`/`loc_bg` before `ck_term_recolour`, so the module is the one
authority. The duplicated cycling logic went with it, including a
second `pressed` static that carried its own idea of "the first press
goes to black". Neither cycle fills colour RAM (only `m65_screen_init`
does), so the terminal's per-cell colours survive the call.

Verified on the machine with the fixed build deployed (identity,
sshauth and knownhosts carried): the same sequence ends `00/00` after
the reconnect, and a MEGA+F inside the session leaves the background
at `00`. Released as 0.4.5.

**Two things that cost time getting here.** HELP ends a session onto an
"any key for the host screen" page and *waits*; a script that dials
again before pressing that key types the host name as the key and the
rest of the prompts into nothing, and "NO REPLY FROM THE HOST" follows.
Two reproductions failed that way before the page was looked at. And a
test server whose output is piped through `head` stops logging once
`head` has its lines: the log froze at forty lines and read as "the
client never connected", which was false. A server runs forever;
redirect it to a file.

### 5.31 The screen background is the user's (2026-09-07)

Reported: with the background and border set to black in BASIC, the
background came up blue after connecting, the border still black, and
MEGA+B put it right. The screenshot was late.sh's splash. The host
replay of that splash, and of the main screen, showed the parser
following exactly the default it was given, black staying black; on
the machine, BASIC's `background 0` and `border 0`, the host screen,
the shell and a full `clear` all left `$D021` at black and the bank's
default at black. So the blue was the other half of 5.20: a host that
sets a background and then clears took the screen background with it,
as a full-screen program's background was meant to, and a welcome
screen or a colored program does exactly that. The user's rule is the
better one: the screen background belongs to the user, inherited from
BASIC or cycled with MEGA+B, and a host's background is drawn per
cell, reversed where it differs, which the terminal already did for
spans. A full clear now sets `$D021` to the client's default only.
Verified: black set, a host `tput setab 4; clear` left the background
and border black and the cells reversed in blue; the suite's check
turned around to say so. Version 0.4.3. 5.20's "background follows a
full clear" is withdrawn.
