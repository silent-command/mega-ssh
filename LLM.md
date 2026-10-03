# mega-ssh

An SSH-2 client for the MEGA65 on mega-net: curve25519-sha256,
ssh-ed25519, chacha20-poly1305@openssh.com, strict kex, password and
Ed25519 public-key login with an identity made on the machine, trust
on first use, a VT100 with color in 25 or 50 rows. C99 for llvm-mos,
`-Oz`, the inner loops in assembly on the math unit. Version in
`src/sshc.c` (`SSHC_VERSION`) and `src/transport.c` (`VERSION_STRING`).
0BSD. Releases carry `bin/SSH.D81`, which must never contain
`IDENTITY`, `SSHAUTH`, `KNOWNHOSTS` or `SSHMARKS` (the build does not put them there; do not add them).

## Read first

1. This file.
2. `../mega-net/docs/PLATFORM.md`: the machine, the family's memory
   map, the traps, the tools, the test driver.
3. `REQUIREMENTS.md`: section 2 decisions (one algorithm per kind, no
   constant time, queries unanswered), section 4 the plan, section 5
   the findings, 5.1 to 5.25 (the numbers skip from 5.11 to 5.19).
4. The README's "How it fits" for the shape; `tools/sizes.py` for
   where every byte is today.

## Commands

```
python3 build.py test     the crypto suite (RFC vectors) and the terminal suite; the gate for any change
python3 build.py          the client, the crypto bank (CRYPTO, TERM) and bin/SSH.D81; refuses on the 5.6 miscompile shape
python3 tools/deploy.py   SSH.D81 onto the card, carrying IDENTITY, SSHAUTH and KNOWNHOSTS over; the only way to redeploy
python3 tools/sizes.py    code and data per file, client and bank
TERM_TRACE=1 python3 build.py     a 64-byte ring of what the terminal parser received, read from the monitor (5.21)
build/venv/bin/python tools/ssh_test_server.py 2222            the echo shell, password mega65/mega65
build/venv/bin/python tools/ssh_test_server.py 2223 --shell --pubkey   a real zsh on a pty, any key accepted
                        ... --other-key | --big-banner | --drop-in-kex | --no-common   one adversary each
cc -std=c99 -O2 -Wno-unused-function -I src -I src/bank -I src/platform tests/term_replay.c src/glyph.c -o build/host/term_replay
build/host/term_replay CAPTURE [50]      replay a captured stream and print the screen and colors
```

`python3 build.py venv` makes the asyncssh environment. The test server
runs with `line_editor=False`; without it every full-screen program
looks broken (5.21).

On the machine, with `tools/m65ssh.sh` (which sources mega-net's
driver):

```
source tools/m65ssh.sh
deploy                                        tools/deploy.py
boot_ssh                                      to the Host prompt, retrying the start-up stick
login 192.168.1.232 2223 mega65 mega65 ' % '  password login, waits for the zsh prompt
login_key 192.168.1.232 2223 mega65 ' % '     identity login, generating one if the disk has none
```

**Never take a screenshot while a session is running**; it wedges the
monitor until a power cycle (5.23, 5.24). Poll the client's own
screens between sessions, or read memory with `mon.py`. In-session
behavior is verified by host replay of a captured stream, or by the
user's eyes.

## What is mine in memory

Bank 0 `$1700`: the crypto trampoline. Bank 1: the screen at `$10000`
(4000 cells for 50 rows), the font copy at `$11000`, the crypto image
at `$12000` (`crypto.ld`: `ram` `$2000-$BDFF` in the bank's map, soft
stack `$BE00-$BFFF`), the terminal parser at `$1E000-$1F7FF` (the `hi`
region; `$1F800` up is the color RAM mirror). Bank 5 `$5E900`: the
known-hosts text; `$11800` the bookmark text. The client: `$2001` to
about `$CE00`, 500 bytes free, without the console library (5.27). The
bank: about 300 bytes free in `ram`, 200 in `hi`. Before adding code,
find its bytes; the findings 5.4, 5.7 and 5.22 say what was moved and
how (buffers built in `ssh_rx` while idle, hashes rolled, the
self-test entry dropped, `-Oz`).

## Rules

- The host proves the arithmetic; the machine measures it. A primitive
  that has not passed its RFC vectors does not go near the MEGA65; a
  terminal change is proved by `tests/test_term.c` and a replay first.
- Every wait is bounded on `$D7FA`; mega-net is polled from every loop,
  including inside the crypto (the bank yields with the map swapped).
- The client owns its interrupt vectors as its first instruction and
  quiets `$D6E0` before mega-net's INIT (5.8, 5.19); never reorder
  `main`'s first lines.
- Loops are pointer walks, never `while (n--)` (5.6); the checker runs
  on every build. In assembly: no branch further than 127 bytes, Q
  instructions through the `LDQA`/`STQA` macros, Z zero before C (5.3,
  5.11).
- No `int64_t`; `uint32_t` only in accumulators; the bank links no
  32-bit multiply or divide helper, so none may be introduced (5.22).
- The terminal answers no query (5.7). Color values are ANSI 0-15,
  or 16 plus a machine color, or NONE (5.22).
- The identity is the user's account on a key-authenticated server:
  never regenerate it, never redeploy without `tools/deploy.py`, never
  read `IDENTITY` off the card into a log. Ask before anything that
  touches it.
- A screenshot proves screen memory; the text screenshot renders the
  RAM font as uppercase; for the picture, the PNG, and only between
  sessions.
- Record every hardware finding in `REQUIREMENTS.md`, numbered, with
  what was seen and what it cost.
- Commits are local until the user asks for a push or a release. A
  release bumps `SSHC_VERSION` and `VERSION_STRING` together, rebuilds,
  tags `vX.Y.Z`, and attaches `SSH.D81` with a short note ending in how
  to run it.

## Not to reopen

One algorithm per kind; RSA, AES, HMAC and compression are refused,
not faked. Trust on first use, no certificates. Constant time is not a
goal. `TERM=vt100`. The screen at `$10000` for both row counts. Queries
unanswered. Randomness is timing jitter and the README says so.

## Open

Re-keying (OpenSSH asks after an hour or a gigabyte; the session ends
there). The two-hour idle soak. Wide characters in the terminal (none
seen yet). The one-in-twenty start-up stick, which is mega-net's (5.19).
