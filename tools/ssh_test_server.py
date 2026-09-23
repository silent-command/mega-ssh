#!/usr/bin/env python3
"""A controllable SSH server for testing the MEGA65 client.

    build/venv/bin/python tools/ssh_test_server.py [port] [--shell]

Port 2222 by default. User `mega65`, password `mega65`. Host key: an
Ed25519 key generated once into build/test_host_key. Algorithms
restricted to what the client offers, so a mismatch shows up here first.
A session gets a small echoing shell: each line typed comes back, `quit`
ends it. With --shell it gets a real zsh on a pseudo-terminal instead,
sized from the pty request, TERM=vt100: that is a shell on this
machine for anyone who knows the test password, so run it only while
testing the terminal, on its own port. asyncssh's own line editor is
off: it echoes keys at the cursor and holds a line until RETURN, which
no full-screen program survives (REQUIREMENTS.md 5.21). LOG_OUT=<file>
records every pty read, each prefixed "##raw/encoded##". The
adversarial variants are flags, one server per flag."""
import asyncio, sys, os, pty, fcntl, termios, struct, signal
from pathlib import Path
import asyncssh, logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s %(message)s')
asyncssh.set_log_level('DEBUG')
asyncssh.set_debug_level(2)

ROOT = Path(__file__).resolve().parent.parent
KEY = ROOT / "build" / "test_host_key"
ARGS = [a for a in sys.argv[1:] if not a.startswith("--")]
PORT = int(ARGS[0]) if ARGS else 2222
REAL_SHELL = "--shell" in sys.argv
# The adversarial variants (step 7): each is a flag, one server per flag.
OTHER_KEY = "--other-key" in sys.argv            # a fresh host key: the client must say the key CHANGED
BIG_BANNER = "--big-banner" in sys.argv          # a 4000-byte login banner: over the client's packet limit
DROP_IN_KEX = "--drop-in-kex" in sys.argv        # close the connection as soon as the key exchange begins
NO_COMMON = "--no-common" in sys.argv            # offer only algorithms the client does not speak
PUBKEY = "--pubkey" in sys.argv                  # accept any public key as well as the password (5.22)

if not KEY.exists():
    KEY.parent.mkdir(parents=True, exist_ok=True)
    asyncssh.generate_private_key("ssh-ed25519").write_private_key(str(KEY))
    print("generated", KEY)
if OTHER_KEY:
    KEY = ROOT / "build" / "test_other_key"
    if not KEY.exists():
        asyncssh.generate_private_key("ssh-ed25519").write_private_key(str(KEY))
        print("generated", KEY)

class Server(asyncssh.SSHServer):
    def connection_made(self, conn):
        print("connection from", conn.get_extra_info("peername")[0])
        self._conn = conn
        if DROP_IN_KEX:                                       # the client's exchange takes thirty seconds: this lands inside it
            asyncio.get_running_loop().call_later(4, self._drop)
    def _drop(self):
        print("dropping the connection in the key exchange")
        self._conn.abort()
    def begin_auth(self, username):
        if BIG_BANNER:
            self._conn.send_auth_banner("banner " * 570)          # 3990 bytes, over SSH_RX_MAX
        return True
    def password_auth_supported(self):
        return True
    def public_key_auth_supported(self):
        return PUBKEY
    def validate_public_key(self, username, key):
        print("public key auth", username, key.get_algorithm(), key.get_fingerprint())
        return True
    def validate_password(self, username, password):
        ok = username == "mega65" and password == "mega65"
        print("password auth", username, "ok" if ok else "REFUSED")
        return ok

async def handle(process):
    """A shell that behaves like a pty: echoes each character, ends a
    line on CR, answers it, `quit` closes with exit status 0."""
    process.stdout.write("Welcome to the MEGA65 SSH test server.\r\n$ ")
    line = ""
    try:
        while True:
            c = await process.stdin.read(1)
            if not c:
                break
            if c in ("\r", "\n"):
                process.stdout.write("\r\n")
                if line == "quit":
                    break
                process.stdout.write("you typed: " + line + "\r\n$ ")
                line = ""
            elif c in ("\x7f", "\b"):
                if line:
                    line = line[:-1]
                    process.stdout.write("\b \b")
            else:
                line += c
                process.stdout.write(c)
    except (asyncssh.BreakReceived, asyncssh.TerminalSizeChanged):
        pass
    process.exit(0)

async def handle_shell(process):
    """A real shell on a pseudo-terminal: the client's pty request sets
    the size, TERM is vt100, bytes are pumped both ways untouched."""
    cols, rows = 80, 25
    size = process.get_terminal_size()
    if size and size[0] and size[1]:
        cols, rows = size[0], size[1]
    master, slave = pty.openpty()
    fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))
    env = dict(os.environ, TERM="vt100", LANG="en_US.UTF-8", PS1="%~ %% ")
    child = await asyncio.create_subprocess_exec("/bin/zsh", "-f", "-i", stdin=slave, stdout=slave, stderr=slave,
                                                 env=env, start_new_session=True, preexec_fn=lambda: fcntl.ioctl(0, termios.TIOCSCTTY, 0))
    os.close(slave)
    loop = asyncio.get_running_loop()
    reader = asyncio.StreamReader()
    await loop.connect_read_pipe(lambda: asyncio.StreamReaderProtocol(reader), os.fdopen(master, "rb", 0, closefd=False))

    logf = open(os.environ["LOG_OUT"], "wb") if os.environ.get("LOG_OUT") else None
    async def to_client():
        while True:
            try:
                data = await reader.read(1024)
            except OSError:
                break
            if not data:
                break
            text = data.decode("utf-8", "replace")
            if logf:                                          # each pty read: raw length, encoded length, the raw bytes
                logf.write(b"\n##%d/%d##" % (len(data), len(text.encode("utf-8"))) + data); logf.flush()
            process.stdout.write(text)

    async def to_shell():
        while True:
            try:
                data = await process.stdin.read(1024)
            except (asyncssh.BreakReceived, asyncssh.TerminalSizeChanged):
                continue
            if not data:
                break
            os.write(master, data.encode("utf-8", "replace"))

    pump = asyncio.gather(to_client(), to_shell(), return_exceptions=True)
    try:
        await child.wait()
    finally:
        pump.cancel()
        try:
            os.close(master)
        except OSError:
            pass
    process.exit(child.returncode or 0)

async def main():
    kex = ["ecdh-sha2-nistp256"] if NO_COMMON else ["curve25519-sha256", "curve25519-sha256@libssh.org"]
    enc = ["aes128-ctr"] if NO_COMMON else ["chacha20-poly1305@openssh.com"]
    await asyncssh.create_server(Server, "", PORT, server_host_keys=[str(KEY)],
                                 process_factory=handle_shell if REAL_SHELL else handle,
                                 encoding="utf-8",
                                 line_editor=False,                 # asyncssh's own line editor echoes keys and holds lines until RETURN: vim and top cannot work through it (5.21)
                                 kex_algs=kex,
                                 encryption_algs=enc,
                                 server_version="mega65test")
    print("listening on", PORT, "fingerprint:",
          asyncssh.read_private_key(str(KEY)).get_fingerprint())
    await asyncio.Event().wait()

asyncio.run(main())
