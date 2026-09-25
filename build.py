#!/usr/bin/env python3
"""Build driver for the MEGA65 SSH client: Python, so that Windows, Linux
and macOS are all first-class development hosts.

    python3 build.py test       build and run the host crypto suite
    python3 build.py            build the client and bin/SSH.D81
    python3 build.py spike      build the spikes under src/spike/
    python3 build.py bank       the crypto bank image and its trampoline alone
    python3 build.py venv       the Python test server's environment (asyncssh)
    python3 build.py clean

It needs llvm-mos (mos-mega65-clang), CMake, c1541 from VICE, a C99 host
compiler, and the two sibling checkouts ../mega-net and
../mega65-libc; it builds mega65-libc and mega-net's
image itself when they are missing.

Overrides: CC, LLVM_MOS_DIR, MEGANET, LIBC_SRC, C1541.
"""
import os, platform, shutil, subprocess, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
BUILD = ROOT / "build"
BIN = ROOT / "bin"
IS_WINDOWS = platform.system() == "Windows"
MEGANET = Path(os.environ.get("MEGANET", ROOT.parent / "mega-net")).resolve()
LIBC_SRC = Path(os.environ.get("LIBC_SRC", ROOT.parent / "mega65-libc")).resolve()
LIBC_BUILD = BUILD / "libc"


def die(msg):
    print(f"error: {msg}", file=sys.stderr); sys.exit(1)


def run(cmd, **kw):
    print("  " + " ".join(Path(c).name if os.sep in str(c) else str(c) for c in cmd))
    if subprocess.run([str(c) for c in cmd], **kw).returncode != 0:
        die("command failed")


def find_tool(exe, roots=(), env=None):
    if env and os.environ.get(env):
        return os.environ[env]
    name = exe + (".exe" if IS_WINDOWS else "")
    for r in roots:
        cand = Path(r) / "bin" / name
        if cand.is_file():
            return str(cand)
    found = shutil.which(name)
    if found:
        return found
    for cand in ("/opt/homebrew/bin/" + name, "/usr/local/bin/" + name):
        if Path(cand).is_file():
            return cand
    die(f"{exe} not found")


def check_rmw(elf):
    """REQUIREMENTS.md 5.6: the compiler once decremented the wrong zero-page
    word in a loop; tools/orphan_rmw.py finds that shape in a linked ELF."""
    if not elf.exists():
        return
    objdump = find_tool("llvm-objdump", [Path(mos_clang()).parent.parent])
    r = subprocess.run([sys.executable, str(ROOT / "tools" / "orphan_rmw.py"), str(elf), objdump])
    if r.returncode:
        die(f"{elf.name}: the loop miscompile of 5.6 is back; rewrite the loop it names")


def mos_clang():
    roots = [os.environ["LLVM_MOS_DIR"]] if os.environ.get("LLVM_MOS_DIR") else []
    roots += [Path.home() / "llvm-mos", "/opt/llvm-mos", "/usr/local/llvm-mos"]
    return find_tool("mos-mega65-clang", roots)


def host_cc():
    if os.environ.get("CC"):
        return os.environ["CC"]
    for c in ("cc", "gcc", "clang", "cl"):
        if shutil.which(c):
            return c
    die("no host C compiler found; set CC")


def ensure_libc():
    lib = LIBC_BUILD / "src" / "libmega65libc.a"
    if lib.is_file():
        return lib
    if not LIBC_SRC.is_dir():
        die(f"mega65-libc not found at {LIBC_SRC}; set LIBC_SRC")
    print("building mega65-libc for llvm-mos:")
    prefix = Path(mos_clang()).parent.parent
    run(["cmake", f"-DCMAKE_PREFIX_PATH={prefix}", "-B", LIBC_BUILD, "-S", LIBC_SRC])
    run(["cmake", "--build", LIBC_BUILD])
    return lib


def ensure_meganet():
    image = MEGANET / "build" / "m65" / "meganet.bin"
    tramp = MEGANET / "build" / "gen" / "meganet_tramp.c"
    if not (image.is_file() and tramp.is_file()):
        if not MEGANET.is_dir():
            die(f"mega-net not found at {MEGANET}; set MEGANET")
        print("building mega-net:")
        run([sys.executable, "build.py", "abi"], cwd=MEGANET)
    return image, tramp


def cflags(libc_src):
    extra = os.environ.get("EXTRA_CFLAGS", "").split()
    # -Oz: 32-bit arithmetic inflates -Os builds on this CPU (the same finding as mega-net 5.17)
    return ["-Oz", "-I", str(libc_src / "include"), "-I", str(MEGANET / "src" / "abi"),
            "-I", str(MEGANET / "build" / "gen"), "-I", str(ROOT / "src" / "platform"),
            "-I", str(ROOT / "src" / "crypto"), "-I", str(ROOT / "src"),
            "-Wall", "-Wextra", "-Werror", "-Wno-unused-parameter"] + extra


def platform_sources():
    return sorted(str(p) for p in (ROOT / "src" / "platform").glob("*.c")) + \
           sorted(str(p) for p in (ROOT / "src" / "platform").glob("*.S"))


def crypto_sources(target=True):
    srcs = sorted(str(p) for p in (ROOT / "src" / "crypto").glob("*.c"))
    if target:
        srcs += sorted(str(p) for p in (ROOT / "src" / "crypto").glob("*.S"))
    return srcs


def build_test():
    cc = host_cc()
    out = BUILD / "host"; out.mkdir(parents=True, exist_ok=True)
    exe = out / ("crypto_tests.exe" if IS_WINDOWS else "crypto_tests")
    srcs = crypto_sources(target=False) + [str(ROOT / "tests" / "test_crypto.c")]
    if Path(cc).name.lower().startswith("cl"):
        run([cc, "/nologo", "/W3", "/O2", "/I", str(ROOT / "src" / "crypto"), *srcs, f"/Fe:{exe}"])
    else:
        run([cc, "-std=c99", "-O2", "-Wall", "-Wextra", "-Werror", "-I", str(ROOT / "src" / "crypto"), *srcs, "-o", str(exe)])
    print("running the host crypto suite:")
    rc = subprocess.run([str(exe)]).returncode
    return rc or build_term_test()


def build_term_test():
    """The terminal on the host: tests/test_term.c includes src/bank/term.c
    with TERM_HOST_TEST, under which the screen is two arrays."""
    cc = host_cc()
    out = BUILD / "host"; out.mkdir(parents=True, exist_ok=True)
    exe = out / ("term_tests.exe" if IS_WINDOWS else "term_tests")
    srcs = [str(ROOT / "tests" / "test_term.c"), str(ROOT / "src" / "glyph.c")]
    inc = ["-I", str(ROOT / "src"), "-I", str(ROOT / "src" / "bank"), "-I", str(ROOT / "src" / "platform")]
    if Path(cc).name.lower().startswith("cl"):
        run([cc, "/nologo", "/W3", "/O2", "/I", str(ROOT / "src"), "/I", str(ROOT / "src" / "bank"), *srcs, f"/Fe:{exe}"])
    else:
        run([cc, "-std=c99", "-O2", "-Wall", "-Wextra", "-Werror", "-Wno-unused-function", *inc, *srcs, "-o", str(exe)])
    print("running the host terminal suite:")
    return subprocess.run([str(exe)]).returncode


def emit_payload(gen, tramp, image, term):
    """build/gen/ck_payload.{c,h}: the trampoline as a C array, and the
    image's size, for the client's boot code."""
    gen.mkdir(parents=True, exist_ok=True)
    tb = tramp.read_bytes()
    (gen / "ck_payload.h").write_text(
        "/* generated by build.py: the crypto trampoline and the image size */\n"
        "#ifndef CK_PAYLOAD_H\n#define CK_PAYLOAD_H\n"
        f"#define CK_TRAMP_SIZE {len(tb)}\n#define CK_BIN_SIZE {image.stat().st_size}UL\n"
        f"#define CK_TERM_SIZE {term.stat().st_size}UL\n"
        "extern const unsigned char ck_tramp_bin[CK_TRAMP_SIZE];\n#endif\n")
    body = ", ".join(f"0x{x:02x}" for x in tb)
    (gen / "ck_payload.c").write_text(f'#include "ck_payload.h"\nconst unsigned char ck_tramp_bin[CK_TRAMP_SIZE] = {{ {body} }};\n')


def build_bank():
    """The crypto bank: a headerless image for bank 1 and its trampoline."""
    clang = mos_clang()
    out = BUILD / "bank"; out.mkdir(parents=True, exist_ok=True)
    gen = BUILD / "gen"
    bank = ROOT / "src" / "bank"
    warn = ["-Wall", "-Wextra", "-Werror", "-Wno-unused-parameter"]
    tramp = out / "ck_tramp.bin"
    print("crypto trampoline:")
    run([clang, "-nostartfiles", "-nostdlib", "-T", str(bank / "trampoline.ld"), str(bank / "trampoline.S"), "-o", str(tramp)])
    hi_objs = []
    for src in (bank / "term.c",):
        obj = out / (src.stem + ".o")
        trace = ["-DTERM_TRACE"] if os.environ.get("TERM_TRACE") else []   # a byte ring for hardware readback (5.21)
        run([clang, "-std=c99", "-Oz", "-fno-lto", "-c", "-I", str(ROOT / "src" / "crypto"), "-I", str(bank),
             "-I", str(ROOT / "src")] + warn + trace + [str(src), "-o", str(obj)])
        hi_objs.append(str(obj))
    both = out / "bank.bin"
    print("crypto image:")
    run([clang, "-std=c99", "-Oz", "-nostartfiles", "-T", str(bank / "crypto.ld"), f"-Wl,-Map={out / 'crypto.map'}",
         "-I", str(ROOT / "src" / "crypto"), "-I", str(bank), "-I", str(ROOT / "src"), "-I", str(ROOT / "src" / "platform")] + warn +
        [str(bank / "jumptable.S"), str(bank / "api.c"), str(bank / "dma.c"), str(bank / "termscr.c"),
         str(ROOT / "src" / "glyph.c")] + hi_objs + crypto_sources() + ["-o", str(both)])
    data = both.read_bytes()
    RAM_LEN = 0x9E00
    if len(data) < RAM_LEN:
        die("the bank image is shorter than its first region; is OUTPUT_FORMAT FULL(ram)?")
    image = out / "crypto.bin"
    image.write_bytes(data[:RAM_LEN].rstrip(b"\0") or b"\0")
    term = out / "term.bin"
    term.write_bytes(data[RAM_LEN:].rstrip(b"\0") or b"\0")
    first = image.read_bytes()[0]
    print(f"  {image.name}: {image.stat().st_size} bytes, first byte ${first:02x} ({'jmp: ok' if first == 0x4c else 'NOT a jmp!'})")
    print(f"  {term.name}: {term.stat().st_size} bytes (the terminal, for $1E000)")
    if first != 0x4c:
        die("the jump table is not at the start of the image")
    check_rmw(both.with_suffix(".bin.elf"))
    emit_payload(gen, tramp, image, term)
    return image, term


def build_spikes():
    clang = mos_clang(); lib = ensure_libc(); image, tramp = ensure_meganet()
    out = BUILD / "spike"; out.mkdir(parents=True, exist_ok=True)
    lib_srcs = sorted(str(p) for p in (ROOT / "src").glob("*.c") if p.stem in ("ui", "wire", "screen", "glyph"))
    for src in sorted((ROOT / "src" / "spike").glob("*.c")):
        prg = out / (src.stem + ".prg")
        print(f"{src.stem}:")
        run([clang] + cflags(LIBC_SRC) + [str(src)] + lib_srcs + crypto_sources() + platform_sources() +
            [str(tramp), str(lib), f"-Wl,-Map={out / (src.stem + '.map')}", "-o", str(prg)])
        print(f"  {prg.name}: {prg.stat().st_size} bytes")
    c1541 = find_tool("c1541", env="C1541")
    d81 = out / "SPIKE.D81"
    shutil.copy(image, out / "meganet")
    if d81.exists():
        d81.unlink()
    cmd = [c1541, "-format", "spike,sp", "d81", d81, "-write", out / "meganet", "meganet"]
    for prg in sorted(out.glob("*.prg")):
        cmd += ["-write", prg, prg.stem.replace("spike_", "")]
    run(cmd, stdout=subprocess.DEVNULL)
    run([c1541, "-attach", d81, "-dir"])
    return 0


def build_client():
    clang = mos_clang(); lib = ensure_libc(); image, tramp = ensure_meganet()
    BIN.mkdir(exist_ok=True)
    srcs = sorted(str(p) for p in (ROOT / "src").glob("*.c"))
    if not srcs:
        print("no client sources yet (src/*.c); build the spikes with `python3 build.py spike`")
        return 0
    prg = BIN / "ssh.prg"
    cimage, cterm = build_bank()
    gen = BUILD / "gen"
    print("client:")
    run([clang] + cflags(LIBC_SRC) + ["-I", str(gen),] + srcs + platform_sources() +
        [str(gen / "ck_payload.c"), str(tramp), str(MEGANET / "src" / "abi" / "meganet_vectors.c"), str(lib),
         f"-Wl,-Map={BIN / 'ssh.map'}", "-o", str(prg)])
    print(f"  {prg.name}: {prg.stat().st_size} bytes")
    check_rmw(prg.with_suffix(".prg.elf"))
    c1541 = find_tool("c1541", env="C1541")
    d81 = BIN / "SSH.D81"
    shutil.copy(image, BIN / "meganet")
    if d81.exists():
        d81.unlink()
    shutil.copy(cimage, BIN / "sshcrypto")
    shutil.copy(cterm, BIN / "term")
    empty = BUILD / "empty.seq"                     # an empty IDENTITY ships on the disk: the first generation
    empty.write_bytes(b"")                          # on a disk without one did not create the file (5.26)
    run([c1541, "-format", "ssh,ss", "d81", d81, "-write", prg, "ssh", "-write", BIN / "meganet", "meganet",
         "-write", BIN / "sshcrypto", "sshcrypto", "-write", BIN / "term", "term",   # SSHCRYPTO, not CRYPTO: the IRC client's bank shares a disk with it on net-tools.d81
         "-write", empty, "identity,s"], stdout=subprocess.DEVNULL)
    run([c1541, "-attach", d81, "-dir"])
    return 0


def build_venv():
    venv = BUILD / "venv"
    py = venv / ("Scripts/python.exe" if IS_WINDOWS else "bin/python")
    if not py.is_file():
        run([sys.executable, "-m", "venv", str(venv)])
    run([str(py), "-m", "pip", "install", "-q", "asyncssh"])
    print(f"test server: {py} tools/ssh_test_server.py")
    return 0


def main():
    target = sys.argv[1] if len(sys.argv) > 1 else "client"
    if target == "client":
        return build_client()
    if target == "spike":
        return build_spikes()
    if target == "test":
        return build_test()
    if target == "venv":
        return build_venv()
    if target == "bank":
        return 0 if build_bank() else 1
    if target == "clean":
        shutil.rmtree(BUILD, ignore_errors=True); shutil.rmtree(BIN, ignore_errors=True); return 0
    print(__doc__); die(f"unknown target '{target}'")


if __name__ == "__main__":
    sys.exit(main())
