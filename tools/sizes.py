#!/usr/bin/env python3
"""Compile every source for the MEGA65 without link-time merging and
print each object's code and data size, largest first. For finding where
the bytes go when the program does not fit."""
import os, subprocess, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LLVM = Path(os.environ.get("LLVM_MOS_DIR", Path.home() / "llvm-mos")) / "bin"
MEGANET = ROOT.parent / "mega-net"
LIBC = ROOT.parent / "mega65-libc"
OUT = ROOT / "build" / "sizes"
OUT.mkdir(parents=True, exist_ok=True)
inc = ["-I", str(ROOT / "src"), "-I", str(ROOT / "src" / "crypto"), "-I", str(ROOT / "src" / "platform"),
       "-I", str(MEGANET / "src" / "abi"), "-I", str(MEGANET / "build" / "gen"), "-I", str(LIBC / "include")]
srcs = sorted((ROOT / "src").glob("*.c")) + sorted((ROOT / "src" / "crypto").glob("*.c")) + \
       sorted((ROOT / "src" / "crypto").glob("*.S")) + sorted((ROOT / "src" / "platform").glob("*.c")) + \
       sorted((ROOT / "src" / "platform").glob("*.S")) + [MEGANET / "build" / "gen" / "meganet_tramp.c"]
objs = []
for s in srcs:
    o = OUT / (s.name + ".o")
    r = subprocess.run([str(LLVM / "mos-mega65-clang"), "-Oz", "-fno-lto", "-c", *inc, str(s), "-o", str(o)],
                       capture_output=True, text=True)
    if r.returncode == 0:
        objs.append(o)
    else:
        print("failed:", s.name, r.stderr.strip().splitlines()[-1] if r.stderr.strip() else "")
r = subprocess.run([str(LLVM / "llvm-size"), *map(str, objs)], capture_output=True, text=True)
rows = []
for line in r.stdout.splitlines()[1:]:
    f = line.split()
    if len(f) >= 6:
        rows.append((int(f[0]), int(f[1]), int(f[2]), Path(f[5]).name.replace(".o", "")))
rows.sort(reverse=True)
tt = td = tb = 0
for t, d, b, n in rows:
    print("%6d text %5d data %6d bss  %s" % (t, d, b, n)); tt += t; td += d; tb += b
print("%6d text %5d data %6d bss  TOTAL" % (tt, td, tb))
