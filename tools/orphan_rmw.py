#!/usr/bin/env python3
"""Scans a linked ELF for the miscompile REQUIREMENTS.md 5.6 records: a
16-bit inw/dew on a zero-page word that the same function never loads
or stores otherwise, i.e. a counter the loop tests somewhere else.
    python3 tools/orphan_rmw.py bin/ssh.prg.elf [llvm-objdump]
Exit status 1 when it finds one."""
import re, subprocess, sys, os
elf = sys.argv[1]
od = sys.argv[2] if len(sys.argv) > 2 else os.path.expanduser("~/llvm-mos/bin/llvm-objdump")
out = subprocess.run([od, "-d", "--no-show-raw-insn", elf], capture_output=True, text=True).stdout
# the argument registers start at __rc0, which each image places differently
nm = subprocess.run([os.path.join(os.path.dirname(od), "llvm-nm"), elf], capture_output=True, text=True).stdout
rc0 = next((int(l.split()[0], 16) for l in nm.splitlines() if l.endswith(" __rc0")), 0)
funcs, cur = {}, None
for l in out.splitlines():
    m = re.match(r'^[0-9a-f]+ <(.+)>:', l)
    if m: cur = m.group(1); funcs[cur] = []; continue
    m = re.match(r'^\s+([0-9a-f]+):\s+(\S+)\s*(.*)', l)
    if m and cur: funcs[cur].append((m.group(1), m.group(2), m.group(3)))
bad = 0
for name, ins in funcs.items():
    for addr, op, arg in ins:
        if op not in ("inw", "dew"): continue
        m = re.match(r'\$([0-9a-f]+)', arg)
        if not m: continue
        zp = int(m.group(1), 16)
        if rc0 <= zp < rc0 + 0x10: continue    # rc0-rc13 carry arguments in, so a bare inw/dew on one is normal
        touched = any(o not in ("inw", "dew") and re.match(r'\$(%x|%x)\b' % (zp, zp + 1), a) for _, o, a in ins)
        if not touched:
            print(f"{elf}: {name} at {addr}: {op} ${zp:02x} on a word the function never touches otherwise"); bad += 1
sys.exit(1 if bad else 0)
