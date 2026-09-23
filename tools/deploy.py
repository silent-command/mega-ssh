#!/usr/bin/env python3
"""Puts bin/SSH.D81 into net-tools on the MEGA65's SD card, keeping what the client
wrote on the disk already there: IDENTITY (the Ed25519 key that is the
user's account on a key-authenticated server), SSHAUTH (the
authentication default), KNOWNHOSTS and SSHMARKS (the bookmarks). Replacing the disk image outright loses all three
(REQUIREMENTS.md 5.22).

    python3 tools/deploy.py [--port /dev/cu.usbserial-23201] [image.d81]

Needs m65 and mega65_ftp from mega65-tools on the PATH (with or without
the .osx suffix) and c1541 from VICE. The machine is reset first, as
mega65_ftp needs; afterwards it sits at the BASIC prompt."""
import os, shutil, subprocess, sys, tempfile, time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
KEEP = ["identity", "sshauth", "knownhosts", "sshmarks"]          # c1541 wants lowercase; the client writes them upper-cased

def tool(name):
    for cand in (name, name + ".osx"):
        if shutil.which(cand):
            return cand
    sys.exit(f"{name} not found on the PATH")

def run(args, check=True):
    r = subprocess.run(args, capture_output=True, text=True)
    if check and r.returncode:
        sys.exit(f"{' '.join(str(a) for a in args)}\n{r.stdout}{r.stderr}")
    return r

def main():
    args = sys.argv[1:]
    port = os.environ.get("MEGA65_PORT", "/dev/cu.usbserial-23201")
    if "--port" in args:
        i = args.index("--port"); port = args[i + 1]; del args[i:i + 2]
    image = Path(args[0]) if args else ROOT / "bin" / "SSH.D81"
    if not image.exists():
        sys.exit(f"{image} not found: build first")
    m65, ftp, c1541 = tool("m65"), tool("mega65_ftp"), tool("c1541")
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        old, new = td / "old.d81", td / "SSH.D81"
        shutil.copy(image, new)
        run([m65, "-F"], check=False); time.sleep(2)                  # reset: mega65_ftp refuses a running program
        r = run([ftp, "-l", port, "-c", "cd net-tools", "-c", f"get SSH.D81 {old}"], check=False)
        kept, absent = [], []
        if old.exists() and old.stat().st_size == 819200:
            # A dated copy of what the card held, under build/deploy: the
            # identity is the user's account somewhere, and a disk that
            # lost it once was not recoverable (REQUIREMENTS.md 5.29).
            keep_dir = ROOT / "build" / "deploy"; keep_dir.mkdir(parents=True, exist_ok=True)
            backup = keep_dir / time.strftime("card-%Y%m%d-%H%M%S.d81")
            shutil.copy(old, backup)
            for name in KEEP:
                out = td / name
                run([c1541, str(old), "-read", f"{name},s", str(out)], check=False)
                real = out.exists() and out.stat().st_size and not (name == "identity" and out.stat().st_size != 64)
                if real:
                    run([c1541, str(new), "-delete", name], check=False)
                    run([c1541, str(new), "-write", str(out), f"{name},s"])
                    kept.append(name)
                else:
                    absent.append(name)
            print("the card's disk is kept as", backup.relative_to(ROOT))
            if absent:
                print("NOT on the card's disk, so not carried:", ", ".join(absent))
        else:
            print("no SSH.D81 on the card yet, nothing to keep")
        r = run([ftp, "-l", port, "-c", "cd net-tools", "-c", "del SSH.D81", "-c", f"put {new} SSH.D81"], check=False)
        if "in " not in r.stdout and "bytes" not in r.stdout:
            sys.exit(f"the upload did not report success:\n{r.stdout}{r.stderr}")
        print("deployed", image.name, "keeping", ", ".join(kept) if kept else "nothing")
        if "identity" in absent and old.exists() and len(list(keep_dir.glob("card-*.d81"))) > 1:
            print("an earlier card image under build/deploy may still hold the identity")

if __name__ == "__main__":
    main()
