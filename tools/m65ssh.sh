# The SSH client's hardware recipes, on mega-net's driver. Source it:
#
#   source tools/m65ssh.sh
#   deploy                                        the disk, keeping IDENTITY, SSHAUTH, KNOWNHOSTS
#   boot_ssh                                      reset, mount, run, the Host prompt
#   login HOST PORT USER PASS MARKER              the prompts in order, the trust question answered, MARKER awaited
#   login_key HOST PORT USER MARKER               identity login; generates the identity if the disk has none
#
# Never screenshot while a session is running (REQUIREMENTS.md 5.24): the
# functions here read the screen only on the client's own pages.

HERE="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
source "$HERE/../../mega-net/tools/m65lib.sh"

deploy() { python3 "$HERE/deploy.py" --port "$MEGA65_PORT" 2>&1 | tail -1; }
boot_ssh() { boot_prg ssh.d81 ssh 'ost:'; }

# The Host, Port, Auth, User and Password prompts; then the trust question
# if the host is new; then MARKER on screen means the shell is up.
_await_shell() { local t=0 s; while [ $t -lt 120 ]; do s=$(row 23); case "$s" in *"to trust"*|*"TO TRUST"*) type_keys y;; *"connect:"*|*"login:"*|*"session:"*|*"CONNECT:"*|*"LOGIN:"*|*"SESSION:"*) echo "stopped: $s"; return 1;; esac; raw | grep -qi -- "$1" && { echo "shell after ${t}s"; return 0; }; sleep 1; t=$((t+1)); done; echo "no shell in 120s" >&2; return 1; }
login() { type_line "$1"; type_line "$2"; type_line "p"; type_line "$3"; type_line "$4"; _await_shell "$5"; }
login_key() { type_line "$1"; type_line "$2"; type_line "i"; type_line "$3"; sleep 2; if raw | grep -qi 'no identity'; then echo "  no identity: generating"; type_keys g; wait_for 'SHA256:' 40 >/dev/null; type_keys '~M'; fi; _await_shell "$4"; }
