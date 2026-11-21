# mega-ssh

An SSH client for the MEGA65. Log in to a modern OpenSSH server with a
password or a key made on the MEGA65, and use its shell in a VT100
terminal on the 80-column screen; programs such as vim and top work.

To our knowledge, this is the world's first SSH client for an 8-bit
computer. The key exchange, the encryption (curve25519, ed25519,
chacha20-poly1305) and the terminal all run on the MEGA65's own 8-bit
CPU, with no Wi-Fi modem or network adapter doing the cryptography for
it.

## Starting

Mount `SSH.D81` and type `RUN "SSH"`, or choose SSH from the
[Net-Tools](https://github.com/silent-command/mega-menu) menu. It needs a
network cable.

## Keys

At the Host prompt (then Port, Auth, User and Password):

| Key | Does |
|---|---|
| RETURN | accept |
| a number | open that bookmark |
| D and a number | delete that bookmark |
| F1 | your key: G makes one, R replaces it |
| P / I at Auth | log in with a password / with your key |
| RUN/STOP | quit to BASIC (at Host); start over (at the others) |

When a server is new, Y trusts it; any other key refuses.

In a session, these keys stay on the MEGA65:

| Key | Does |
|---|---|
| HELP | disconnect |
| MEGA+M | bookmark this server, or remove the bookmark |
| MEGA+K | type your public key into the session |
| MEGA+F / MEGA+B | change the text / background colour |

Everything else goes to the server. RUN/STOP sends Ctrl-C, CTRL+letter
sends that control code, and the cursor keys, CLR/HOME (Home),
SHIFT+CLR/HOME (End) and F1 to F12 work as on a PC terminal. For the
characters the MEGA65 keyboard lacks:

| Key | Types |
|---|---|
| £ | `\` |
| ↑ | `^` |
| MEGA+: / MEGA+; | `{` / `}` |
| MEGA+/ | `\|` |
| MEGA+← | `~` |
| SHIFT+← | `` ` `` |

## Credits

Created by Justin Cameron. Apache License 2.0; see [LICENSE](LICENSE)
and [NOTICE](NOTICE).
