# coebot

Personal-account protocol client for Clash of Empire (SFS2X over raw TCP).

- `sfs.py` – SFSObject codec + packet framing (tested: `python -m pytest coebot/tests`)
- `client.py` – handshake → login → command → heartbeat
- `cnmm.py` – **open blocker**: pluggable provider for the 31-byte `cnmm` token.
  Reverse it from `libil2cpp.so` (xrefs to string literal 0x5F9B488 in Ghidra) or
  by Frida-hooking the live app, then implement `__call__(command, params)`.

Never commit `config.json`, captures, or hashes (`pw`, `scode`, `deviceId`).
