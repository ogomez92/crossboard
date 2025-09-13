# Crossboard

Secure, minimal, cross‑platform clipboard sync over a single TCP connection. Text sync is the default; optional file transfer uses path‑text detection and streaming.

## Quick Start

- Two‑way text sync (A connects to B):
  - A: `./crossboard -k "secret" -m b.local`
  - B: `./crossboard -k "secret"`

- File transfer (path‑text detection, no clipboard tricks):
  - A: `./crossboard -k "secret" -m b.local -f`
  - B: `./crossboard -k "secret" -f`
  - On A, copy file paths as text (Windows: “Copy as path”, macOS Finder: “Copy … as Pathname”, Linux: absolute paths or `file://` URIs). A streams those files; B extracts them into `inbox/…` and opens the folder.

## Usage

- `-k string` (required): Shared passphrase for AES‑256‑GCM.
- `-m host[:port]`: Monitor clipboard and connect to peer; server always listens on `-addr`.
- `-addr host:port`: Listen address (default `:9876`).
- `-sound path`: WAV to play on copy (default `copy.wav`).
- `-f`: Enable file transfer. When the clipboard text looks like absolute paths (including `file://` URIs), Crossboard tars and streams those paths instead of sending the text.
- `-x path`: Custom file explorer command to open received inbox folders (e.g., `-x C:\\Tools\\Explorer++.exe` on Windows). If it fails, Crossboard falls back to the system default opener.

Behavior
- Text: On change, sends text; receiver writes to clipboard and plays sound.
- Files with `-f`: Sender detects path‑like text and streams referenced files; receiver extracts into `<app_dir>/inbox/<timestamp>-<id>`, opens that folder in Finder/Explorer (or `xdg-open`), and plays sound. The receiver clipboard is not modified to avoid loops.
  - Use `-x` to override the opener (helpful for Total Commander, Explorer++, etc.).

## Build

Requires Go 1.21+.

```
go build -o crossboard ./cmd/crossboard
```

Place `copy.wav` next to the binary or pass `-sound`.

## Security

- AES‑256‑GCM for transport encryption.
- scrypt key derivation (N=32768, r=8, p=1) from `-k` with a fixed salt shared by peers.
- Per‑message random nonce; decryption failures close the connection.

## Platform Notes

- macOS, Windows, Linux supported.
- File transfer uses path‑text only; no native file clipboard APIs are used.
- Linux clipboard for text may require `xclip`/`xsel` depending on environment.

## Autostart (optional)

See `packaging/` for launchd (macOS) and systemd (Linux) examples.

## Troubleshooting

- No sound: ensure `copy.wav` exists or pass `-sound`.
- File transfers not triggering: confirm the clipboard contains absolute paths or `file://` URIs and `-f` is enabled.
- Inbox location: `<app_dir>/inbox/<timestamp>-<id>` (auto‑opened on receive).
- Cross‑compile examples:
  - macOS (arm64): `GOOS=darwin GOARCH=arm64 go build -o crossboard-darwin ./cmd/crossboard`
  - Windows: `GOOS=windows GOARCH=amd64 go build -o crossboard.exe ./cmd/crossboard`
  - Linux: `GOOS=linux GOARCH=amd64 go build -o crossboard-linux ./cmd/crossboard`
- Keep changes minimal and focused; include rationale in PR description.
- For features affecting behavior or flags, update README and packaging files.

## License

MIT (or your preferred license).
