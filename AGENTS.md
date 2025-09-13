# Agents Guide

This repository contains a single Go module that builds a small CLI tool named `crossboard`.

## Structure

- `cmd/crossboard/main.go` — All program logic (CLI, networking, encryption, clipboard, audio).
- `README.md` — Usage and documentation.
- `go.mod` — Module and dependencies.

## Coding Conventions

- Keep the code simple, readable, and minimal.
- Favor standard library packages; use small, focused third‑party libs only when necessary.
- Handle errors explicitly; log failures but keep the service running when safe.
- Avoid global state unless necessary; prefer passing context and dependencies.

## Platform Compatibility

- Clipboard: `github.com/atotto/clipboard` (may require `xclip`/`xsel` on Linux).
- Audio: uses OS playback tools (afplay on macOS, paplay/aplay on Linux, PowerShell SoundPlayer on Windows).

## Security Notes

- Encryption: AES‑256‑GCM.
- Key derivation: scrypt with a fixed salt for simplicity; peers must share the same passphrase.
- Max frame size: 100MB to prevent unbounded allocations.

## Development Tips

- The binary always runs a server on `-addr` (default `:9876`).
- `-m host[:port]` enables client mode to send clipboard updates to the peer.
- Audio playback is optional; if `copy.wav` is missing or audio init fails, the app continues without sound.

### File Transfer Behavior (`-f`)

- Do not use native file clipboard APIs. File sharing is triggered by detecting path‑like text on the sender’s clipboard (Windows “Copy as path”, macOS Finder “Copy … as Pathname”, Linux POSIX paths or `file://` URIs).
- When `-f` is enabled and clipboard text parses into existing absolute paths, tar those paths and stream them in chunks over the existing encrypted framing.
- The receiver extracts into `<app_dir>/inbox/<timestamp>-<id>` (created if needed), opens that folder using the platform opener (Finder/Explorer/xdg-open), and plays the copy sound. Do not modify the receiver clipboard for files (prevents ping‑pong).
- Keep text behavior unchanged: text is still sent as text unless it matches path‑like input with `-f` enabled.
- Maintain loop suppression logic for text; file transfers should not be re‑broadcast.
