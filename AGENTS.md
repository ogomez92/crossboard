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
