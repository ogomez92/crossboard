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
- The receiver extracts into `<app_dir>/inbox/<timestamp>-<shortid>` (created if needed), opens that folder using the platform opener (Finder/Explorer/xdg-open), and plays the copy sound. Optional `-x` lets users specify a custom opener (e.g. Total Commander, Explorer++). Do not modify the receiver clipboard for files (prevents ping‑pong).
- Keep text behavior unchanged: text is still sent as text unless it matches path‑like input with `-f` enabled.
- Maintain loop suppression logic for text; file transfers should not be re‑broadcast.

## Recent Changes and Implementation Notes

### New Flags

- `-f`: Enables file transfer by path‑text detection on the sender. Text that looks like absolute paths (or `file://` URIs) is sent as a streamed tar bundle instead of text.
- `-x <path>`: Custom file explorer to open the inbox folder on receive. On startup, if `-x` is set and the executable cannot be resolved (direct path or via `PATH`), the program exits with code 2. On success, the resolved absolute path is logged.

### File Transfer Protocol

- Frames are AES‑GCM encrypted like text frames, using the same outer frame format; a custom plaintext header identifies file traffic:
  - `CBF1\n<32-hex-id>\nSTART\n` — begin session
  - `CBF1\n<32-hex-id>\nDATA\n<bytes…>` — 1MB default chunks (respects 100MB max per frame)
  - `CBF1\n<32-hex-id>\nEND\n` — end session
- Receiver uses an `io.Pipe` + `archive/tar` reader to extract as data streams in; sessions de‑duped on START and tracked by `fileIDs` to avoid reprocessing.

### Inbox Handling

- Extracts to `<app_dir>/inbox/<timestamp>-<shortid>` (auto‑created). After successful receive:
  - Plays the copy sound (if configured)
  - Opens the inbox folder using:
    - Custom `-x` if provided (validated on startup)
    - Otherwise platform default (macOS `open`, Windows `explorer`, Linux `xdg-open` if available)
  - On Windows, opening attempts to focus the window via PowerShell + `WScript.Shell.AppActivate` (best effort; Windows may still block focus stealing).

### Path Parsing Logic

- Primary: Extract multiple quoted tokens '...'/"..." on a single line (macOS Finder multi‑select case).
- Fallback: Newline‑separated entries.
- Last resort: Whitespace‑separated tokens only if ALL tokens are valid absolute existing paths (prevents false positives).
- Supports:
  - POSIX absolute paths and `~/` expansion (non‑Windows)
  - `file://` URIs with path unescaping
  - Windows drive‑letter and UNC paths

### Loop Prevention

- Text: existing suppression via hash avoids immediate re‑echo.
- Files: receiver never writes to clipboard; sender suppresses repeated sends of the same canonical selection (absolute, cleaned, sorted) using a short‑term signature.

### Misc

- README was rewritten to reduce repetition and document the new behavior and flags.
- `makefile.bat` was replaced with a proper Windows batch that builds/cleans and supports cross OS/arch builds.
- Logging improvements:
  - Logs resolved sound file path
  - Logs resolved custom explorer (or exits if invalid)
  - Logs inbox destination and which explorer is used to open it
