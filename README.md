# Crossboard

Crossboard is a tiny, secure, cross‑platform clipboard sharer. It always runs a small TCP server (default `:9876`) to accept encrypted clipboard updates and copy them to your system clipboard, playing a sound each time it copies. Optionally, it can also monitor your clipboard and connect to a peer to sync two‑ways — using a single TCP connection.

## Quick Start

Two‑way sync between two machines (A and B) — only one side needs to specify the other side’s address:

```
# On A (dial B and sync both directions)
./crossboard -k "shared-secret" -m machineB.local

# On B (just listen)
./crossboard -k "shared-secret"
```

Send text from stdin to a peer (one‑shot, exits after send):

```
echo "Hello from A" | ./crossboard -k "shared-secret" machineB.local
```

## Features

- Encrypted peer‑to‑peer clipboard sharing (AES‑256‑GCM with scrypt key derivation)
- Cross‑platform: macOS, Windows, Linux
- Plays `copy.wav` on every successful copy
- Always-on server and optional connector in a single binary
- Clipboard monitoring mode (`-m`) for automatic syncing (initiates outbound connection)
- Optional file transfer in monitor mode with `-f`: when you copy a file path as text (e.g., Copy as Path/Pathname) the sender detects path-like text and streams the referenced files/folders to the peer. Supports POSIX paths and `file://` URIs.

## Install

Requires Go 1.21+.

```
git clone <this-repo>
cd crossboard
go build -o crossboard ./cmd/crossboard
```

Place a `copy.wav` sound file next to the binary (or pass `-sound` with a path).

## Autostart

### macOS (LaunchAgent)

1. Copy the provided plist:
   - `cp packaging/launchd/com.crossboard.agent.plist ~/Library/LaunchAgents/`
2. Edit the file to set your args:
   - In the `EnvironmentVariables` section, set `CROSSBOARD_ARGS` (for example: `-k "secret" -m peer.host`).
3. Load and start:
   - `launchctl load ~/Library/LaunchAgents/com.crossboard.agent.plist`
   - `launchctl start com.crossboard.agent`

Logs: `~/Library/Logs/crossboard.out.log` and `~/Library/Logs/crossboard.err.log`.

### Linux (systemd user service)

1. Copy the unit file:
   - `mkdir -p ~/.config/systemd/user`
   - `cp packaging/systemd/crossboard.service ~/.config/systemd/user/`
2. Create env file with your args:
   - `mkdir -p ~/.config`
   - `cp packaging/crossboard.env.example ~/.config/crossboard.env`
   - Edit `~/.config/crossboard.env` and set your key/peer.
3. Reload and enable:
   - `systemctl --user daemon-reload`
   - `systemctl --user enable --now crossboard.service`

Logs: `journalctl --user -u crossboard -f`.

## Usage

Crossboard runs a server by default and has two usage patterns:

- Monitor/connect mode (`-m host[:port]`): watches your clipboard and connects to the peer; both sides can send/receive over the single TCP connection. The listener side does not need `-m`.
- One‑shot mode (no `-m` + piped stdin): send once to a destination host and exit. The server is still started in normal usage, but one‑shot exits after send.

### Monitor mode: sync to a peer (two‑way)

With the same `-k` on both computers, only one side needs to dial the other with `-m`:

```
# On Machine A (connects to B)
./crossboard -k "shared-secret" -m machineB.local

# On Machine B (listens only)
./crossboard -k "shared-secret"
```

Notes:
- `-m` accepts `host` or `host:port`. If the port is omitted, `9876` is used.
- Both sides run a server so either can accept connections. If both also specify `-m` to each other, two connections will work fine; it’s just not required.
- Each side monitors its own system clipboard and sends text changes to connected peers.
- If you type or pipe into stdin while it’s running, Crossboard also forwards that input to the peer.
- Received text is placed on the receiver’s clipboard; a sound is played.
- Loop protection prevents immediately re‑sending text that was just received and set locally.

### One‑shot mode: send from stdin

Without `-m`, you must pipe text and provide the destination host as a positional argument. Crossboard sends it and exits. If stdin is not provided or empty, it errors out. Only plain text is supported.

```
echo "hello" | ./crossboard -k "shared-secret" peer.host
```

With `-m`, stdin lines also send, but the app continues running for two‑way sync:

```
./crossboard -k "shared-secret" -m peer.host
```

If you pipe without `-m` and omit the destination, or if stdin is a TTY (not piped), the command fails with an error.

### Flags

- `-k string`: Required. Shared encryption key (passphrase). Must match on both peers.
- `-m host[:port]`: Monitor clipboard and send text changes to the given peer (initiates outbound connection; server always runs).
- `-addr host:port`: Listen address for incoming connections in monitor mode (default `:9876`).
- `-sound path`: Path to a WAV file to play on copy (default `copy.wav`).
- `-f`: Enable file transfers (in `-m` monitor mode). When enabled and the clipboard text looks like absolute file paths (Windows “Copy as path”, macOS Finder “Copy … as Pathname”, Linux file manager address bar or “Copy Location”), Crossboard tars those paths and streams them to the peer. `file://` URIs are also recognized.

Notes:
- Text is always treated as text unless it looks like absolute paths and `-f` is enabled.
- The receiver extracts into an `inbox` folder next to the app binary, under a timestamped subfolder (e.g., `inbox/20250101-123456-abcd1234`). It auto-opens that folder in Finder/Explorer and plays the copy sound. The system clipboard is not modified.
- This approach avoids platform-specific file clipboard APIs and avoids ping‑pong.

## Security

- Symmetric encryption: AES‑256‑GCM.
- Key derivation: scrypt (N=32768, r=8, p=1) over the provided passphrase with a fixed, built‑in salt.
- Per‑message random nonce with authenticated encryption; wrong keys cause decryption failures, logged and the connection is closed.

For the strongest security, choose a long, random passphrase and keep it private. Both peers must use the exact same passphrase.

## Clipboard Monitoring

There is no portable clipboard event API across OSes, so Crossboard polls the clipboard ~3×/second. It sends only when text changes. Text received from the peer is suppressed from being re‑sent for a short window to avoid loops.

## Sound Playback

- Provide a `copy.wav` file in the working directory or pass `-sound /path/to/copy.wav`.
- Playback uses OS tools for reliability:
  - macOS: `afplay`
  - Linux: `paplay` (PulseAudio) or `aplay` (ALSA)
  - Windows: PowerShell `System.Media.SoundPlayer`

## Platform Notes

- macOS: Works out of the box.
- Windows: Works out of the box.
- Linux: Clipboard requires an X11 environment. For `github.com/atotto/clipboard`, you may need `xclip` or `xsel` installed for some setups.

## Examples

One‑way sharing from A to B:

```
# On B (receiver)
./crossboard -k "shared-secret"

# On A (sender)
./crossboard -k "shared-secret" -m b.local
```

Two‑way sharing (both directions):

```
# On A (connects to B)
./crossboard -k "shared-secret" -m b.local

# On B (listens only)
./crossboard -k "shared-secret"
```

## Error Handling

- Invalid key or mismatched keys: Decryption fails; the connection is closed and an error is logged.
- Network interruptions: Client reconnects with exponential backoff.
- Oversized frames: Rejected with a clear error to avoid memory abuse.
- Audio issues: Non‑fatal; logs the error and keeps running.

## Development

Dependencies:

- `github.com/atotto/clipboard` for cross‑platform clipboard
- `golang.org/x/crypto/scrypt` for key derivation
  - Audio playback uses OS commands (no third‑party Go audio libs).

Build:

```
go build -o crossboard ./cmd/crossboard
```

Run with verbose logging by default; use your system tools to supervise as needed.

## Contributing

- Fork and create a feature branch.
- Build and test locally:
  - `go build ./cmd/crossboard`
  - Optional: `go vet ./...`
- Cross‑compile examples:
  - macOS (arm64): `GOOS=darwin GOARCH=arm64 go build -o crossboard-darwin ./cmd/crossboard`
  - Windows: `GOOS=windows GOARCH=amd64 go build -o crossboard.exe ./cmd/crossboard`
  - Linux: `GOOS=linux GOARCH=amd64 go build -o crossboard-linux ./cmd/crossboard`
- Keep changes minimal and focused; include rationale in PR description.
- For features affecting behavior or flags, update README and packaging files.

## License

MIT (or your preferred license).
