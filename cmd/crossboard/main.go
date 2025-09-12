package main

import (
    "bufio"
    "context"
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "crypto/sha256"
    "encoding/binary"
    "errors"
    "flag"
    "fmt"
    "io"
    "log"
    "net"
    "os"
    "os/exec"
    "os/signal"
    "path/filepath"
    "runtime"
    "strings"
    "sync"
    "syscall"
    "time"

    "github.com/atotto/clipboard"
    "golang.org/x/crypto/scrypt"
)

const (
    defaultPort       = 9876
    defaultListenAddr = ":9876"
)

// secureKeyFromPass derives a 32-byte key from a passphrase using scrypt.
func secureKeyFromPass(pass string) ([]byte, error) {
    if pass == "" {
        return nil, errors.New("empty key is not allowed; provide -k")
    }
    // Fixed salt provides defense against rainbow tables while keeping CLI simple.
    // Peers must use the same key; salt is static and embedded in code.
    salt := []byte("crossboard-v1-fixed-salt")
    key, err := scrypt.Key([]byte(pass), salt, 1<<15, 8, 1, 32) // N=32768, r=8, p=1
    if err != nil {
        return nil, err
    }
    return key, nil
}

// encrypt returns nonce||ciphertext for plaintext using AES-256-GCM.
func encrypt(aead cipher.AEAD, plaintext []byte) ([]byte, error) {
    nonce := make([]byte, aead.NonceSize())
    if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
        return nil, err
    }
    sealed := aead.Seal(nil, nonce, plaintext, nil)
    out := make([]byte, len(nonce)+len(sealed))
    copy(out, nonce)
    copy(out[len(nonce):], sealed)
    return out, nil
}

// decrypt expects input as nonce||ciphertext
func decrypt(aead cipher.AEAD, in []byte) ([]byte, error) {
    ns := aead.NonceSize()
    if len(in) < ns {
        return nil, errors.New("ciphertext too short")
    }
    nonce := in[:ns]
    ct := in[ns:]
    pt, err := aead.Open(nil, nonce, ct, nil)
    if err != nil {
        return nil, err
    }
    return pt, nil
}

// frame write: [uint32 big endian length][payload]
func writeFrame(w io.Writer, payload []byte) error {
    var lenbuf [4]byte
    binary.BigEndian.PutUint32(lenbuf[:], uint32(len(payload)))
    if _, err := w.Write(lenbuf[:]); err != nil {
        return err
    }
    _, err := w.Write(payload)
    return err
}

func readFrame(r *bufio.Reader, max int) ([]byte, error) {
    var lenbuf [4]byte
    if _, err := io.ReadFull(r, lenbuf[:]); err != nil {
        return nil, err
    }
    n := int(binary.BigEndian.Uint32(lenbuf[:]))
    if n < 0 || n > max {
        return nil, fmt.Errorf("frame size %d exceeds limit %d", n, max)
    }
    buf := make([]byte, n)
    if _, err := io.ReadFull(r, buf); err != nil {
        return nil, err
    }
    return buf, nil
}

// playWAV plays a WAV file using platform tools.
// macOS: afplay, Linux: paplay/aplay, Windows: PowerShell SoundPlayer.
func playWAV(wavPath string) error {
    if wavPath == "" {
        return nil
    }
    if _, err := os.Stat(wavPath); err != nil {
        return err
    }
    switch runtime.GOOS {
    case "darwin":
        cmd := exec.Command("afplay", wavPath)
        return cmd.Run()
    case "linux":
        // Try paplay first (PulseAudio), then aplay (ALSA)
        if _, err := exec.LookPath("paplay"); err == nil {
            return exec.Command("paplay", wavPath).Run()
        }
        if _, err := exec.LookPath("aplay"); err == nil {
            return exec.Command("aplay", wavPath).Run()
        }
        return fmt.Errorf("no audio player found (install paplay or aplay)")
    case "windows":
        // Use PowerShell to play synchronously
        ps := `Add-Type -AssemblyName System.Media; $p = New-Object System.Media.SoundPlayer '` + wavPath + `'; $p.PlaySync()`
        cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", ps)
        return cmd.Run()
    default:
        return fmt.Errorf("unsupported OS for sound: %s", runtime.GOOS)
    }
}

// clipboard helpers
func setClipboard(text string) error {
    return clipboard.WriteAll(text)
}

func getClipboard() (string, error) {
    return clipboard.ReadAll()
}

// suppressSet tracks content set by us to avoid echoing back
type suppressSet struct {
    mu    sync.Mutex
    items map[[32]byte]time.Time
}

func newSuppressSet() *suppressSet {
    return &suppressSet{items: make(map[[32]byte]time.Time)}
}

func (s *suppressSet) add(text string) {
    var h [32]byte
    h = sha256.Sum256([]byte(text))
    s.mu.Lock()
    s.items[h] = time.Now()
    s.mu.Unlock()
}

func (s *suppressSet) contains(text string) bool {
    var h [32]byte
    h = sha256.Sum256([]byte(text))
    s.mu.Lock()
    defer s.mu.Unlock()
    ts, ok := s.items[h]
    if !ok {
        return false
    }
    if time.Since(ts) > 10*time.Second {
        delete(s.items, h)
        return false
    }
    return true
}

// server: listen and handle connections
// Now uses a peerHub to support full duplex over any connection (incoming or outgoing).
func runServer(ctx context.Context, addr string, aead cipher.AEAD, soundPath string, hub *peerHub, suppress *suppressSet) error {
    ln, err := net.Listen("tcp", addr)
    if err != nil {
        return err
    }
    defer ln.Close()
    log.Printf("listening on %s", addr)

    var wg sync.WaitGroup
    go func() {
        <-ctx.Done()
        ln.Close()
    }()

    for {
        conn, err := ln.Accept()
        if err != nil {
            select {
            case <-ctx.Done():
                wg.Wait()
                return nil
            default:
            }
            if ne, ok := err.(net.Error); ok && ne.Temporary() {
                log.Printf("accept error: %v", err)
                continue
            }
            return err
        }
        pc := hub.add(conn)
        wg.Add(1)
        go func(pc *peerConn) {
            defer wg.Done()
            hub.readLoop(ctx, pc, aead, soundPath, suppress)
        }(pc)
    }
}

// peerConn wraps a net.Conn with a write mutex to serialize writes per connection.
type peerConn struct {
    c   net.Conn
    wmu sync.Mutex
}

// peerHub tracks all active connections (incoming and outgoing)
type peerHub struct {
    mu    sync.Mutex
    conns map[*peerConn]struct{}
}

func newPeerHub() *peerHub { return &peerHub{conns: make(map[*peerConn]struct{})} }

func (h *peerHub) add(c net.Conn) *peerConn {
    pc := &peerConn{c: c}
    h.mu.Lock()
    h.conns[pc] = struct{}{}
    h.mu.Unlock()
    log.Printf("peer connected: %s", c.RemoteAddr())
    return pc
}

func (h *peerHub) remove(pc *peerConn) {
    h.mu.Lock()
    if _, ok := h.conns[pc]; ok {
        delete(h.conns, pc)
    }
    h.mu.Unlock()
    _ = pc.c.Close()
    log.Printf("peer disconnected: %s", pc.c.RemoteAddr())
}

func (h *peerHub) hasPeers() bool {
    h.mu.Lock()
    n := len(h.conns)
    h.mu.Unlock()
    return n > 0
}

// broadcast sends plaintext text to all peers (encrypting independently).
func (h *peerHub) broadcast(aead cipher.AEAD, text string) {
    if text == "" {
        return
    }
    h.mu.Lock()
    conns := make([]*peerConn, 0, len(h.conns))
    for pc := range h.conns {
        conns = append(conns, pc)
    }
    h.mu.Unlock()
    for _, pc := range conns {
        ct, err := encrypt(aead, []byte(text))
        if err != nil {
            log.Printf("encrypt error: %v", err)
            continue
        }
        pc.wmu.Lock()
        err = writeFrame(pc.c, ct)
        pc.wmu.Unlock()
        if err != nil {
            log.Printf("send error to %s: %v", pc.c.RemoteAddr(), err)
            h.remove(pc)
        } else {
            log.Printf("sent %d bytes to %s", len(text), pc.c.RemoteAddr())
        }
    }
}

// readLoop handles inbound messages for a connection until it closes.
func (h *peerHub) readLoop(ctx context.Context, pc *peerConn, aead cipher.AEAD, soundPath string, suppress *suppressSet) {
    defer h.remove(pc)
    r := bufio.NewReader(pc.c)
    for {
        select {
        case <-ctx.Done():
            return
        default:
        }
        frame, err := readFrame(r, 100*1024*1024)
        if err != nil {
            if errors.Is(err, io.EOF) {
                return
            }
            log.Printf("read error from %s: %v", pc.c.RemoteAddr(), err)
            return
        }
        pt, err := decrypt(aead, frame)
        if err != nil {
            log.Printf("decrypt failed from %s: %v", pc.c.RemoteAddr(), err)
            return
        }
        msg := string(pt)
        if err := setClipboard(msg); err != nil {
            log.Printf("clipboard set error: %v", err)
        } else {
            suppress.add(msg)
            log.Printf("copied %d bytes to clipboard (from %s)", len(msg), pc.c.RemoteAddr())
            if soundPath != "" {
                if _, err := os.Stat(soundPath); err == nil {
                    go func() {
                        if err := playWAV(soundPath); err != nil {
                            log.Printf("sound error: %v", err)
                        }
                    }()
                }
            }
        }
    }
}

// connector dials addr and, on success, adds the connection to the hub and serves a read loop.
func connector(ctx context.Context, addr string, aead cipher.AEAD, hub *peerHub, soundPath string, suppress *suppressSet) {
    backoff := time.Second
    const maxBackoff = 10 * time.Second
    for {
        select {
        case <-ctx.Done():
            return
        default:
        }
        conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
        if err != nil {
            log.Printf("connect %s failed: %v", addr, err)
            time.Sleep(backoff)
            if backoff < maxBackoff {
                backoff *= 2
            }
            continue
        }
        backoff = time.Second
        pc := hub.add(conn)
        hub.readLoop(ctx, pc, aead, soundPath, suppress)
        // when readLoop returns, the connection is closed/removed; retry
        time.Sleep(backoff)
        if backoff < maxBackoff {
            backoff *= 2
        }
    }
}

// clipboardWatcher polls clipboard and broadcasts changes to all peers.
func clipboardWatcher(ctx context.Context, aead cipher.AEAD, hub *peerHub, suppress *suppressSet) {
    lastSentHash := [32]byte{}
    // initial send if content exists (optional)
    if txt, err := getClipboard(); err == nil {
        if txt != "" && !suppress.contains(txt) {
            lastSentHash = sha256.Sum256([]byte(txt))
            hub.broadcast(aead, txt)
        }
    }
    ticker := time.NewTicker(300 * time.Millisecond)
    defer ticker.Stop()
    for {
        select {
        case <-ctx.Done():
            return
        case <-ticker.C:
            txt, err := getClipboard()
            if err != nil {
                continue
            }
            if txt == "" || suppress.contains(txt) {
                continue
            }
            h := sha256.Sum256([]byte(txt))
            if h == lastSentHash {
                continue
            }
            lastSentHash = h
            hub.broadcast(aead, txt)
        }
    }
}

func ensurePort(hostport string) string {
    if strings.Contains(hostport, ":") {
        return hostport
    }
    return net.JoinHostPort(hostport, fmt.Sprintf("%d", defaultPort))
}

func main() {
    log.SetFlags(log.LstdFlags | log.Lmsgprefix)
    log.SetPrefix("crossboard: ")

    var (
        monitorHost string
        keyString   string
        listenAddr  string
        soundPath   string
    )

    flag.StringVar(&monitorHost, "m", "", "monitor clipboard and send to host (hostname or host:port)")
    flag.StringVar(&keyString, "k", "", "shared encryption key (required)")
    flag.StringVar(&listenAddr, "addr", defaultListenAddr, "listen address for incoming connections")
    flag.StringVar(&soundPath, "sound", "copy.wav", "path to WAV sound file to play on copy")
    flag.Parse()
    args := flag.Args()

    if keyString == "" {
        fmt.Fprintln(os.Stderr, "error: -k key is required")
        os.Exit(2)
    }

    key, err := secureKeyFromPass(keyString)
    if err != nil {
        fmt.Fprintln(os.Stderr, "key derivation error:", err)
        os.Exit(1)
    }
    block, err := aes.NewCipher(key)
    if err != nil {
        fmt.Fprintln(os.Stderr, "cipher error:", err)
        os.Exit(1)
    }
    aead, err := cipher.NewGCM(block)
    if err != nil {
        fmt.Fprintln(os.Stderr, "gcm error:", err)
        os.Exit(1)
    }

    // One-shot mode: if no -m and stdin is piped with a destination arg, send and exit.
    if monitorHost == "" {
        if info, err := os.Stdin.Stat(); err == nil && (info.Mode()&os.ModeCharDevice) == 0 {
            if len(args) == 0 {
                fmt.Fprintln(os.Stderr, "error: destination host[:port] required when piping without -m")
                os.Exit(2)
            }
            dest := ensurePort(args[0])
            data, err := io.ReadAll(os.Stdin)
            if err != nil {
                fmt.Fprintln(os.Stderr, "stdin read error:", err)
                os.Exit(1)
            }
            if len(data) == 0 {
                fmt.Fprintln(os.Stderr, "error: empty input on stdin")
                os.Exit(2)
            }
            done := make(chan struct{})
            ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
            defer cancel()
            go func() {
                sendBytesWithReconnect(ctx, dest, aead, data)
                close(done)
            }()
            select {
            case <-done:
                os.Exit(0)
            case <-ctx.Done():
                fmt.Fprintln(os.Stderr, "send timed out")
                os.Exit(1)
            }
        }
    }

    // Prepare audio context if sound file exists; if not present, we'll skip playing.
    // No audio context needed; playback uses platform tools.

    ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
    defer cancel()

    suppress := newSuppressSet()
    hub := newPeerHub()

    // Always run server to accept peers
    srvErrCh := make(chan error, 1)
    go func() {
        srvErrCh <- runServer(ctx, listenAddr, aead, soundPath, hub, suppress)
    }()

    // Run a connector only if -m is provided (optional)
    if monitorHost != "" {
        dest := ensurePort(monitorHost)
        go connector(ctx, dest, aead, hub, soundPath, suppress)
    }

    // Start clipboard watcher to broadcast local changes to all peers
    go clipboardWatcher(ctx, aead, hub, suppress)

    // Also allow typing or piping text to send directly to connected peers.
    go sendFromStdinToPeers(ctx, aead, hub)

    // Ensure sound path is absolute in logs for clarity
    if soundPath != "" {
        if p, err := filepath.Abs(soundPath); err == nil {
            log.Printf("sound file: %s", p)
        }
    }

    select {
    case <-ctx.Done():
        log.Println("shutdown")
    case err := <-srvErrCh:
        if err != nil {
            log.Fatalf("server error: %v", err)
        }
    }
}

// sendFromStdinToPeers reads stdin and broadcasts bytes to all connected peers.
func sendFromStdinToPeers(ctx context.Context, aead cipher.AEAD, hub *peerHub) {
    info, _ := os.Stdin.Stat()
    // Only act if input is not a TTY or user is interacting.
    if (info.Mode() & os.ModeCharDevice) == 0 {
        // Piped input: read all and send once
        data, err := io.ReadAll(os.Stdin)
        if err != nil {
            log.Printf("stdin read error: %v", err)
            return
        }
        if len(data) == 0 {
            return
        }
        // Broadcast; if no peers yet, this will be a no-op.
        hub.broadcast(aead, string(data))
        return
    }
    // Interactive terminal: send each line including newline
    r := bufio.NewReader(os.Stdin)
    for {
        select {
        case <-ctx.Done():
            return
        default:
        }
        line, err := r.ReadString('\n')
        if err != nil {
            if errors.Is(err, io.EOF) {
                return
            }
            log.Printf("stdin read error: %v", err)
            return
        }
        if len(line) == 0 {
            continue
        }
        hub.broadcast(aead, line)
    }
}

func sendBytesWithReconnect(ctx context.Context, addr string, aead cipher.AEAD, data []byte) {
    var backoff = time.Second
    const maxBackoff = 10 * time.Second
    for {
        select {
        case <-ctx.Done():
            return
        default:
        }
        conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
        if err != nil {
            log.Printf("connect %s failed: %v", addr, err)
            time.Sleep(backoff)
            if backoff < maxBackoff {
                backoff *= 2
            }
            continue
        }
        ct, err := encrypt(aead, data)
        if err != nil {
            log.Printf("encrypt error: %v", err)
            conn.Close()
            return
        }
        err = writeFrame(conn, ct)
        conn.Close()
        if err != nil {
            log.Printf("send error: %v", err)
            time.Sleep(backoff)
            if backoff < maxBackoff {
                backoff *= 2
            }
            continue
        }
        log.Printf("sent %d bytes from stdin", len(data))
        return
    }
}
