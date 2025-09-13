package main

import (
	"archive/tar"
	"bufio"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
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

// message encoding with IDs (versioned textual header inside the AEAD plaintext)
// Format:
//   CB1\n
//   <32-hex-id>\n
//   <raw text bytes...>

type msgID [16]byte

func encodeMessage(text string) (msgID, []byte, error) {
	var id msgID
	if _, err := rand.Read(id[:]); err != nil {
		return msgID{}, nil, err
	}
	hexID := make([]byte, 32)
	hex.Encode(hexID, id[:])
	// Build: CB1\n<hex>\n<text>
	payload := make([]byte, 0, 4+32+1+len(text))
	payload = append(payload, 'C', 'B', '1', '\n')
	payload = append(payload, hexID...)
	payload = append(payload, '\n')
	payload = append(payload, []byte(text)...)
	return id, payload, nil
}

func decodeMessage(pt []byte) (msgID, string, error) {
	// Expect header "CB1\n"
	if !(len(pt) >= 4 && pt[0] == 'C' && pt[1] == 'B' && pt[2] == '1' && pt[3] == '\n') {
		return msgID{}, "", errors.New("missing CB1 header")
	}
	rest := pt[4:]
	// Next line is 32 hex chars then '\n'
	if !(len(rest) >= 33 && rest[32] == '\n') {
		return msgID{}, "", errors.New("malformed id line")
	}
	var id msgID
	if _, err := hex.Decode(id[:], rest[:32]); err != nil {
		return msgID{}, "", fmt.Errorf("invalid id hex: %w", err)
	}
	return id, string(rest[33:]), nil
}

// idCache tracks seen message IDs to avoid re-applying duplicates.
type idCache struct {
	mu    sync.Mutex
	items map[msgID]time.Time
}

func newIDCache() *idCache { return &idCache{items: make(map[msgID]time.Time)} }

func (c *idCache) add(id msgID) {
	c.mu.Lock()
	c.items[id] = time.Now()
	c.mu.Unlock()
}

func (c *idCache) contains(id msgID) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	ts, ok := c.items[id]
	if !ok {
		return false
	}
	if time.Since(ts) > 2*time.Minute {
		delete(c.items, id)
		return false
	}
	return true
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

// getClipboardFiles tries to read a list of file paths from the OS clipboard.
// Returns empty slice if clipboard does not contain files or not supported.
func getClipboardFiles() ([]string, error) {
	switch runtime.GOOS {
	case "darwin":
		// AppleScript: attempt to read clipboard as alias list (files)
		script := []string{
			"-e", "try",
			"-e", "set theFiles to the clipboard as alias list",
			"-e", "on error",
			"-e", "return \"\"",
			"-e", "end try",
			"-e", "set out to \"\"",
			"-e", "repeat with f in theFiles",
			"-e", "set out to out & POSIX path of f & \n",
			"-e", "end repeat",
			"-e", "out",
		}
		cmd := exec.Command("osascript", script...)
		out, err := cmd.Output()
		if err != nil {
			return nil, nil
		}
		s := strings.TrimSpace(string(out))
		if s == "" {
			return nil, nil
		}
		lines := strings.Split(s, "\n")
		var paths []string
		for _, p := range lines {
			p = strings.TrimSpace(p)
			if p == "" {
				continue
			}
			if _, err := os.Stat(p); err == nil {
				paths = append(paths, p)
			}
		}
		return paths, nil
	case "windows":
		// Prefer WinForms FileDropList for reliability
		ps := strings.Join([]string{
			"Add-Type -AssemblyName System.Windows.Forms",
			"$fl = [System.Windows.Forms.Clipboard]::GetFileDropList()",
			"if ($null -ne $fl) { $fl | ForEach-Object { $_ } }",
		}, "; ")
		cmd := exec.Command("powershell", "-STA", "-NoProfile", "-NonInteractive", "-Command", ps)
		out, err := cmd.Output()
		if err != nil {
			return nil, nil
		}
		s := strings.TrimSpace(string(out))
		if s == "" {
			return nil, nil
		}
		lines := strings.Split(s, "\n")
		var paths []string
		for _, p := range lines {
			p = strings.TrimSpace(p)
			if p == "" {
				continue
			}
			if _, err := os.Stat(p); err == nil {
				paths = append(paths, p)
			}
		}
		return paths, nil
	default:
		return nil, nil
	}
}

// setClipboardFiles sets the OS clipboard to a list of file paths (macOS/Windows).
func setClipboardFiles(paths []string) error {
	if len(paths) == 0 {
		return nil
	}
	switch runtime.GOOS {
	case "darwin":
		// Build AppleScript to set clipboard to a list of file aliases and also notify Finder.
		parts := make([]string, 0, len(paths))
		for _, p := range paths {
			ep := strings.ReplaceAll(p, "\"", "\\\"")
			parts = append(parts, `POSIX file "`+ep+`" as alias`)
		}
		obj := "{" + strings.Join(parts, ", ") + "}"
		script := []string{
			"-e", "set theFiles to " + obj,
			"-e", "set the clipboard to theFiles",
			"-e", "try",
			"-e", "tell application \"Finder\" to set the clipboard to theFiles",
			"-e", "end try",
		}
		cmd := exec.Command("osascript", script...)
		return cmd.Run()
	case "windows":
		// Use WinForms Clipboard FileDropList via STA PowerShell
		// This sets proper file references for Explorer paste.
		esc := func(s string) string {
			s = strings.ReplaceAll(s, "`", "``")
			s = strings.ReplaceAll(s, "\"", "`\"")
			return s
		}
		items := make([]string, 0, len(paths))
		for _, p := range paths {
			items = append(items, `"`+esc(p)+`"`)
		}
		ps := strings.Join([]string{
			"Add-Type -AssemblyName System.Windows.Forms",
			"$col = New-Object System.Collections.Specialized.StringCollection",
			"$col.AddRange(@(" + strings.Join(items, ",") + "))",
			"[System.Windows.Forms.Clipboard]::SetFileDropList($col)",
		}, "; ")
		cmd := exec.Command("powershell", "-STA", "-NoProfile", "-NonInteractive", "-Command", ps)
		return cmd.Run()
	default:
		return errors.New("file clipboard not supported on this OS")
	}
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
	mu        sync.Mutex
	conns     map[*peerConn]struct{}
	ids       *idCache
	fileIDs   *idCache
	fsessions map[msgID]*fileSession
}

func newPeerHub() *peerHub {
	return &peerHub{conns: make(map[*peerConn]struct{}), ids: newIDCache(), fileIDs: newIDCache(), fsessions: make(map[msgID]*fileSession)}
}

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
		_, payload, err := encodeMessage(text)
		if err != nil {
			log.Printf("encode error: %v", err)
			continue
		}
		ct, err := encrypt(aead, payload)
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

// broadcastPlain encrypts and sends the given plaintext payload to all peers.
func (h *peerHub) broadcastPlain(aead cipher.AEAD, payload []byte) {
	h.mu.Lock()
	conns := make([]*peerConn, 0, len(h.conns))
	for pc := range h.conns {
		conns = append(conns, pc)
	}
	h.mu.Unlock()
	for _, pc := range conns {
		ct, err := encrypt(aead, payload)
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
		// Dispatch on header: text or file payload
		if len(pt) >= 4 && pt[0] == 'C' && pt[1] == 'B' && pt[2] == '1' && pt[3] == '\n' {
			id, msg, derr := decodeMessage(pt)
			if derr != nil {
				log.Printf("invalid message from %s: %v", pc.c.RemoteAddr(), derr)
				continue
			}
			if h.ids.contains(id) {
				continue
			}
			h.ids.add(id)
			if cur, err := getClipboard(); err == nil && cur == msg {
				continue
			}
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
			continue
		}
		if len(pt) >= 5 && pt[0] == 'C' && pt[1] == 'B' && pt[2] == 'F' && pt[3] == '1' && pt[4] == '\n' {
			// File transfer frame
			if err := h.handleFileFrame(pt, soundPath, suppress); err != nil {
				log.Printf("file frame error from %s: %v", pc.c.RemoteAddr(), err)
			}
			continue
		}
		// Unknown payload; ignore
	}
}

// fileSession holds state for an in-progress tar extraction
type fileSession struct {
	wr   *io.PipeWriter
	done chan struct{}
	dir  string
}

func (h *peerHub) handleFileFrame(pt []byte, soundPath string, suppress *suppressSet) error {
	// Expect: CBF1\n<32hex>\nTYPE\n[bytes]
	rest := pt[5:]
	if !(len(rest) >= 33 && rest[32] == '\n') {
		return errors.New("malformed file id line")
	}
	var id msgID
	if _, err := hex.Decode(id[:], rest[:32]); err != nil {
		return fmt.Errorf("invalid file id hex: %w", err)
	}
	rest = rest[33:]
	// Read type line
	idx := bytesIndexByte(rest, '\n')
	if idx < 0 {
		return errors.New("missing type line")
	}
	typ := string(rest[:idx])
	payload := rest[idx+1:]

	switch typ {
	case "START":
		if h.fileIDs.contains(id) {
			// Already processed; ignore
			return nil
		}
		// Create session and start extractor
		dir, err := os.MkdirTemp("", "crossboard-*")
		if err != nil {
			return err
		}
		pr, pw := io.Pipe()
		done := make(chan struct{})
		sess := &fileSession{wr: pw, done: done, dir: dir}
		h.mu.Lock()
		h.fsessions[id] = sess
		h.mu.Unlock()
		go func() {
			defer close(done)
			err := untarToDir(pr, dir)
			if err != nil {
				log.Printf("untar error: %v", err)
			}
		}()
		return nil
	case "DATA":
		h.mu.Lock()
		sess := h.fsessions[id]
		h.mu.Unlock()
		if sess == nil {
			return errors.New("unknown file session")
		}
		// Write payload to pipe
		if len(payload) > 0 {
			if _, err := sess.wr.Write(payload); err != nil {
				return err
			}
		}
		return nil
	case "END":
		h.mu.Lock()
		sess := h.fsessions[id]
		delete(h.fsessions, id)
		h.mu.Unlock()
		if sess == nil {
			return errors.New("unknown file session end")
		}
		// Close writer to finish extraction
		_ = sess.wr.Close()
		<-sess.done
		h.fileIDs.add(id)
		// Collect top-level entries in dir to put on clipboard
		entries, _ := os.ReadDir(sess.dir)
		var paths []string
		for _, e := range entries {
			paths = append(paths, filepath.Join(sess.dir, e.Name()))
		}
		if len(paths) > 0 {
			// Set file clipboard; do NOT set text clipboard to avoid ping-pong
			if err := setClipboardFiles(paths); err != nil {
				log.Printf("set file clipboard failed: %v", err)
			} else if soundPath != "" {
				if _, err := os.Stat(soundPath); err == nil {
					go func() {
						if err := playWAV(soundPath); err != nil {
							log.Printf("sound error: %v", err)
						}
					}()
				}
			}
			// Suppress re-broadcast by marking this selection
			suppress.add(strings.Join(paths, "\n"))
		}
		return nil
	default:
		return fmt.Errorf("unknown file frame type: %s", typ)
	}
}

// bytesIndexByte is like bytes.IndexByte without importing bytes to avoid overhead
func bytesIndexByte(b []byte, c byte) int {
	for i, v := range b {
		if v == c {
			return i
		}
	}
	return -1
}

// untarToDir extracts a tar stream into target directory, preserving structure.
func untarToDir(r io.Reader, dir string) error {
	tr := tar.NewReader(r)
	for {
		hdr, err := tr.Next()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		name := filepath.Clean(hdr.Name)
		if strings.HasPrefix(name, "..") {
			continue // skip unsafe
		}
		target := filepath.Join(dir, name)
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
		case tar.TypeReg, tar.TypeRegA:
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			f, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, os.FileMode(hdr.Mode))
			if err != nil {
				return err
			}
			if _, err := io.Copy(f, tr); err != nil {
				f.Close()
				return err
			}
			f.Close()
		case tar.TypeSymlink:
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			// Best-effort create symlink
			_ = os.Symlink(hdr.Linkname, target)
		default:
			// ignore other types
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
func clipboardWatcher(ctx context.Context, aead cipher.AEAD, hub *peerHub, suppress *suppressSet, enableFiles bool) {
	lastSentHash := [32]byte{}
	var lastFilesSig [32]byte
	// Initialize baseline to current clipboard without sending on startup.
	if txt, err := getClipboard(); err == nil && txt != "" {
		lastSentHash = sha256.Sum256([]byte(txt))
	}
	if enableFiles {
		if paths, _ := getClipboardFiles(); len(paths) > 0 {
			sig := sha256.Sum256([]byte(strings.Join(paths, "\n")))
			lastFilesSig = sig
		}
	}
	ticker := time.NewTicker(300 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// If file mode enabled, prefer files when clipboard contains file list
            if enableFiles {
                if paths, _ := getClipboardFiles(); len(paths) > 0 {
                    joined := strings.Join(paths, "\n")
                    // If we set this selection locally, suppress rebroadcast
                    if suppress.contains(joined) {
                        lastFilesSig = sha256.Sum256([]byte(joined))
                        continue
                    }
                    sig := sha256.Sum256([]byte(joined))
                    if sig != lastFilesSig {
                        lastFilesSig = sig
                        go sendFilesAsStream(ctx, aead, hub, paths)
                    }
                    // When files detected, skip text processing this tick
                    continue
                }
            }
			// Fallback to text
			txt, err := getClipboard()
			if err != nil || txt == "" {
				continue
			}
			if suppress.contains(txt) {
				lastSentHash = sha256.Sum256([]byte(txt))
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
		fileMode    bool
	)

	flag.StringVar(&monitorHost, "m", "", "monitor clipboard and send to host (hostname or host:port)")
	flag.StringVar(&keyString, "k", "", "shared encryption key (required)")
	flag.StringVar(&listenAddr, "addr", defaultListenAddr, "listen address for incoming connections")
	flag.StringVar(&soundPath, "sound", "copy.wav", "path to WAV sound file to play on copy")
	flag.BoolVar(&fileMode, "f", false, "enable file transfer in monitor mode (-m)")
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
	go clipboardWatcher(ctx, aead, hub, suppress, fileMode)

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
		// Wrap data as a message with an ID for dedupe on receiver.
		_, payload, err := encodeMessage(string(data))
		if err != nil {
			log.Printf("encode error: %v", err)
			conn.Close()
			return
		}
		ct, err := encrypt(aead, payload)
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

// -------- File sending (client) --------

// encode file control frames
func encodeFileStart() (msgID, []byte, error) {
	var id msgID
	if _, err := rand.Read(id[:]); err != nil {
		return msgID{}, nil, err
	}
	hexID := make([]byte, 32)
	hex.Encode(hexID, id[:])
	payload := make([]byte, 0, 5+32+1+6)
	payload = append(payload, 'C', 'B', 'F', '1', '\n')
	payload = append(payload, hexID...)
	payload = append(payload, '\n')
	payload = append(payload, []byte("START\n")...)
	return id, payload, nil
}

func encodeFileData(id msgID, chunk []byte) []byte {
	hexID := make([]byte, 32)
	hex.Encode(hexID, id[:])
	payload := make([]byte, 0, 5+32+1+5+len(chunk))
	payload = append(payload, 'C', 'B', 'F', '1', '\n')
	payload = append(payload, hexID...)
	payload = append(payload, '\n')
	payload = append(payload, []byte("DATA\n")...)
	payload = append(payload, chunk...)
	return payload
}

func encodeFileEnd(id msgID) []byte {
	hexID := make([]byte, 32)
	hex.Encode(hexID, id[:])
	payload := make([]byte, 0, 5+32+1+4)
	payload = append(payload, 'C', 'B', 'F', '1', '\n')
	payload = append(payload, hexID...)
	payload = append(payload, '\n')
	payload = append(payload, []byte("END\n")...)
	return payload
}

// sendFilesAsStream tars the given paths and streams chunks to peers.
func sendFilesAsStream(ctx context.Context, aead cipher.AEAD, hub *peerHub, paths []string) {
	if len(paths) == 0 {
		return
	}
	// Prepare pipe: tar writer -> reader -> chunk sender
	pr, pw := io.Pipe()
	// Start tar writing in background
	go func() {
		err := writeTar(paths, pw)
		_ = pw.CloseWithError(err)
	}()
	// Announce start
	id, startPayload, err := encodeFileStart()
	if err != nil {
		log.Printf("file start encode error: %v", err)
		return
	}
	hub.broadcastPlain(aead, startPayload)
	// Stream chunks
	buf := make([]byte, 1<<20) // 1MB chunks
	for {
		n, err := pr.Read(buf)
		if n > 0 {
			payload := encodeFileData(id, buf[:n])
			hub.broadcastPlain(aead, payload)
		}
		if err != nil {
			if !errors.Is(err, io.EOF) {
				log.Printf("tar read error: %v", err)
			}
			break
		}
		select {
		case <-ctx.Done():
			return
		default:
		}
	}
	// Send end
	endPayload := encodeFileEnd(id)
	hub.broadcastPlain(aead, endPayload)
}

// writeTar writes the provided files/dirs into a tar stream.
func writeTar(paths []string, w io.Writer) error {
	tw := tar.NewWriter(w)
	defer tw.Close()
	for _, p := range paths {
		abs, err := filepath.Abs(p)
		if err != nil {
			abs = p
		}
		fi, err := os.Lstat(abs)
		if err != nil {
			return err
		}
		base := filepath.Base(abs)
		if fi.IsDir() {
			// Walk directory
			err = filepath.WalkDir(abs, func(path string, d os.DirEntry, err error) error {
				if err != nil {
					return err
				}
				rel, _ := filepath.Rel(abs, path)
				name := filepath.ToSlash(filepath.Join(base, rel))
				info, err := d.Info()
				if err != nil {
					return err
				}
				if d.IsDir() {
					hdr, err := tar.FileInfoHeader(info, "")
					if err != nil {
						return err
					}
					hdr.Name = name
					if err := tw.WriteHeader(hdr); err != nil {
						return err
					}
					return nil
				}
				if info.Mode()&os.ModeSymlink != 0 {
					link, err := os.Readlink(path)
					if err != nil {
						return err
					}
					hdr, err := tar.FileInfoHeader(info, link)
					if err != nil {
						return err
					}
					hdr.Name = name
					return tw.WriteHeader(hdr)
				}
				hdr, err := tar.FileInfoHeader(info, "")
				if err != nil {
					return err
				}
				hdr.Name = name
				if err := tw.WriteHeader(hdr); err != nil {
					return err
				}
				f, err := os.Open(path)
				if err != nil {
					return err
				}
				_, err = io.Copy(tw, f)
				f.Close()
				return err
			})
			if err != nil {
				return err
			}
		} else {
			// Single file or symlink
			if fi.Mode()&os.ModeSymlink != 0 {
				link, err := os.Readlink(abs)
				if err != nil {
					return err
				}
				hdr, err := tar.FileInfoHeader(fi, link)
				if err != nil {
					return err
				}
				hdr.Name = filepath.ToSlash(base)
				if err := tw.WriteHeader(hdr); err != nil {
					return err
				}
			} else {
				hdr, err := tar.FileInfoHeader(fi, "")
				if err != nil {
					return err
				}
				hdr.Name = filepath.ToSlash(base)
				if err := tw.WriteHeader(hdr); err != nil {
					return err
				}
				f, err := os.Open(abs)
				if err != nil {
					return err
				}
				_, err = io.Copy(tw, f)
				f.Close()
				if err != nil {
					return err
				}
			}
		}
	}
	return nil
}
