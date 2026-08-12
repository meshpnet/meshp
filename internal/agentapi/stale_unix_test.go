//go:build unix

package agentapi

import (
	"os"
	"syscall"
	"testing"
)

// A socket left behind by a process that died must not stop the daemon starting: that
// is the "won't come back after a crash" failure this code exists to prevent.
//
// Go's net package unlinks a unix socket when the listener is closed, so a listener
// cannot produce the state being tested. Binding through the syscall directly and
// closing the descriptor leaves the file exactly as a killed process would.
func TestListenClearsAStaleSocket(t *testing.T) {
	path := socketPath(t)

	fd, err := syscall.Socket(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatalf("socket: %v", err)
	}
	if err := syscall.Bind(fd, &syscall.SockaddrUnix{Name: path}); err != nil {
		_ = syscall.Close(fd)
		t.Fatalf("bind: %v", err)
	}
	// Closing the descriptor without unlinking is what a killed process leaves behind.
	if err := syscall.Close(fd); err != nil {
		t.Fatalf("close: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("the socket file did not survive: %v", err)
	}
	if info.Mode()&os.ModeSocket == 0 {
		t.Fatal("the leftover file is not a socket")
	}

	srv := NewServer(&fakeHandler{}, ServerConfig{SocketPath: path})
	if err := srv.Listen(); err != nil {
		t.Fatalf("Listen over a stale socket: %v", err)
	}
	t.Cleanup(func() { _ = os.Remove(path) })

	// And it is usable, not merely bound.
	if info, err := os.Stat(path); err != nil {
		t.Errorf("no socket after Listen: %v", err)
	} else if info.Mode().Perm() != 0o600 {
		t.Errorf("the replacement socket is %04o, want 0600", info.Mode().Perm())
	}
}
