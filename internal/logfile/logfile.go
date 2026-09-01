// Package logfile is a log file that does not grow forever.
//
// It exists because the agent's log is the only account of what a device did, and on two of
// the three platforms that can supervise it the daemon has to keep that account itself.
// systemd hands stderr to the journal, which rotates it. launchd and the Windows service
// control manager do not: launchd writes to a path and stops there, and a service has no
// console at all.
//
// Rotation is done here rather than by the system's log rotator, and that is not a
// preference. newsyslog(8) rotates by renaming, and a rename does not move an open file
// descriptor — so a file launchd is holding goes on receiving the daemon's output under its
// new name while the path everybody reads stays empty. Measured on macOS 26 rather than
// assumed: after renaming the file, the running job's next lines were in the renamed one and
// the original was never recreated. Whoever owns the descriptor has to be the one to rotate
// it, and that is this process.
package logfile

import (
	"fmt"
	"os"
	"sync"
)

// File is an io.WriteCloser that starts a new file once the current one is large enough.
type File struct {
	path string
	max  int64
	keep int

	mu   sync.Mutex
	f    *os.File
	size int64
}

// Open opens path for appending, rotating it when it passes max bytes and keeping that many
// previous files beside it.
//
// The current size is read from the file rather than counted from zero, so a daemon that
// restarts every few minutes cannot append forever without ever reaching the threshold.
func Open(path string, max int64, keep int) (*File, error) {
	if max <= 0 {
		return nil, fmt.Errorf("logfile: a maximum size of %d would rotate on every write", max)
	}
	if keep < 0 {
		return nil, fmt.Errorf("logfile: cannot keep %d previous files", keep)
	}
	l := &File{path: path, max: max, keep: keep}
	if err := l.open(); err != nil {
		return nil, err
	}
	return l, nil
}

func (l *File) open() error {
	f, err := os.OpenFile(l.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return fmt.Errorf("logfile: opening %s: %w", l.path, err)
	}
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return fmt.Errorf("logfile: measuring %s: %w", l.path, err)
	}
	l.f, l.size = f, info.Size()
	return nil
}

// Write appends, rotating first if this record would take the file past its limit.
//
// Rotation is before the write and not after, so the limit is one a reader can rely on: a
// file is never larger than max plus the record that filled it, rather than max plus however
// much arrived before anybody looked.
func (l *File) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.size > 0 && l.size+int64(len(p)) > l.max {
		if err := l.rotate(); err != nil {
			// Reported, but the write still happens. A device whose log cannot be rotated
			// should keep telling somebody what it is doing; losing the account of an
			// outage to a full disk is worse than a file that is too big.
			fmt.Fprintf(os.Stderr, "logfile: %v\n", err)
		}
	}

	n, err := l.f.Write(p)
	l.size += int64(n)
	return n, err
}

// rotate closes the current file, shifts the previous ones along, and opens a new one.
//
// Oldest first, so nothing is overwritten before it has been moved: shifting .1 to .2 before
// .2 has become .3 would throw away a file this was asked to keep.
func (l *File) rotate() error {
	if err := l.f.Close(); err != nil {
		return fmt.Errorf("logfile: closing %s: %w", l.path, err)
	}
	if l.keep == 0 {
		// Nothing to keep: the file is emptied rather than moved aside. Truncating an
		// unlinked file would leave the daemon writing to something with no name.
		if err := os.Remove(l.path); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("logfile: removing %s: %w", l.path, err)
		}
		return l.open()
	}
	for i := l.keep; i > 1; i-- {
		older := fmt.Sprintf("%s.%d", l.path, i)
		newer := fmt.Sprintf("%s.%d", l.path, i-1)
		if err := os.Rename(newer, older); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("logfile: rotating %s: %w", newer, err)
		}
	}
	if err := os.Rename(l.path, l.path+".1"); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("logfile: rotating %s: %w", l.path, err)
	}
	return l.open()
}

// Close closes the current file. Rotation state is on disk, so a later Open resumes it.
func (l *File) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.f.Close()
}
