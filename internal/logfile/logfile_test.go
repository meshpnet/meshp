package logfile

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// The whole point: a log that is written to forever does not grow forever.
func TestTheFileStopsGrowing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "meshpd.log")
	l, err := Open(path, 100, 2)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })

	line := strings.Repeat("x", 40) + "\n"
	for i := 0; i < 50; i++ {
		if _, err := l.Write([]byte(line)); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}

	// 50 records of 41 bytes is a little over 2KB. With a 100-byte limit and two previous
	// files kept, what is on disk has to be bounded by roughly three times the limit —
	// not by how much was written.
	var total int64
	for _, name := range onDisk(t, path) {
		info, err := os.Stat(name)
		if err != nil {
			t.Fatal(err)
		}
		total += info.Size()
	}
	if total > 400 {
		t.Errorf("wrote ~2KB through a 100-byte file keeping 2, and %d bytes are on disk", total)
	}
}

// Rotation has to move the old file aside, not delete it. An agent's log is the only account
// of what a device did, and the interesting minute is usually the one before somebody looked.
func TestWhatWasWrittenBeforeRotationIsStillThere(t *testing.T) {
	path := filepath.Join(t.TempDir(), "meshpd.log")
	l, err := Open(path, 50, 2)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })

	if _, err := l.Write([]byte("the first thing that happened\n")); err != nil {
		t.Fatal(err)
	}
	if _, err := l.Write([]byte("the second thing that happened\n")); err != nil {
		t.Fatal(err)
	}

	previous, err := os.ReadFile(path + ".1")
	if err != nil {
		t.Fatalf("the previous file is not beside the current one: %v", err)
	}
	if !strings.Contains(string(previous), "the first thing") {
		t.Errorf("%s.1 does not hold what was written before the rotation: %q", path, previous)
	}
	current, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(current), "the second thing") {
		t.Errorf("the current file does not hold what was written after: %q", current)
	}
}

// Files shift oldest-first, so nothing is overwritten before it has been moved along.
//
// Run for more than one value of keep on purpose. At keep=2 there is a single rename and
// shifting the wrong way round is indistinguishable from shifting the right way — a mutation
// that reversed the loop passed every test here until this became a table.
func TestOlderFilesShiftAlongAndTheOldestGoes(t *testing.T) {
	for _, keep := range []int{2, 3, 4} {
		t.Run(fmt.Sprintf("keep=%d", keep), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "meshpd.log")
			l, err := Open(path, 30, keep)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = l.Close() })

			// Enough records to fill every slot and then some, so the oldest has to go.
			for i := 0; i < keep+4; i++ {
				if _, err := fmt.Fprintf(l, "record number %d padded out\n", i); err != nil {
					t.Fatal(err)
				}
			}

			for i := 1; i <= keep; i++ {
				if _, err := os.Stat(fmt.Sprintf("%s.%d", path, i)); err != nil {
					t.Errorf("expected %s.%d to exist: %v", path, i, err)
				}
			}
			if _, err := os.Stat(fmt.Sprintf("%s.%d", path, keep+1)); !os.IsNotExist(err) {
				t.Errorf("keeping %d files left a %dth: %v", keep, keep+1, err)
			}

			// The property somebody reading these back relies on: a higher suffix is older.
			// Asserted as an ordering rather than as particular records, because which
			// record lands where depends on how many rotations happened.
			previous := -1
			for i := keep; i >= 1; i-- {
				n := recordIn(t, fmt.Sprintf("%s.%d", path, i))
				if n <= previous {
					t.Errorf(".%d holds record %d, which is not newer than the %d before it",
						i, n, previous)
				}
				previous = n
			}
			if n := recordIn(t, path); n <= previous {
				t.Errorf("the current file holds record %d, not newer than .1's %d", n, previous)
			}
		})
	}
}

// A daemon that restarts often must not be able to append forever without ever reaching the
// threshold, which is what counting from zero on every Open would allow.
func TestReopeningPicksUpTheSizeAlreadyOnDisk(t *testing.T) {
	path := filepath.Join(t.TempDir(), "meshpd.log")
	if err := os.WriteFile(path, []byte(strings.Repeat("y", 90)), 0o600); err != nil {
		t.Fatal(err)
	}

	l, err := Open(path, 100, 1)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })

	if _, err := l.Write([]byte("this takes it over the line\n")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path + ".1"); err != nil {
		t.Errorf("a file already at 90 of 100 bytes did not rotate on the next write: %v", err)
	}
}

// slog writes from whichever goroutine logged, and the reconciler, the control channel and
// the socket server all log.
func TestConcurrentWritersDoNotCorruptTheCount(t *testing.T) {
	path := filepath.Join(t.TempDir(), "meshpd.log")
	l, err := Open(path, 200, 3)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				if _, err := fmt.Fprintf(l, "goroutine %d record %d\n", n, j); err != nil {
					t.Errorf("write: %v", err)
					return
				}
			}
		}(i)
	}
	wg.Wait()

	for _, name := range onDisk(t, path) {
		info, err := os.Stat(name)
		if err != nil {
			t.Fatal(err)
		}
		// Each file is bounded by the limit plus the one record that crossed it.
		if info.Size() > 200+64 {
			t.Errorf("%s is %d bytes, past a 200-byte limit", name, info.Size())
		}
	}
}

func TestOpenRefusesASizeThatWouldRotateOnEveryWrite(t *testing.T) {
	if _, err := Open(filepath.Join(t.TempDir(), "l"), 0, 1); err == nil {
		t.Error("a maximum size of zero was accepted")
	}
}

func onDisk(t *testing.T, path string) []string {
	t.Helper()
	names, err := filepath.Glob(path + "*")
	if err != nil {
		t.Fatal(err)
	}
	return names
}

// recordIn returns the number of the first record in a file, so files can be compared by
// age without depending on how many rotations it took to get there.
func recordIn(t *testing.T, path string) int {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	var n int
	if _, err := fmt.Sscanf(string(raw), "record number %d", &n); err != nil {
		t.Fatalf("%s does not start with a record: %q", path, raw)
	}
	return n
}
