package main

import (
	"bytes"
	"io"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/meshpnet/meshp/internal/agentstate"
)

// quiet builds an agent on a fresh state directory. The log goes nowhere: these tests are
// about what the agent does, and the daemon is deliberately talkative.
func quiet(t *testing.T) *agent {
	t.Helper()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	return newAgent(t.Context(), log, t.TempDir(), 0)
}

// enrolled writes a state file with one membership and returns the directory and its id.
func enrolled(t *testing.T) (dir string, membershipID uuid.UUID) {
	t.Helper()
	dir = t.TempDir()
	membershipID = uuid.New()
	state := &agentstate.State{
		IdentityPublicKey:  "abcdefghijklmnopqrstuvwxyz0123456789ABCD",
		IdentityPrivateKey: "0123456789ABCDEFabcdef",
		Memberships: []agentstate.Membership{{
			MembershipID: membershipID,
			NetworkID:    uuid.New(),
			DeviceID:     uuid.New(),
			// Refused immediately rather than hung on, so a regression that started a
			// session here fails fast instead of waiting for a dial to time out.
			ControlURL:          "https://127.0.0.1:1",
			InterfaceName:       "meshp0",
			WireGuardPublicKey:  "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa=",
			WireGuardPrivateKey: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb=",
			JoinedAt:            time.Now().UTC(),
		}},
	}
	if err := agentstate.Save(dir, state); err != nil {
		t.Fatalf("writing state: %v", err)
	}
	return dir, membershipID
}

// Being installed before anybody has a token is the ordinary case, not a failure.
//
// An earlier version of this exited here, which meant joining a network required restarting
// a service. The socket has to come up on a device with no state at all or `meshp join` has
// nothing to talk to.
func TestADeviceWithNoStateStaysUpAndSaysSo(t *testing.T) {
	a := quiet(t)

	if err := a.load(); err != nil {
		t.Fatalf("a device that has never been enrolled refused to start: %v", err)
	}

	status, err := a.Status(t.Context())
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if status.Enrolled {
		t.Error("a device with no state reported itself enrolled")
	}
	if len(status.Memberships) != 0 {
		t.Errorf("a device with no state reported %d memberships", len(status.Memberships))
	}
	if status.StartedAt.IsZero() {
		t.Error("status carries no start time, so nothing can say how long this has been up")
	}
}

// And the other half of that, which is the dangerous one.
//
// A state file that exists and cannot be read is not "start fresh". Treating it as one
// abandons the device's identity and leaves a registered device that nobody can revoke by
// name — the device's own record of who it is, gone because a write was truncated.
func TestAStateFileThatCannotBeReadIsNotStartFresh(t *testing.T) {
	a := quiet(t)
	if err := os.WriteFile(agentstate.Path(a.stateDir), []byte("{ this is not"), 0o600); err != nil {
		t.Fatalf("writing a broken state file: %v", err)
	}

	if err := a.load(); err == nil {
		t.Fatal("an unreadable state file was accepted; this device has just forgotten who it is")
	}

	status, err := a.Status(t.Context())
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if status.Enrolled {
		t.Error("a device whose state would not load reported itself enrolled")
	}
}

// Taking a device off the mesh has to survive a reboot.
//
// A machine that came back up carrying traffic its owner had deliberately stopped would be
// the opposite of what they asked for, and they would have no reason to check.
func TestBeingTakenDownSurvivesARestart(t *testing.T) {
	dir, _ := enrolled(t)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	first := newAgent(t.Context(), log, dir, 0)
	if err := first.load(); err != nil {
		t.Fatalf("loading: %v", err)
	}
	first.setPaused(true)

	// A different agent on the same directory, which is what a restart is.
	second := newAgent(t.Context(), log, dir, 0)
	if err := second.load(); err != nil {
		t.Fatalf("loading after a restart: %v", err)
	}
	if !second.paused() {
		t.Fatal("a device taken down deliberately came back up on the mesh")
	}

	status, err := second.Status(t.Context())
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if !status.Paused {
		t.Error("status does not say the device was taken down, so nobody can tell this from a fault")
	}
}

// And a device that was taken down does not merely fail to connect — it does not look at its
// memberships at all.
//
// The guard is in startAll rather than at its call sites, because the call sites are "the
// daemon started" and "somebody ran meshp up", and only one of them knows about pausing.
//
// Read out of the log, which is the only place this decision is visible and is also where an
// operator would look for it. The unpaused half is not a courtesy: without it this passes on
// any agent that fails to start a session for any reason at all, which is what the first
// version of this test did.
func TestADeviceTakenDownDoesNotEvenLookAtItsMemberships(t *testing.T) {
	downDir, _ := enrolled(t)
	upDir, _ := enrolled(t)

	var down, up bytes.Buffer

	stopped := newAgent(t.Context(), slog.New(slog.NewTextHandler(&down, nil)), downDir, 0)
	if err := stopped.load(); err != nil {
		t.Fatalf("loading: %v", err)
	}
	stopped.setPaused(true)
	stopped.startAll()

	started := newAgent(t.Context(), slog.New(slog.NewTextHandler(&up, nil)), upDir, 0)
	if err := started.load(); err != nil {
		t.Fatalf("loading: %v", err)
	}
	started.startAll()

	// The membership these tests write carries an identity that will not decode, so an
	// agent that reaches it says so. That is the marker: reaching it at all is the failure.
	const reached = "cannot start a session without a usable identity"

	if !strings.Contains(up.String(), reached) {
		t.Fatalf("the running device never reached its memberships, so this test would pass "+
			"whatever the guard did:\n%s", up.String())
	}
	if strings.Contains(down.String(), reached) {
		t.Errorf("a device taken down deliberately went on to consider its memberships:\n%s",
			down.String())
	}
	if !strings.Contains(down.String(), "staying off the mesh") {
		t.Errorf("nothing in the log says why this device is doing nothing:\n%s", down.String())
	}
}

// Recording against state that is not there has to be an error rather than a silent no-op.
//
// These are called from the session as it applies what the server sent. Swallowing them
// would leave a device reporting a state version it never converged on, and the control
// plane sending deltas from a point the device never reached.
func TestRecordingAgainstStateThatIsNotThereIsAnError(t *testing.T) {
	a := quiet(t)
	if err := a.load(); err != nil {
		t.Fatalf("loading: %v", err)
	}

	if err := a.setApplied(uuid.New(), 7); err == nil {
		t.Error("a state version was recorded against a device with no local state")
	}
	if err := a.setListenPort(uuid.New(), 51820); err == nil {
		t.Error("a listen port was recorded against a device with no local state")
	}

	// And with state, against a membership this device does not have.
	dir, _ := enrolled(t)
	b := newAgent(t.Context(), slog.New(slog.NewTextHandler(io.Discard, nil)), dir, 0)
	if err := b.load(); err != nil {
		t.Fatalf("loading: %v", err)
	}
	if err := b.setApplied(uuid.New(), 7); err == nil {
		t.Error("a state version was recorded against a membership this device does not have")
	}
	if err := b.setListenPort(uuid.New(), 51820); err == nil {
		t.Error("a listen port was recorded against a membership this device does not have")
	}
}

// An unchanged value is not written back.
//
// This runs on every reconcile, which is once a minute per membership on every device. A
// device that rewrote its state file each time would be doing a disk write a minute to
// record that nothing had changed — and the point of persisting the port at all is that the
// next start asks for the same one, which an unchanged write does not help with.
func TestAnUnchangedValueIsNotWrittenBack(t *testing.T) {
	dir, membershipID := enrolled(t)
	a := newAgent(t.Context(), slog.New(slog.NewTextHandler(io.Discard, nil)), dir, 0)
	if err := a.load(); err != nil {
		t.Fatalf("loading: %v", err)
	}

	if err := a.setListenPort(membershipID, 51820); err != nil {
		t.Fatalf("recording a port: %v", err)
	}
	if err := a.setApplied(membershipID, 12); err != nil {
		t.Fatalf("recording a version: %v", err)
	}

	written, err := agentstate.Load(dir)
	if err != nil {
		t.Fatalf("reading back: %v", err)
	}
	before := written.UpdatedAt

	// The same values again, which is what every reconcile after the first sends.
	if err := a.setListenPort(membershipID, 51820); err != nil {
		t.Fatalf("recording the same port: %v", err)
	}
	if err := a.setApplied(membershipID, 12); err != nil {
		t.Fatalf("recording the same version: %v", err)
	}

	after, err := agentstate.Load(dir)
	if err != nil {
		t.Fatalf("reading back: %v", err)
	}
	if !after.UpdatedAt.Equal(before) {
		t.Errorf("the state file was rewritten for values that had not changed (%s then %s)",
			before, after.UpdatedAt)
	}
}

// A port of zero is not a port. It is what a membership that has never come up says, and
// recording it would overwrite the one this device settled on last time.
func TestAPortOfZeroIsNotRecorded(t *testing.T) {
	dir, membershipID := enrolled(t)
	a := newAgent(t.Context(), slog.New(slog.NewTextHandler(io.Discard, nil)), dir, 0)
	if err := a.load(); err != nil {
		t.Fatalf("loading: %v", err)
	}
	if err := a.setListenPort(membershipID, 51820); err != nil {
		t.Fatalf("recording a port: %v", err)
	}

	if err := a.setListenPort(membershipID, 0); err != nil {
		t.Fatalf("a port of zero was an error: %v", err)
	}

	written, err := agentstate.Load(dir)
	if err != nil {
		t.Fatalf("reading back: %v", err)
	}
	if got := written.Memberships[0].ListenPort; got != 51820 {
		t.Errorf("the port this device settled on became %d; peers now hold a dead endpoint", got)
	}
}

// A membership read from disk says nothing about whether an interface is up right now.
//
// This is the reason to ask the daemon rather than read the state file, and reporting a
// tunnel that is not there would make `meshp status` agree with the device's hopes.
func TestAMembershipFromDiskIsNotAReportOfALiveTunnel(t *testing.T) {
	dir, _ := enrolled(t)
	a := newAgent(t.Context(), slog.New(slog.NewTextHandler(io.Discard, nil)), dir, 0)
	if err := a.load(); err != nil {
		t.Fatalf("loading: %v", err)
	}

	status, err := a.Status(t.Context())
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if len(status.Memberships) != 1 {
		t.Fatalf("got %d memberships, want 1", len(status.Memberships))
	}
	m := status.Memberships[0]
	if m.TunnelUp {
		t.Error("a membership with no running session reported a tunnel that is up")
	}
	if m.Connected {
		t.Error("a membership with no running session reported a live control channel")
	}
	if m.Relay != nil {
		t.Error("a membership with no running session reported a relay attachment")
	}
}

// A device with no data plane reports no tunnel, rather than an empty one.
//
// "" is not a kind. A status that said the tunnel was down and named a kind would read as a
// broken interface rather than as a platform that has none.
func TestNoDataPlaneReportsNoTunnelAndNoKind(t *testing.T) {
	applier := &deviceApplier{}

	up, kind := applier.tunnelStatus()
	if up || kind != "" {
		t.Errorf("a membership with no reconciler reported up=%v kind=%q", up, kind)
	}
	if got := applier.lastError(); got != "" {
		t.Errorf("a membership with no reconciler reported the error %q", got)
	}

	// What the applier was told beats what the reconciler would say, and there is no
	// reconciler here to say anything.
	applier.setLastError("the control plane refused this device")
	if got := applier.lastError(); got != "the control plane refused this device" {
		t.Errorf("the recorded error was lost: %q", got)
	}
}

// Keys are elided in logs, and a short one is left alone rather than being decorated with an
// ellipsis that suggests there is more to it.
func TestAKeyIsElidedOnlyWhenThereIsSomethingToElide(t *testing.T) {
	const key = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa="

	long := truncateKey(key)
	if len(long) >= len(key) {
		t.Errorf("a full key reached the log: %q", long)
	}
	if !strings.HasSuffix(long, "…") {
		t.Errorf("an elided key does not say it was elided: %q", long)
	}

	if got := truncateKey("short"); got != "short" {
		t.Errorf("a short key was decorated: %q", got)
	}
}
