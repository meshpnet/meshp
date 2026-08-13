package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"runtime"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/meshpnet/meshp/internal/agentapi"
	"github.com/meshpnet/meshp/internal/agentstate"
	"github.com/meshpnet/meshp/internal/controlurl"
	"github.com/meshpnet/meshp/internal/enrollclient"
	"github.com/meshpnet/meshp/internal/keys"
	"github.com/meshpnet/meshp/internal/peerset"
	"github.com/meshpnet/meshp/internal/sessionclient"
	"github.com/meshpnet/meshp/internal/tunnel"
	"github.com/meshpnet/meshp/internal/version"
	"github.com/meshpnet/meshp/internal/wglink"
)

// agent owns this device's state and its control-channel sessions.
//
// It is the daemon's side of the privilege boundary: the keys, the enrolment and the
// sessions all live here, and meshp reaches them only through the local socket.
type agent struct {
	log       *slog.Logger
	stateDir  string
	startedAt time.Time

	// reconcileEvery is how often the interface is checked against desired state even
	// when nothing has changed. Zero switches it off, which is only useful in tests that
	// want to observe drift rather than have it corrected.
	reconcileEvery time.Duration

	// mu guards state and running together. Both change when a device joins, and a
	// status read that saw one without the other would report a membership with no
	// session or a session with no membership.
	mu      sync.Mutex
	state   *agentstate.State
	running map[uuid.UUID]*sessionHandle

	// link is the host's interface manager, opened once and shared: it holds netlink
	// sockets, and a device in several networks would otherwise open a pair for each.
	// Opened lazily on the first session, because it needs privileges and a daemon that
	// refused to start without them could not report why it has no tunnel.
	linkOnce sync.Once
	link     wglink.Link
	linkErr  error

	ctx context.Context
}

// reconcilerFor returns something to converge this membership's interface, or nil when this
// platform or this process cannot manage one.
//
// Nil rather than an error, because there is nothing to do about it here and it is not a
// reason to refuse the session: the control channel is still worth having, the device is
// still enrolled, and `meshp status` still has something true to report. What would be wrong
// is claiming a tunnel exists.
func (a *agent) reconcilerFor(m agentstate.Membership, log *slog.Logger) *tunnel.Reconciler {
	a.linkOnce.Do(func() {
		a.link, a.linkErr = wglink.New()
		switch {
		case errors.Is(a.linkErr, wglink.ErrUnsupported):
			a.log.Warn("no tunnel on this platform",
				"os", runtime.GOOS,
				"note", "devices enrol and hold addresses; nothing routes to them")
		case a.linkErr != nil:
			a.log.Error("cannot manage WireGuard interfaces",
				"error", a.linkErr,
				"hint", "meshpd needs to run with enough privilege to create network interfaces")
		}
	})
	if a.link == nil {
		return nil
	}
	return tunnel.New(a.link, tunnel.Membership{
		InterfaceName: m.InterfaceName,
		PrivateKey:    m.WireGuardPrivateKey,
		AddressV4:     m.AddressV4,
		AddressV6:     m.AddressV6,
	}, log)
}

// sessionHandle is one supervised session.
type sessionHandle struct {
	cancel  context.CancelFunc
	client  *sessionclient.Client
	applier *deviceApplier
	started time.Time
}

func newAgent(ctx context.Context, log *slog.Logger, stateDir string, reconcileEvery time.Duration) *agent {
	return &agent{
		log:            log,
		stateDir:       stateDir,
		startedAt:      time.Now().UTC(),
		reconcileEvery: reconcileEvery,
		running:        make(map[uuid.UUID]*sessionHandle),
		ctx:            ctx,
	}
}

// load reads local state, tolerating its absence.
//
// Not being enrolled is a normal condition: the agent may be installed before anyone
// has a token, and it must stay up so that `meshp join` has something to talk to. An
// earlier version exited here, which meant joining required restarting a service.
func (a *agent) load() error {
	state, err := agentstate.Load(a.stateDir)
	switch {
	case err == nil:
		a.mu.Lock()
		a.state = state
		a.mu.Unlock()
		a.log.Info("local state loaded", "memberships", len(state.Memberships))
		return nil
	case isNotEnrolled(err):
		a.log.Info("not enrolled yet; waiting for a join",
			"state_dir", a.stateDir, "hint", "run 'meshp join <token>'")
		return nil
	default:
		// A state file that exists but cannot be read is different from no state file at
		// all, and must not be treated as "start fresh" — that would abandon the device's
		// identity and leave a registered device nobody can revoke by name.
		return err
	}
}

// startAll supervises a session for every membership.
func (a *agent) startAll() {
	a.mu.Lock()
	memberships := a.membershipsLocked()
	a.mu.Unlock()

	for _, m := range memberships {
		a.ensureSession(m)
	}
}

func (a *agent) membershipsLocked() []agentstate.Membership {
	if a.state == nil {
		return nil
	}
	out := make([]agentstate.Membership, len(a.state.Memberships))
	copy(out, a.state.Memberships)
	return out
}

// ensureSession starts a session for a membership if one is not already running.
//
// One session per membership, each independent: a device in several networks must not
// lose one because another network's control plane is down (ADR-0004).
func (a *agent) ensureSession(m agentstate.Membership) {
	a.mu.Lock()
	if _, exists := a.running[m.MembershipID]; exists {
		a.mu.Unlock()
		return
	}
	identity, err := a.state.Identity()
	if err != nil {
		a.mu.Unlock()
		a.log.Error("cannot start a session without a usable identity", "error", err)
		return
	}

	sessionCtx, cancel := context.WithCancel(a.ctx)
	log := a.log.With("network_id", m.NetworkID)
	applier := &deviceApplier{
		log:          log,
		membershipID: m.MembershipID,
		agent:        a,
		reconciler:   a.reconcilerFor(m, log),
	}
	client := sessionclient.New(sessionclient.Options{
		ControlURL:   m.ControlURL,
		Identity:     identity,
		MembershipID: m.MembershipID,
		AgentVersion: version.Version(),
		OS:           runtime.GOOS,
		Hostname:     hostname(),
		Log:          log,
	})
	a.running[m.MembershipID] = &sessionHandle{
		cancel: cancel, client: client, applier: applier, started: time.Now().UTC(),
	}
	a.mu.Unlock()

	go func() {
		defer func() {
			a.mu.Lock()
			delete(a.running, m.MembershipID)
			a.mu.Unlock()
		}()
		if err := client.Run(sessionCtx, applier); err != nil && sessionCtx.Err() == nil {
			log.Error("session ended", "error", err)
		}
	}()

	// Converge on a timer as well as on arrival. Desired state changing is not the only
	// thing that can make an interface wrong, and nothing else would notice.
	go a.reconcileLoop(sessionCtx, applier)
}

// reconcileLoop re-applies desired state periodically for as long as the session lives.
func (a *agent) reconcileLoop(ctx context.Context, applier *deviceApplier) {
	if a.reconcileEvery <= 0 {
		return
	}
	ticker := time.NewTicker(a.reconcileEvery)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			applier.reconcile(ctx)
		}
	}
}

// setApplied records that a version was applied, and persists it.
func (a *agent) setApplied(membershipID uuid.UUID, appliedVersion int64) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.state == nil {
		return fmt.Errorf("meshpd: no local state to record version %d against", appliedVersion)
	}
	for i := range a.state.Memberships {
		if a.state.Memberships[i].MembershipID != membershipID {
			continue
		}
		if a.state.Memberships[i].AppliedStateVersion == appliedVersion {
			return nil // nothing changed; no need to rewrite the file
		}
		a.state.Memberships[i].AppliedStateVersion = appliedVersion
		return agentstate.Save(a.stateDir, a.state)
	}
	return fmt.Errorf("meshpd: no local membership %s", membershipID)
}

// Status implements agentapi.Handler.
func (a *agent) Status(_ context.Context) (agentapi.Status, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	status := agentapi.Status{
		Version:   version.Version(),
		StartedAt: a.startedAt,
		Enrolled:  a.state != nil,
	}
	if a.state == nil {
		return status, nil
	}
	status.IdentityPublicKey = a.state.IdentityPublicKey

	for _, m := range a.state.Memberships {
		ms := agentapi.MembershipStatus{
			MembershipID:        m.MembershipID,
			NetworkID:           m.NetworkID,
			DeviceID:            m.DeviceID,
			ControlURL:          m.ControlURL,
			InterfaceName:       m.InterfaceName,
			AddressV4:           m.AddressV4,
			AddressV6:           m.AddressV6,
			WireGuardPublicKey:  m.WireGuardPublicKey,
			AppliedStateVersion: m.AppliedStateVersion,
			JoinedAt:            m.JoinedAt,
			// Only ever true from a live reconciler below. A membership read from disk says
			// nothing about whether an interface is up right now.
			TunnelUp: false,
		}
		if handle, ok := a.running[m.MembershipID]; ok {
			// Live, from the session rather than from disk. This is the reason to ask the
			// daemon instead of reading the state file: the file cannot say whether the
			// control plane is reachable right now.
			ms.Connected = true
			ms.ConnectedSince = handle.started
			ms.AppliedStateVersion = handle.client.AppliedVersion()
			ms.LastError = handle.applier.lastError()
			ms.TunnelUp, ms.TunnelKind = handle.applier.tunnelStatus()
		}
		status.Memberships = append(status.Memberships, ms)
	}
	return status, nil
}

// Join implements agentapi.Handler.
//
// This is the whole reason the socket exists. The keys are generated here, in the
// privileged process, and the private halves never leave it — not to the CLI that asked,
// and not to the control plane (Invariant 1).
func (a *agent) Join(ctx context.Context, req agentapi.JoinRequest) (agentapi.JoinResponse, error) {
	// Validated here because this is where it enters the system, and because a join sends
	// an enrolment token to whatever address it is given.
	controlURL, err := controlurl.Validate(req.ControlURL)
	if err != nil {
		return agentapi.JoinResponse{}, err
	}

	a.mu.Lock()
	if a.state == nil {
		a.state = &agentstate.State{}
		identity, err := keys.NewIdentity()
		if err != nil {
			a.mu.Unlock()
			return agentapi.JoinResponse{}, err
		}
		a.state.SetIdentity(identity)
	}
	identity, err := a.state.Identity()
	a.mu.Unlock()
	if err != nil {
		return agentapi.JoinResponse{}, err
	}

	// A fresh WireGuard keypair per membership, never shared between them, so two
	// networks cannot recognise this device by its key (Invariant 19).
	wg, err := keys.NewWireGuardPair()
	if err != nil {
		return agentapi.JoinResponse{}, err
	}

	name := req.Name
	if name == "" {
		name = hostname()
	}

	res, err := enrollclient.New(controlURL, nil).Join(ctx, enrollclient.JoinRequest{
		Token:        req.Token,
		Identity:     identity,
		WireGuard:    wg,
		Name:         name,
		Hostname:     hostname(),
		OS:           runtime.GOOS,
		AgentVersion: version.Version(),
	})
	if err != nil {
		return agentapi.JoinResponse{}, err
	}

	membership := agentstate.Membership{
		MembershipID:        res.MembershipID,
		NetworkID:           res.NetworkID,
		DeviceID:            res.DeviceID,
		ControlURL:          controlURL,
		InterfaceName:       res.InterfaceName,
		WireGuardPrivateKey: wg.Private.String(),
		WireGuardPublicKey:  wg.Public.String(),
		JoinedAt:            time.Now().UTC(),
	}
	if res.AddressV4 != nil {
		membership.AddressV4 = res.AddressV4.String()
	}
	if res.AddressV6 != nil {
		membership.AddressV6 = res.AddressV6.String()
	}

	a.mu.Lock()
	a.state.AddMembership(membership)
	saveErr := agentstate.Save(a.stateDir, a.state)
	a.mu.Unlock()

	if saveErr != nil {
		// The device exists in the network but cannot prove who it is. Reporting success
		// here would leave an operator with a registered device and no way to use it and
		// no idea why.
		return agentapi.JoinResponse{}, fmt.Errorf(
			"enrolled, but the keys could not be saved to %s: %w (revoke the device and try again)",
			a.stateDir, saveErr)
	}

	a.log.Info("joined a network",
		"network_id", res.NetworkID, "membership_id", res.MembershipID,
		"interface", res.InterfaceName, "address_v4", membership.AddressV4)

	// Start serving it immediately. Requiring a restart to pick up a join is the kind
	// of paper cut that makes people script around the daemon.
	a.ensureSession(membership)

	return agentapi.JoinResponse{
		MembershipID:  res.MembershipID,
		NetworkID:     res.NetworkID,
		DeviceID:      res.DeviceID,
		InterfaceName: res.InterfaceName,
		AddressV4:     membership.AddressV4,
		AddressV6:     membership.AddressV6,
	}, nil
}

// deviceApplier converges the interface and records how far this device has got.
//
// Two jobs rather than one because they fail independently and both matter. Converging is
// what makes the network work; persisting the version is what makes `meshp status` and the
// control plane agree about what this device has — a version acknowledged but never written
// is requested again on every restart, and reported as applied while the state file says
// otherwise.
//
// The interface comes first. Recording a version this host has not reached would tell the
// control plane the device is converged when it is not, and the convergence metric is the
// one thing that would otherwise show a broken agent.
type deviceApplier struct {
	log          *slog.Logger
	membershipID uuid.UUID
	agent        *agent

	// reconciler is nil where there is no data-plane implementation. The device is then
	// enrolled, holds an address and has no tunnel — a state it reports rather than hides.
	reconciler *tunnel.Reconciler

	mu   sync.Mutex
	last string

	// lastState is the desired state most recently applied, kept so it can be applied
	// again without the control plane sending it again.
	//
	// Keeping it is only safe because the set handed to an Applier belongs to it
	// (Invariant 22). If it were the session's live set, this would be re-applying
	// whatever the session had folded in by then rather than what was last converged on.
	lastState *peerset.Set
}

func (a *deviceApplier) Apply(ctx context.Context, state *peerset.Set) ([]string, error) {
	for _, p := range state.Peers() {
		a.log.Debug("peer in desired state",
			"device", p.GetDeviceName(),
			"allowed_ips", p.GetAllowedIps(),
			"public_key", truncateKey(p.GetPublicKey()))
	}

	if a.reconciler != nil {
		unapplied, err := a.reconciler.Apply(ctx, state)
		if err != nil {
			a.setLastError(err.Error())
			return unapplied, err
		}
	}

	if err := a.agent.setApplied(a.membershipID, int64(state.Version())); err != nil {
		a.setLastError(err.Error())
		return []string{"local-state"}, err
	}
	a.setLastError("")

	a.mu.Lock()
	a.lastState = state
	a.mu.Unlock()

	if a.reconciler == nil {
		a.log.Info("recorded desired state",
			"version", state.Version(),
			"peers", state.Len(),
			"note", "no tunnel: this platform has no data-plane implementation in this build")
	}
	return nil, nil
}

func (a *deviceApplier) setLastError(msg string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.last = msg
}

func (a *deviceApplier) lastError() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.last != "" {
		return a.last
	}
	if a.reconciler != nil {
		return a.reconciler.Status().LastError
	}
	return ""
}

// reconcile applies the last known desired state again.
//
// Called on a timer, because desired state arriving is not the only thing that can make an
// interface wrong. An operator can take it down, another process can remove an address, a
// crash can leave it half configured — and none of those cause the control plane to send
// anything, so without this the agent would sit next to a broken interface indefinitely
// believing itself converged.
//
// Safe to run as often as one likes because planning against a correct interface produces no
// operations at all (Invariant 18). A reconcile that finds nothing wrong costs two netlink
// reads and touches nothing, which is what makes a periodic tick affordable rather than a
// source of churn.
func (a *deviceApplier) reconcile(ctx context.Context) {
	if a.reconciler == nil {
		return
	}
	a.mu.Lock()
	state := a.lastState
	a.mu.Unlock()
	if state == nil {
		return // nothing has been applied yet; there is nothing to restore it to
	}

	if _, err := a.reconciler.Apply(ctx, state); err != nil {
		a.setLastError(err.Error())
		return
	}
	a.setLastError("")
}

// tunnelStatus reports what the data plane is doing, or nothing when there is none.
func (a *deviceApplier) tunnelStatus() (up bool, kind string) {
	if a.reconciler == nil {
		return false, ""
	}
	st := a.reconciler.Status()
	return st.Up, string(st.Kind)
}

func truncateKey(k string) string {
	if len(k) <= 12 {
		return k
	}
	return k[:12] + "…"
}

func hostname() string {
	h, err := os.Hostname()
	if err != nil {
		return "unknown"
	}
	return h
}
