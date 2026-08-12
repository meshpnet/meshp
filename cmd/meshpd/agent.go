package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"runtime"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/meshpnet/meshp/internal/agentapi"
	"github.com/meshpnet/meshp/internal/agentstate"
	"github.com/meshpnet/meshp/internal/enrollclient"
	"github.com/meshpnet/meshp/internal/keys"
	"github.com/meshpnet/meshp/internal/sessionclient"
	"github.com/meshpnet/meshp/internal/version"
	meshpv1 "github.com/meshpnet/meshp/proto/gen/meshp/v1"
)

// agent owns this device's state and its control-channel sessions.
//
// It is the daemon's side of the privilege boundary: the keys, the enrolment and the
// sessions all live here, and meshp reaches them only through the local socket.
type agent struct {
	log       *slog.Logger
	stateDir  string
	startedAt time.Time

	// mu guards state and running together. Both change when a device joins, and a
	// status read that saw one without the other would report a membership with no
	// session or a session with no membership.
	mu      sync.Mutex
	state   *agentstate.State
	running map[uuid.UUID]*sessionHandle

	ctx context.Context
}

// sessionHandle is one supervised session.
type sessionHandle struct {
	cancel  context.CancelFunc
	client  *sessionclient.Client
	applier *recordingApplier
	started time.Time
}

func newAgent(ctx context.Context, log *slog.Logger, stateDir string) *agent {
	return &agent{
		log:       log,
		stateDir:  stateDir,
		startedAt: time.Now().UTC(),
		running:   make(map[uuid.UUID]*sessionHandle),
		ctx:       ctx,
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
	applier := &recordingApplier{log: log, membershipID: m.MembershipID, agent: a}
	client := sessionclient.New(sessionclient.Options{
		ControlURL:     m.ControlURL,
		Identity:       identity,
		MembershipID:   m.MembershipID,
		AppliedVersion: m.AppliedStateVersion,
		AgentVersion:   version.Version(),
		OS:             runtime.GOOS,
		Hostname:       hostname(),
		Log:            log,
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
			// Never true in this build, and saying so is the point: a membership with an
			// address is not a working tunnel.
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
	controlURL := req.ControlURL
	if controlURL == "" {
		return agentapi.JoinResponse{}, fmt.Errorf("meshpd: a control URL is required")
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

// recordingApplier is the Applier this build ships: it writes down what it was told and
// reports success.
//
// Deliberately not pretending to configure anything. When WireGuard arrives this becomes
// the reconciler and its acknowledgement will mean the system reached that state. Until
// then the log says so, so nobody mistakes a converged control plane for a working
// network.
type recordingApplier struct {
	log          *slog.Logger
	membershipID uuid.UUID
	agent        *agent

	mu   sync.Mutex
	last string
}

func (a *recordingApplier) Apply(_ context.Context, delta *meshpv1.StateDelta) ([]string, error) {
	for _, p := range delta.GetUpsertPeers() {
		a.log.Debug("peer in desired state",
			"device", p.GetDeviceName(),
			"allowed_ips", p.GetAllowedIps(),
			"public_key", truncateKey(p.GetPublicKey()))
	}

	if err := a.agent.setApplied(a.membershipID, int64(delta.GetToVersion())); err != nil {
		a.setLastError(err.Error())
		// Persisting matters: a version acknowledged but not written would be requested
		// again on every restart, and a future reconciler would believe the host already
		// matched a state it had never applied.
		return []string{"local-state"}, err
	}
	a.setLastError("")

	a.log.Info("recorded desired state",
		"version", delta.GetToVersion(),
		"peers", len(delta.GetUpsertPeers()),
		"note", "nothing is configured: this build has no WireGuard")
	return nil, nil
}

func (a *recordingApplier) setLastError(msg string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.last = msg
}

func (a *recordingApplier) lastError() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.last
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
