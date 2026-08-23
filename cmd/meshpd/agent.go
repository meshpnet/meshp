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
	"github.com/meshpnet/meshp/internal/dns"
	"github.com/meshpnet/meshp/internal/enrollclient"
	"github.com/meshpnet/meshp/internal/keys"
	"github.com/meshpnet/meshp/internal/nftables"
	"github.com/meshpnet/meshp/internal/pathprobe"
	"github.com/meshpnet/meshp/internal/peerset"
	"github.com/meshpnet/meshp/internal/relaylink"
	"github.com/meshpnet/meshp/internal/resolved"
	"github.com/meshpnet/meshp/internal/routeprobe"
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

	// filter enforces network policy, opened once and shared. Nil where this host cannot
	// filter, which the agent reports honestly rather than accepting a policy it will not
	// apply (ADR-0007).
	filterOnce sync.Once
	filter     *nftables.Filter

	// claims is what every membership on this device says it carries, shared so that two
	// networks asking for the same customer prefix can each see the other. One device can
	// hold memberships in many networks (ADR-0004), and two customers who both took their
	// router's default both carry 192.168.1.0/24.
	claims *tunnel.Claims

	// zones is every name this device can answer for, across every network it is in, and
	// resolver is what answers from them. Shared for the reason claims is: a bare name
	// that exists in two of this device's networks is ambiguous, and only something that
	// sees both can say so (ADR-0021).
	zones    *dns.Zones
	resolver *dns.Server

	// systemResolver points this machine's own resolver at the agent, or is nil on a host
	// where meshp cannot configure one and put it back afterwards. Nil means names answer
	// only to something querying the agent directly, which the status command says plainly
	// rather than leaving somebody to wonder why `ssh fileserver` does not work.
	systemResolverOnce sync.Once
	systemResolver     *resolved.Resolvectl

	ctx context.Context
}

// ensureLink opens the host's interface manager, once.
//
// Lazily, because it needs privileges and a daemon that refused to start without them could
// not report why it has no tunnel.
func (a *agent) ensureLink() wglink.Link {
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
	return a.link
}

// reconcilerFor returns something to converge this membership's interface, or nil when this
// platform or this process cannot manage one.
//
// Nil rather than an error, because there is nothing to do about it here and it is not a
// reason to refuse the session: the control channel is still worth having, the device is
// still enrolled, and `meshp status` still has something true to report. What would be wrong
// is claiming a tunnel exists.
func (a *agent) reconcilerFor(m agentstate.Membership, relay tunnel.Relay, chooser *routeprobe.Chooser, log *slog.Logger) *tunnel.Reconciler {
	if a.ensureLink() == nil {
		return nil
	}
	return tunnel.New(a.link, tunnel.Membership{
		InterfaceName: m.InterfaceName,
		PrivateKey:    m.WireGuardPrivateKey,
		AddressV4:     m.AddressV4,
		AddressV6:     m.AddressV6,
		ListenPort:    m.ListenPort,
		ControlURL:    m.ControlURL,
	}, relay, a.filterOrNil(), log).
		WithChooser(chooser).
		WithEgress(routerOrNil()).
		WithProber(proberOrNil()).
		WithClaims(a.claims).
		WithNames(a.zones).
		WithSystemResolver(a.systemResolverOrNil(), a.resolver.Addr)
}

// proberOrNil converts a possibly-absent dialer into the interface.
//
// Explicit for the reason routerOrNil is, and it has bitten this project already: a nil
// *pathprobe.BoundDialer assigned straight to an interface is a non-nil interface holding a
// nil pointer, so the reconciler's `r.prober == nil` check would pass and every probe would
// panic on a platform that has no dialer.
func proberOrNil() tunnel.Prober {
	if d := pathprobe.NewDialer(); d != nil {
		return d
	}
	return nil
}

// systemResolverOrNil converts a possibly-absent resolver configurer into the interface.
//
// Explicit for the reason routerOrNil and proberOrNil are: a nil *resolved.Resolvectl
// assigned straight to an interface is a non-nil interface holding a nil pointer, so the
// reconciler's own nil check would pass and every reconcile would call a method on nothing.
//
// Once, and lazily: it asks systemd-resolved for its status, which is a process spawn, and
// doing that per membership per reconcile would be a spawn a minute for nothing.
func (a *agent) systemResolverOrNil() tunnel.SystemResolver {
	a.systemResolverOnce.Do(func() {
		a.systemResolver = resolved.New(a.ctx)
		if a.systemResolver == nil {
			a.log.Warn("this machine's resolver cannot be configured by meshp",
				"note", "names answer to a direct query and nowhere else",
				"hint", "meshp status reports the resolver address; addresses always work")
		}
	})
	if a.systemResolver == nil {
		return nil
	}
	return a.systemResolver
}

// routerOrNil converts a possibly-absent router into the interface.
//
// Explicit for the same reason relayOrNil and filterOrNil are: a nil *wglink.Router assigned
// straight to an interface is a non-nil interface holding a nil pointer, so every downstream
// nil check would pass and the reconciler would believe this host can claim a default route.
func routerOrNil() tunnel.Egress {
	if r := wglink.NewRouter(); r != nil {
		return r
	}
	return nil
}

// reclaimEgressLock removes a fail-closed lock left behind by a previous life.
//
// This is the half of ADR-0011 that makes the other half safe to have. The rules survive
// this process on purpose — that is the point of them, since agent crash and agent kill are
// two of the cases the feature exists to cover — which means the only thing standing between
// a `kill -9` and a machine somebody has to physically recover is a daemon that finds them
// again and takes them off (Invariant 20).
//
// Unconditional, and deliberately so. At this moment there is no tunnel and no route claimed
// through one, so a lock here is not protecting traffic; it is only denying it. Whatever
// this run decides to be, it reinstalls the lock before it claims a route, which is the
// order ADR-0011 requires anyway. The window between the two is a device that is not
// tunnelled — which is exactly what it was while the daemon was dead.
//
// Reported only when one was actually found, because "removed a lock" and "there was
// nothing to remove" are different events and only the first explains an outage.
func (a *agent) reclaimEgressLock() {
	// The routing first, for the same reason a release does it first: rules pointing at a
	// table whose tunnel is gone send traffic nowhere, and they outlive this process exactly
	// as the lock does.
	if held, err := wglink.EgressHeld(); err == nil && held {
		a.log.Warn("found a default route claimed by a previous run",
			"cause", "meshpd exited or was killed while sending everything through the tunnel")
		if err := wglink.NewRouter().Release(); err != nil {
			a.log.Error("could not release it; this device may have no working routing",
				"error", err)
		}
	}

	filter := a.ensureFilter()
	if filter == nil || !nftables.LockHeld(a.ctx) {
		return
	}

	a.log.Warn("found a fail-closed lock from a previous run; this device had no egress",
		"table", nftables.LockTableName,
		"cause", "meshpd exited or was killed while a default route was claimed")
	if err := filter.ApplyLock(a.ctx, "", nil, nil, false); err != nil {
		// The worst outcome this project has: a machine with no network and no obvious
		// cause. Say what it is and how to undo it by hand, because whoever reads this is
		// at a console on a host that cannot reach anything.
		a.log.Error("could not remove it; this device still has no egress",
			"error", err,
			"fix", "run: nft delete table inet "+nftables.LockTableName)
		return
	}
	a.log.Info("removed it; egress is restored")
}

// ensureFilter opens the host's packet filter, once.
//
// Probed rather than assumed: a container can have nft installed and no permission to use
// it, and finding that out at apply time would look like a policy fault rather than a
// missing capability.
func (a *agent) ensureFilter() *nftables.Filter {
	a.filterOnce.Do(func() {
		a.filter = nftables.New(a.ctx)
		if a.filter == nil {
			a.log.Warn("this host cannot enforce a packet filter",
				"os", runtime.GOOS,
				"note", "networks with a policy will report this device as unconverged")
		}
	})
	return a.filter
}

// filterOrNil converts a possibly-absent filter into the interface.
//
// Explicit for the same reason relayOrNil is: a nil *nftables.Filter assigned straight to
// an interface is a non-nil interface holding a nil pointer, so every downstream nil check
// would pass and the reconciler would believe it can enforce.
func (a *agent) filterOrNil() tunnel.Filter {
	if f := a.ensureFilter(); f != nil {
		return f
	}
	return nil
}

// relayFor returns this membership's relay attachment, or nil when there is no data plane
// to carry relayed packets into.
//
// Nil rather than an error for the same reason the reconciler is: a device with no tunnel is
// still enrolled and still worth a control channel, and a relay connection with nowhere to
// deliver would be a connection kept open for nothing.
func (a *agent) relayFor(m agentstate.Membership, log *slog.Logger) *relaylink.Link {
	if a.ensureLink() == nil {
		return nil
	}
	link, err := relaylink.New(relaylink.Options{
		Key: m.WireGuardPublicKey,
		// Zero on a membership that has never come up. The reconciler supplies the kernel's
		// choice once the interface exists.
		WireGuardPort: m.ListenPort,
		Log:           log,
	})
	if err != nil {
		// Not fatal. Without a relay every peer is unreachable until a direct path exists,
		// which is where this was before relaying — and saying so is better than refusing
		// to serve the membership at all.
		log.Error("cannot relay for this membership",
			"error", err, "note", "peers will be unreachable until a direct path exists")
		return nil
	}
	return link
}

// sessionHandle is one supervised session.
type sessionHandle struct {
	cancel  context.CancelFunc
	client  *sessionclient.Client
	applier *deviceApplier
	relay   *relaylink.Link
	started time.Time
}

// relayOrNil and relayCredentials convert a possibly-absent link into interfaces.
//
// Explicitly, because a nil *relaylink.Link assigned straight to an interface produces a
// non-nil interface holding a nil pointer: every `if relay != nil` downstream would be true
// and the first call would panic. Platforms with no data plane take exactly that path.
// pathsOrNil hands over the reconciler as a path reporter, or nothing.
//
// A typed nil would satisfy the interface and be called, so the nil check has to happen
// here rather than at the call site — the same trap the control plane's presence hook
// documents.
func pathsOrNil(r *tunnel.Reconciler) sessionclient.PathReports {
	if r == nil {
		return nil
	}
	return r
}

func relayOrNil(l *relaylink.Link) tunnel.Relay {
	if l == nil {
		return nil
	}
	return l
}

func relayCredentials(l *relaylink.Link) sessionclient.RelayCredentials {
	if l == nil {
		return nil
	}
	return l
}

// relayStatus renders a link for the status socket, or nothing when there is no link.
func relayStatus(l *relaylink.Link) *agentapi.RelayStatus {
	if l == nil {
		return nil
	}
	st := l.Status()
	return &agentapi.RelayStatus{
		RelayID:          st.RelayID,
		Endpoints:        st.Endpoints,
		Connected:        st.Connected,
		ConnectedSince:   st.ConnectedSince,
		Endpoint:         st.Endpoint,
		Reflexive:        st.Reflexive,
		HasToken:         st.HasToken,
		TokenExpiresAt:   st.TokenExpiresAt,
		Refusal:          st.Refusal,
		LastError:        st.LastError,
		PeersRelayed:     st.Forwarder.Peers,
		PacketsRelayed:   st.Forwarder.Relayed,
		PacketsDelivered: st.Forwarder.Delivered,
		// Summed, because from here the interesting fact is that packets are being lost;
		// which counter caught them is a question for the daemon's log.
		Dropped: st.Forwarder.DroppedNoRelay + st.Forwarder.DroppedNoPeer +
			st.Forwarder.DroppedNoPort + st.Forwarder.SendFailed,
	}
}

func newAgent(ctx context.Context, log *slog.Logger, stateDir string, reconcileEvery time.Duration) *agent {
	zones := dns.NewZones()
	return &agent{
		log:            log,
		stateDir:       stateDir,
		startedAt:      time.Now().UTC(),
		reconcileEvery: reconcileEvery,
		running:        make(map[uuid.UUID]*sessionHandle),
		claims:         tunnel.NewClaims(),
		zones:          zones,
		resolver:       dns.NewServer(zones, log),
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
	// Nothing starts while this device is deliberately off the mesh. Checked here rather
	// than at each call site, because the call sites are "the daemon started" and "somebody
	// ran meshp up", and only one of them knows about pausing.
	if a.paused() {
		a.log.Info("staying off the mesh; this device was taken down deliberately",
			"restore", "meshp up")
		return
	}

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

	// Built before the reconciler, which needs it to give relayed peers an endpoint, and
	// handed to the session, which is how the credential to use it arrives (ADR-0017).
	relay := a.relayFor(m, log)

	// One chooser for as long as this membership is supervised, shared by the two halves of
	// the failover loop: the reconciler folds observations in and acts on the answer, and
	// the session drains the verdicts out to the control plane.
	//
	// It sits outside the session deliberately. A control channel dropping and reconnecting
	// must not reset the counters and hold times, because they are the whole mechanism — and
	// a control-plane outage is precisely when a device has to be able to leave a dead
	// gateway on its own (Invariant 15).
	chooser := routeprobe.New(nil)

	applier := &deviceApplier{
		log:          log,
		membershipID: m.MembershipID,
		agent:        a,
		relay:        relay,
		reconciler:   a.reconcilerFor(m, relayOrNil(relay), chooser, log),
	}
	client := sessionclient.New(sessionclient.Options{
		ControlURL:   m.ControlURL,
		Identity:     identity,
		MembershipID: m.MembershipID,
		AgentVersion: version.Version(),
		OS:           runtime.GOOS,
		Hostname:     hostname(),
		Relay:        relayCredentials(relay),
		CanFilter:    a.ensureFilter() != nil,
		Revoked:      &membershipRevoker{agent: a, membershipID: m.MembershipID},
		Reachability: chooser,
		// The same reconciler, asked a different question: what the tunnel it configured
		// actually looks like. Nil on a platform with no data plane, where there is
		// nothing to observe (#117).
		Paths: pathsOrNil(applier.reconciler),
		Log:   log,
	})
	a.running[m.MembershipID] = &sessionHandle{
		cancel: cancel, client: client, applier: applier, relay: relay, started: time.Now().UTC(),
	}
	a.mu.Unlock()

	// The relay connection is supervised alongside the session but not by it. A control
	// channel dropping must not disturb networking that is already up (Invariant 15), and a
	// relayed path is networking that is up: the token in hand outlives the connection that
	// delivered it, and reconnecting to the control plane does not interrupt the relay.
	if relay != nil {
		go func() {
			if err := relay.Run(sessionCtx); err != nil && sessionCtx.Err() == nil {
				log.Error("relay attachment ended", "error", err)
			}
		}()
	}

	go func() {
		defer func() {
			a.mu.Lock()
			delete(a.running, m.MembershipID)
			a.mu.Unlock()
			if relay != nil {
				// The sockets are this membership's endpoints; a session that has stopped
				// being supervised must not leave them behind.
				_ = relay.Close()
			}
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

// setListenPort records the port an interface settled on.
//
// Written only when it changes, which after the first time is almost never: the point of
// persisting it is that the next start asks for the same port, so peers keep working
// endpoints and NAT mappings survive a restart.
func (a *agent) setListenPort(membershipID uuid.UUID, port int) error {
	if port == 0 {
		return nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.state == nil {
		return fmt.Errorf("meshpd: no local state to record a listen port against")
	}
	for i := range a.state.Memberships {
		if a.state.Memberships[i].MembershipID != membershipID {
			continue
		}
		if a.state.Memberships[i].ListenPort == port {
			return nil
		}
		a.state.Memberships[i].ListenPort = port
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
		Paused:    a.state != nil && a.state.Paused,
	}
	// Before the enrolment check, because a resolver that is up on a device with no
	// memberships is still a fact worth reporting — and its absence on a device that has
	// them is the thing somebody will be looking for.
	if addr := a.resolver.Addr(); addr.IsValid() {
		status.Resolver = addr.String()
		status.ResolverSuffixes = a.zones.Suffixes()
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
			//
			// From the client rather than from the handle. A handle exists for as long as
			// the membership is supervised, which includes the whole time a revoked or
			// misconfigured device is having every connection refused — reporting that as
			// connected would make status agree with the device's own hopes rather than
			// with the control plane.
			ms.Connected, ms.ConnectedSince = handle.client.Connected()
			ms.AppliedStateVersion = handle.client.AppliedVersion()
			ms.LastError = handle.applier.lastError()
			ms.TunnelUp, ms.TunnelKind = handle.applier.tunnelStatus()
			if handle.applier.reconciler != nil {
				ms.ListenPort = handle.applier.reconciler.Status().ListenPort
			}
			ms.Relay = relayStatus(handle.relay)
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

	// relay is nil for the same reasons, and additionally when this deployment offers none.
	relay *relaylink.Link

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

	// Before converging, not after. The reconciler is about to ask the link for an endpoint
	// for every relayed peer in this same state, and a link that had not yet been told which
	// relay it serves would refuse all of them.
	if a.relay != nil {
		a.relay.SetRelays(state.Relays())
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

	// Keep whatever port the interface settled on, so the next start asks for the same one.
	// A failure here costs port stability, not connectivity, so it is logged rather than
	// reported as an unapplied component.
	if a.reconciler != nil {
		if port := a.reconciler.Status().ListenPort; port != 0 {
			if err := a.agent.setListenPort(a.membershipID, port); err != nil {
				a.log.Warn("could not record the interface's listen port",
					"port", port, "error", err)
			}
		}
	}

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
