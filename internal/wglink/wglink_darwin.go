//go:build darwin

package wglink

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/ipc"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/meshpnet/meshp/internal/wgplan"
)

// macOS has no WireGuard in the kernel, so every interface here is a userspace device that
// this process owns: wireguard-go moves the packets, and wgctrl configures it over the same
// UAPI socket it would use for a userspace device on Linux.
//
// That last part is ADR-0015's bet paying off. "Set this private key, these peers, these
// allowed IPs" is written once and runs unchanged here, because wgctrl speaks netlink to a
// kernel device and the UAPI socket to a userspace one behind one interface. What is
// genuinely different on this platform is everything *around* the tunnel — how an interface
// comes into existence, how it gets an address, how a route is pointed at it — and that is
// what this file is.

// The socket directory every WireGuard tool on this platform agrees on. wg-quick(8) puts
// its sockets and name files here, so `wg show` finds a meshp interface without being told
// where to look.
const wireguardRunDir = "/var/run/wireguard"

// commandTimeout bounds one ifconfig or route invocation.
//
// These run on the reconcile path. Both are small, synchronous programs that either work or
// fail in milliseconds, so a bound this generous only ever fires when something is very
// wrong — and when it does, the agent reports a failed operation rather than stopping
// converging on everything else.
const commandTimeout = 10 * time.Second

// darwinLink manages userspace WireGuard interfaces on macOS.
//
// The devices are held in this process. That is the load-bearing difference from Linux,
// where an interface is kernel state that outlives the agent: here, meshpd exiting takes
// every tunnel with it. Reconciliation rebuilds them on the next start, so the consequence
// is a gap in connectivity across a restart rather than a wrong configuration — but it is
// why Observe treats a name file with no live socket behind it as an interface that does
// not exist, rather than as one to adopt.
type darwinLink struct {
	// mu serialises operations, for the reason the Linux implementation gives: one Link is
	// shared by every membership on the host, each with its own reconcile timer, and
	// wgctrl's client makes no promise about concurrent use. It also guards devices.
	mu sync.Mutex

	wg *wgctrl.Client

	// devices maps the name meshp asked for to what is actually running. The map is this
	// process's memory of what it created; the name file below is the same fact written
	// down where another tool can read it.
	devices map[string]*runningDevice

	// runDir is where the name files live. A field rather than the constant everywhere so
	// a test can exercise the stale-file handling without writing into the directory the
	// rest of the system's WireGuard tools are using.
	runDir string
}

// runningDevice is one wireguard-go tunnel this process started.
type runningDevice struct {
	dev *device.Device

	// uapi accepts the configuration connections wgctrl makes. Closed before the device,
	// so nothing is half-configuring a tunnel that is going away.
	uapi net.Listener

	// real is the interface the kernel gave us — utun4, utun9 — which is not the name
	// meshp asked for and cannot be. See nameFile.
	real string
}

// New returns a Link for this host.
func New() (Link, error) {
	// Created rather than assumed. wg-quick creates it too, and a first run on a fresh
	// machine would otherwise fail inside wireguard-go with a message about a socket path
	// rather than about a missing directory.
	if err := os.MkdirAll(wireguardRunDir, 0o700); err != nil {
		return nil, fmt.Errorf("wglink: preparing %s: %w", wireguardRunDir, err)
	}
	wg, err := wgctrl.New()
	if err != nil {
		return nil, fmt.Errorf("wglink: opening the WireGuard control socket: %w", err)
	}
	return &darwinLink{wg: wg, devices: map[string]*runningDevice{}, runDir: wireguardRunDir}, nil
}

func (l *darwinLink) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	var errs []error
	for name, running := range l.devices {
		errs = append(errs, l.stop(name, running))
	}
	l.devices = map[string]*runningDevice{}
	errs = append(errs, l.wg.Close())
	return errors.Join(errs...)
}

// Kind reports what is behind an interface.
//
// Always userspace where there is anything at all: macOS has no kernel WireGuard, which is
// the whole reason this file exists. ADR-0015 requires this be reported rather than
// inferred, because a silent fallback turns "why is this host a tenth the speed of that
// one" into an unanswerable question.
func (l *darwinLink) Kind(name string) (Kind, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if _, err := l.wg.Device(name); err != nil {
		return KindUnknown, fmt.Errorf("wglink: reading %s: %w", name, err)
	}
	return KindUserspace, nil
}

// Observe reports what the interface currently holds.
func (l *darwinLink) Observe(name string) (wgplan.Observed, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	real, ok, err := l.resolve(name)
	if err != nil || !ok {
		// Not an error when it is simply absent: that is what the planner needs in order
		// to decide to create it.
		return wgplan.Observed{}, err
	}

	iface, err := net.InterfaceByName(real)
	if err != nil {
		return wgplan.Observed{}, fmt.Errorf("wglink: reading %s (%s): %w", name, real, err)
	}

	obs := wgplan.Observed{
		Exists: true,
		Up:     iface.Flags&net.FlagUp != 0,
		MTU:    iface.MTU,
	}

	dev, err := l.wg.Device(name)
	if err != nil {
		return wgplan.Observed{}, fmt.Errorf("wglink: %s is not a WireGuard interface: %w", name, err)
	}
	obs.ListenPort = dev.ListenPort
	if dev.PrivateKey != (wgtypes.Key{}) {
		obs.PrivateKey = wgplan.Key(dev.PrivateKey.String())
	}
	for _, peer := range dev.Peers {
		obs.Peers = append(obs.Peers, peerFromDevice(peer))
	}

	if obs.Addresses, err = interfaceAddresses(iface); err != nil {
		return wgplan.Observed{}, err
	}
	if obs.Routes, err = interfaceRoutes(iface.Index); err != nil {
		return wgplan.Observed{}, err
	}
	return obs, nil
}

// Apply carries out one operation.
func (l *darwinLink) Apply(name string, op wgplan.Op) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	switch op.Kind {
	case wgplan.CreateDevice:
		return l.createDevice(name, op.Device.MTU)
	case wgplan.DestroyDevice:
		return l.destroyDevice(name)
	case wgplan.SetDevice:
		return l.setDevice(name, op.Device)
	case wgplan.SetPeer:
		return l.setPeer(name, op.Peer)
	case wgplan.RemovePeer:
		return l.removePeer(name, op.Peer)
	case wgplan.AddAddress:
		return l.address(name, op.Prefix, true)
	case wgplan.RemoveAddress:
		return l.address(name, op.Prefix, false)
	case wgplan.AddRoute:
		return l.route(name, op.Prefix, true)
	case wgplan.RemoveRoute:
		return l.route(name, op.Prefix, false)
	case wgplan.BringUp:
		return l.bringUp(name)
	default:
		return fmt.Errorf("wglink: unknown operation %s", op.Kind)
	}
}

// createDevice starts a userspace tunnel and publishes its UAPI socket.
func (l *darwinLink) createDevice(name string, mtu int) error {
	if _, running := l.devices[name]; running {
		return nil
	}
	if mtu <= 0 {
		mtu = device.DefaultMTU
	}

	// "utun" rather than the name meshp asked for. macOS names these devices itself, in
	// sequence, and will not take a name of ours — so the interface is utun4 while meshp
	// calls it meshp0, and the mapping has to be written down. See nameFile.
	tunnel, err := tun.CreateTUN("utun", mtu)
	if err != nil {
		return fmt.Errorf("wglink: creating a utun device for %s: %w", name, err)
	}
	real, err := tunnel.Name()
	if err != nil {
		_ = tunnel.Close()
		return fmt.Errorf("wglink: reading the name of the device created for %s: %w", name, err)
	}

	dev := device.NewDevice(tunnel, conn.NewDefaultBind(), &device.Logger{
		Verbosef: device.DiscardLogf,
		// Errors only. wireguard-go's verbose logging is per packet at times, and this
		// runs as a daemon: what is worth keeping is what went wrong.
		Errorf: device.DiscardLogf,
	})
	if err := dev.Up(); err != nil {
		dev.Close()
		return fmt.Errorf("wglink: starting the device for %s: %w", name, err)
	}

	// Named for what meshp calls the interface, not for the utun behind it. `wg show` then
	// lists "meshp0" and agrees with the rest of the product, which is worth more than
	// matching wg-quick's choice of the kernel's name — and the name file below is what
	// bridges to `ifconfig` for anybody cross-referencing.
	socket, err := ipc.UAPIOpen(name)
	if err != nil {
		dev.Close()
		return fmt.Errorf("wglink: opening the control socket for %s: %w", name, err)
	}
	listener, err := ipc.UAPIListen(name, socket)
	if err != nil {
		dev.Close()
		return fmt.Errorf("wglink: listening on the control socket for %s: %w", name, err)
	}

	go func() {
		for {
			c, err := listener.Accept()
			if err != nil {
				// The listener was closed, which is how this goroutine ends.
				return
			}
			go dev.IpcHandle(c)
		}
	}()

	if err := os.WriteFile(l.nameFile(name), []byte(real+"\n"), 0o600); err != nil {
		_ = listener.Close()
		dev.Close()
		return fmt.Errorf("wglink: recording the interface name for %s: %w", name, err)
	}

	l.devices[name] = &runningDevice{dev: dev, uapi: listener, real: real}
	return nil
}

// destroyDevice stops the tunnel and takes the interface with it.
func (l *darwinLink) destroyDevice(name string) error {
	running, ok := l.devices[name]
	if !ok {
		// Nothing of ours is running under that name. Removing a stale name file is still
		// worth doing: it is what stops the next Observe reporting an interface that is
		// not there.
		_ = os.Remove(l.nameFile(name))
		return nil
	}
	delete(l.devices, name)
	return l.stop(name, running)
}

// stop closes one device. Not locked: every caller holds the lock already.
func (l *darwinLink) stop(name string, running *runningDevice) error {
	// The listener first, so nothing is half-configuring a tunnel that is going away.
	err := running.uapi.Close()
	running.dev.Close()
	if rmErr := os.Remove(l.nameFile(name)); rmErr != nil && !os.IsNotExist(rmErr) {
		err = errors.Join(err, rmErr)
	}
	if err != nil {
		return fmt.Errorf("wglink: stopping %s: %w", name, err)
	}
	return nil
}

// setDevice sets the private key, listen port and MTU.
func (l *darwinLink) setDevice(name string, dev wgplan.Device) error {
	key, err := wgtypes.ParseKey(string(dev.PrivateKey))
	if err != nil {
		return fmt.Errorf("wglink: the private key for %s is not a WireGuard key: %w", name, err)
	}
	port := dev.ListenPort
	cfg := wgtypes.Config{PrivateKey: &key, ListenPort: &port}
	if err := l.wg.ConfigureDevice(name, cfg); err != nil {
		return fmt.Errorf("wglink: configuring %s: %w", name, err)
	}
	if dev.MTU > 0 {
		return l.setMTU(name, dev.MTU)
	}
	return nil
}

func (l *darwinLink) setMTU(name string, mtu int) error {
	real, ok, err := l.resolve(name)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("wglink: setting the MTU of %s: no such interface", name)
	}
	return run("/sbin/ifconfig", real, "mtu", strconv.Itoa(mtu))
}

func (l *darwinLink) bringUp(name string) error {
	real, ok, err := l.resolve(name)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("wglink: bringing up %s: no such interface", name)
	}
	return run("/sbin/ifconfig", real, "up")
}

func (l *darwinLink) setPeer(name string, peer wgplan.Peer) error {
	cfg, err := peerConfig(peer)
	if err != nil {
		return err
	}
	if err := l.wg.ConfigureDevice(name, wgtypes.Config{Peers: []wgtypes.PeerConfig{cfg}}); err != nil {
		return fmt.Errorf("wglink: setting a peer on %s: %w", name, err)
	}
	return nil
}

func (l *darwinLink) removePeer(name string, peer wgplan.Peer) error {
	key, err := wgtypes.ParseKey(string(peer.PublicKey))
	if err != nil {
		return fmt.Errorf("wglink: %q is not a WireGuard key: %w", peer.PublicKey, err)
	}
	cfg := wgtypes.Config{Peers: []wgtypes.PeerConfig{{PublicKey: key, Remove: true}}}
	if err := l.wg.ConfigureDevice(name, cfg); err != nil {
		return fmt.Errorf("wglink: removing a peer from %s: %w", name, err)
	}
	return nil
}

// address puts an address on the interface, or takes one off.
//
// A utun is a point-to-point device, so an IPv4 address is given with itself as the
// destination: `inet 100.90.0.7 100.90.0.7`. Without the second address ifconfig takes the
// prefix's broadcast address as the peer, and the interface ends up routing to something
// nobody is.
func (l *darwinLink) address(name string, prefix netip.Prefix, add bool) error {
	real, ok, err := l.resolve(name)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("wglink: addressing %s: no such interface", name)
	}

	addr := prefix.Addr()
	family := "inet"
	if addr.Is6() {
		family = "inet6"
	}
	action := "alias"
	if !add {
		action = "-alias"
	}

	if addr.Is4() {
		if add {
			return run("/sbin/ifconfig", real, family, addr.String(), addr.String(),
				"netmask", ipv4Netmask(prefix.Bits()), action)
		}
		return run("/sbin/ifconfig", real, family, addr.String(), action)
	}
	if add {
		return run("/sbin/ifconfig", real, family, prefix.String(), action)
	}
	return run("/sbin/ifconfig", real, family, addr.String(), action)
}

// route points a prefix at the interface, or withdraws one.
//
// Written with route(8) rather than by hand over PF_ROUTE, while Observe reads the table
// through golang.org/x/net/route. The asymmetry is deliberate: reading drives every
// reconcile and has to be exact and structured, so it is worth a library; writing is a
// discrete action taken once, whose failure is reported and acted on, and hand-marshalling
// sockaddrs to save one exec is not a trade this needs to make.
func (l *darwinLink) route(name string, prefix netip.Prefix, add bool) error {
	real, ok, err := l.resolve(name)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("wglink: routing to %s: no such interface", name)
	}

	family := "-inet"
	if prefix.Addr().Is6() {
		family = "-inet6"
	}
	action := "add"
	if !add {
		action = "delete"
	}
	// -n so route does not try to resolve anything: this runs while the tunnel that
	// resolution might depend on is being built.
	return run("/sbin/route", "-n", action, family, prefix.String(), "-interface", real)
}

// resolve maps the name meshp uses to the interface macOS gave us.
//
// Three answers, and the third is why this is not just a map lookup. A name file with no
// live interface behind it is what meshpd leaves after being killed: the tunnel died with
// the process and the file outlived it. Reporting that as an existing interface would have
// the planner configure something that is not there; removing the file and reporting
// absence has it rebuild, which is what should happen.
func (l *darwinLink) resolve(name string) (string, bool, error) {
	if running, ok := l.devices[name]; ok {
		return running.real, true, nil
	}

	raw, err := os.ReadFile(l.nameFile(name))
	if os.IsNotExist(err) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("wglink: reading the interface name for %s: %w", name, err)
	}
	real := string(trimNewline(raw))
	if real == "" {
		_ = os.Remove(l.nameFile(name))
		return "", false, nil
	}
	if !interfaceExists(real) {
		// Left behind by a process that is gone. Tidied rather than reported, because
		// there is nothing an operator would do about it that this cannot do itself.
		_ = os.Remove(l.nameFile(name))
		return "", false, nil
	}
	return real, true, nil
}

// interfaceExists reports whether the kernel still has an interface by this name.
//
// A predicate rather than an error check at the call site, because the answer there is not
// "something went wrong": a name file whose interface is gone is the expected state after
// meshpd was killed, and the only thing to do about it is to tidy up and rebuild.
func interfaceExists(name string) bool {
	_, err := net.InterfaceByName(name)
	return err == nil
}

// nameFile is where the mapping from meshp's name to the kernel's is written down.
//
// The same convention wg-quick(8) uses on this platform, so anybody cross-referencing
// `wg show` against `ifconfig` has the answer in the place they would look for it.
func (l *darwinLink) nameFile(name string) string {
	dir := l.runDir
	if dir == "" {
		dir = wireguardRunDir
	}
	return filepath.Join(dir, name+".name")
}

// interfaceAddresses lists the interface's own addresses as host prefixes.
func interfaceAddresses(iface *net.Interface) ([]netip.Prefix, error) {
	addrs, err := iface.Addrs()
	if err != nil {
		return nil, fmt.Errorf("wglink: reading the addresses of %s: %w", iface.Name, err)
	}
	var out []netip.Prefix
	for _, raw := range addrs {
		ipnet, ok := raw.(*net.IPNet)
		if !ok {
			continue
		}
		addr, ok := netip.AddrFromSlice(ipnet.IP)
		if !ok {
			continue
		}
		addr = addr.Unmap()
		// Link-local addresses are the kernel's, not ours. macOS gives every utun an
		// fe80:: address of its own, and reporting it would have the planner withdraw an
		// address it never installed.
		if addr.IsLinkLocalUnicast() {
			continue
		}
		ones, _ := ipnet.Mask.Size()
		out = append(out, netip.PrefixFrom(addr, ones))
	}
	return out, nil
}

// run executes one system command, bounded, and reports what it said when it fails.
//
// The output matters. `route: writing to routing socket: File exists` is the whole
// diagnosis, and an error that reported only the exit status would throw it away.
func run(path string, args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), commandTimeout)
	defer cancel()

	out, err := exec.CommandContext(ctx, path, args...).CombinedOutput()
	if err != nil {
		if len(out) > 0 {
			return fmt.Errorf("wglink: %s %v: %w: %s", filepath.Base(path), args, err, trimNewline(out))
		}
		return fmt.Errorf("wglink: %s %v: %w", filepath.Base(path), args, err)
	}
	return nil
}

func trimNewline(b []byte) []byte {
	for len(b) > 0 && (b[len(b)-1] == '\n' || b[len(b)-1] == '\r' || b[len(b)-1] == ' ') {
		b = b[:len(b)-1]
	}
	return b
}

// ipv4Netmask renders a prefix length the way ifconfig wants it.
func ipv4Netmask(bits int) string {
	mask := net.CIDRMask(bits, 32)
	return fmt.Sprintf("0x%02x%02x%02x%02x", mask[0], mask[1], mask[2], mask[3])
}
