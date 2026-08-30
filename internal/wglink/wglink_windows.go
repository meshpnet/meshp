//go:build windows

package wglink

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/ipc"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"

	"github.com/meshpnet/meshp/internal/wgplan"
)

// Windows has no WireGuard the way Linux does, so every interface here is a userspace device
// this process owns: wireguard-go moves the packets over a WinTun adapter, and wgctrl
// configures it over the same UAPI the other platforms use (ADR-0028).
//
// ADR-0015's bet holds here as it did on macOS. "Set this private key, these peers, these
// allowed IPs" is written once and runs unchanged, because wgctrl speaks the UAPI to a
// userspace device whatever the operating system underneath. What differs is everything
// *around* the tunnel, and that is what this file is.
//
// Two differences from the macOS implementation are worth knowing before reading it.
//
// **The adapter takes the name meshp asks for.** macOS names its own devices in sequence and
// will not take one of ours, which is why that file keeps a name file mapping meshp0 to
// utun4. WinTun accepts a name, so there is no mapping and no file: `meshp0` is `meshp0`
// everywhere.
//
// **Addresses and routes go through the IP Helper API, not a command.** macOS shells out to
// ifconfig and route(8) and reads the routing table back over PF_ROUTE, because reading it
// with netstat(1) would mean parsing abbreviated output. Windows has the same hazard in a
// worse form — netsh's output is localised, so parsing it would work in English and fail in
// German — so nothing here shells out at all.

// windowsLink manages userspace WireGuard interfaces on Windows.
//
// The devices are held in this process, which is the same load-bearing difference macOS has
// from Linux: meshpd exiting takes every tunnel with it, and reconciliation rebuilds them on
// the next start. The consequence is a gap in connectivity across a restart rather than a
// wrong configuration.
type windowsLink struct {
	// mu serialises operations. One Link is shared by every membership on the host, each
	// with its own reconcile timer, and wgctrl's client makes no promise about concurrent
	// use. It also guards devices.
	mu sync.Mutex

	wg *wgctrl.Client

	// devices is what this process has running, by the name meshp gave it.
	devices map[string]*windowsDevice
}

// windowsDevice is one wireguard-go tunnel this process started.
type windowsDevice struct {
	dev *device.Device

	// uapi accepts the configuration connections wgctrl makes. Closed before the device, so
	// nothing is half-configuring a tunnel that is going away.
	uapi net.Listener

	// luid identifies the adapter to the IP Helper API. It is how addresses, routes and the
	// MTU are set: an interface index would do for reading, but the calls that write take a
	// LUID and it is stable for the adapter's life.
	luid winipcfg.LUID
}

// New returns a Link for this host.
func New() (Link, error) {
	wg, err := wgctrl.New()
	if err != nil {
		return nil, fmt.Errorf("wglink: opening the WireGuard control socket: %w", err)
	}
	return &windowsLink{wg: wg, devices: map[string]*windowsDevice{}}, nil
}

func (l *windowsLink) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	var errs []error
	for name, running := range l.devices {
		errs = append(errs, l.stop(name, running))
	}
	l.devices = map[string]*windowsDevice{}
	errs = append(errs, l.wg.Close())
	return errors.Join(errs...)
}

// Kind reports what is behind an interface.
//
// Always userspace where there is anything at all. Windows does have an in-kernel WireGuard —
// WireGuardNT, which the WireGuard for Windows client installs — and meshp does not use it:
// what this file creates is a WinTun adapter driven by wireguard-go in this process. ADR-0015
// requires the distinction be reported rather than inferred, because a silent fallback turns
// "why is this host slower than that one" into an unanswerable question.
func (l *windowsLink) Kind(name string) (Kind, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if _, err := l.wg.Device(name); err != nil {
		return KindUnknown, fmt.Errorf("wglink: reading %s: %w", name, err)
	}
	return KindUserspace, nil
}

// Observe reports what the interface currently holds.
func (l *windowsLink) Observe(name string) (wgplan.Observed, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	running, ok := l.devices[name]
	if !ok {
		// Nothing of ours under that name, which is what the planner needs in order to
		// decide to create it. An adapter left by something else is deliberately not
		// adopted: it is not one this process can configure, because the UAPI pipe that
		// configures it belongs to whoever made it.
		return wgplan.Observed{}, nil
	}

	iface, err := net.InterfaceByName(name)
	if err != nil {
		// Ours in memory and gone from the system. Treated as absent rather than as an
		// error, so the reconciler rebuilds it — the same answer macOS gives for a name
		// file with no live interface behind it, and the ordinary state after something
		// removed the adapter underneath us.
		delete(l.devices, name)
		_ = l.stop(name, running)
		return wgplan.Observed{}, nil
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

	if obs.Addresses, err = adapterAddresses(running.luid); err != nil {
		return wgplan.Observed{}, err
	}
	if obs.Routes, err = adapterRoutes(running.luid); err != nil {
		return wgplan.Observed{}, err
	}
	return obs, nil
}

// Apply carries out one operation.
func (l *windowsLink) Apply(name string, op wgplan.Op) error {
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

// createDevice starts a userspace tunnel and publishes its UAPI pipe.
func (l *windowsLink) createDevice(name string, mtu int) error {
	if _, running := l.devices[name]; running {
		return nil
	}
	if mtu <= 0 {
		mtu = device.DefaultMTU
	}

	// The name meshp asked for, which WinTun accepts. This is the simplification macOS does
	// not get: there is no second name to record and nothing to go stale.
	tunnel, err := tun.CreateTUN(name, mtu)
	if err != nil {
		return fmt.Errorf("wglink: creating a WinTun adapter for %s: %w", name, wintunHint(err))
	}
	native, ok := tunnel.(*tun.NativeTun)
	if !ok {
		_ = tunnel.Close()
		return fmt.Errorf("wglink: the adapter created for %s is not a WinTun device", name)
	}
	luid := winipcfg.LUID(native.LUID())

	dev := device.NewDevice(tunnel, conn.NewDefaultBind(), &device.Logger{
		// Errors only, for the reason macOS gives: wireguard-go's verbose logging is per
		// packet at times, and this runs as a daemon.
		Verbosef: device.DiscardLogf,
		Errorf:   device.DiscardLogf,
	})
	if err := dev.Up(); err != nil {
		dev.Close()
		return fmt.Errorf("wglink: starting the device for %s: %w", name, err)
	}

	// Named for what meshp calls the interface, so `wg show` agrees with the rest of the
	// product. On this platform the UAPI is a named pipe under
	// \\.\pipe\ProtectedPrefix\Administrators\WireGuard\, and wireguard-go creates it owned
	// by LocalSystem — which is what wgctrl insists on before it will dial one.
	//
	// Handing an object to a security identity you are not is refused by default, even to an
	// administrator: Windows answers ERROR_INVALID_OWNER, which prints as "this security ID
	// may not be assigned as the owner of this object" and names neither the identity nor the
	// remedy. A service running as LocalSystem never meets it, because it already is the
	// owner it is assigning. Anybody running meshpd from an elevated prompt does, and so does
	// CI.
	//
	// SeRestorePrivilege is the documented way through, and an administrator already holds
	// it — it is disabled in the token rather than absent. So it is enabled for exactly the
	// call that needs it and put back immediately, rather than held for the life of a daemon:
	// while enabled it also permits writing files regardless of their permissions, which is
	// far more than publishing a pipe needs.
	restore, err := withRestorePrivilege()
	if err != nil {
		dev.Close()
		return fmt.Errorf("wglink: preparing to publish the control pipe for %s: %w", name, err)
	}
	listener, err := ipc.UAPIListen(name)
	restore()
	if err != nil {
		dev.Close()
		return fmt.Errorf("wglink: listening on the control pipe for %s: %w", name, err)
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

	l.devices[name] = &windowsDevice{dev: dev, uapi: listener, luid: luid}
	return nil
}

// destroyDevice stops the tunnel and takes the adapter with it.
func (l *windowsLink) destroyDevice(name string) error {
	running, ok := l.devices[name]
	if !ok {
		return nil
	}
	delete(l.devices, name)
	return l.stop(name, running)
}

// stop closes one device. Not locked: every caller holds the lock already.
func (l *windowsLink) stop(name string, running *windowsDevice) error {
	// The pipe first, so nothing is half-configuring a tunnel that is going away.
	err := running.uapi.Close()
	running.dev.Close()
	if err != nil {
		return fmt.Errorf("wglink: stopping %s: %w", name, err)
	}
	return nil
}

// setDevice sets the private key, listen port and MTU.
func (l *windowsLink) setDevice(name string, dev wgplan.Device) error {
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

// setMTU sets the MTU on both address families.
//
// Both, and separately, because Windows keeps one IP interface per family and setting the
// MTU on one says nothing about the other. A device with an IPv4 MTU of 1420 and an IPv6 MTU
// of 1500 fragments in one direction only, which is the kind of fault that looks like a bad
// network rather than a bad configuration.
func (l *windowsLink) setMTU(name string, mtu int) error {
	running, ok := l.devices[name]
	if !ok {
		return fmt.Errorf("wglink: setting the MTU of %s: no such interface", name)
	}
	for _, family := range []winipcfg.AddressFamily{windowsIPv4, windowsIPv6} {
		row, err := running.luid.IPInterface(family)
		if err != nil {
			// A family this adapter does not carry is not a failure. An IPv6-disabled host
			// has no IPv6 interface to set an MTU on, and refusing the whole operation
			// would leave the IPv4 one unset too.
			continue
		}
		row.NLMTU = uint32(mtu)
		if err := row.Set(); err != nil {
			return fmt.Errorf("wglink: setting the MTU of %s: %w", name, err)
		}
	}
	return nil
}

// bringUp is a no-op that checks rather than acts.
//
// A WinTun adapter is up from the moment it exists — there is no administrative down state to
// lift, as there is on Linux and macOS. Reporting success without looking would make this the
// one operation that cannot fail, so it asks the system whether the interface is really there.
func (l *windowsLink) bringUp(name string) error {
	if _, err := net.InterfaceByName(name); err != nil {
		return fmt.Errorf("wglink: bringing up %s: %w", name, err)
	}
	return nil
}

func (l *windowsLink) setPeer(name string, peer wgplan.Peer) error {
	cfg, err := peerConfig(peer)
	if err != nil {
		return err
	}
	if err := l.wg.ConfigureDevice(name, wgtypes.Config{Peers: []wgtypes.PeerConfig{cfg}}); err != nil {
		return fmt.Errorf("wglink: setting a peer on %s: %w", name, err)
	}
	return nil
}

func (l *windowsLink) removePeer(name string, peer wgplan.Peer) error {
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

// address puts an address on the adapter, or takes one off.
//
// Idempotent in both directions, because the reconciler calls this on every pass: an address
// that is already there and one that is already gone are both what was asked for.
func (l *windowsLink) address(name string, prefix netip.Prefix, add bool) error {
	running, ok := l.devices[name]
	if !ok {
		return fmt.Errorf("wglink: addressing %s: no such interface", name)
	}
	if add {
		err := running.luid.AddIPAddress(prefix)
		if errors.Is(err, windowsObjectExists) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("wglink: adding %s to %s: %w", prefix, name, err)
		}
		return nil
	}
	err := running.luid.DeleteIPAddress(prefix)
	if errors.Is(err, windowsNotFound) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("wglink: removing %s from %s: %w", prefix, name, err)
	}
	return nil
}

// route points a prefix at the adapter, or stops pointing it.
//
// The next hop is the unspecified address, which is how a route through a point-to-point
// interface is expressed here: there is no gateway on the other side of a tunnel to name.
func (l *windowsLink) route(name string, prefix netip.Prefix, add bool) error {
	running, ok := l.devices[name]
	if !ok {
		return fmt.Errorf("wglink: routing %s: no such interface", name)
	}
	nextHop := netip.IPv4Unspecified()
	if prefix.Addr().Is6() {
		nextHop = netip.IPv6Unspecified()
	}

	if add {
		err := running.luid.AddRoute(prefix, nextHop, 0)
		if errors.Is(err, windowsObjectExists) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("wglink: routing %s to %s: %w", prefix, name, err)
		}
		return nil
	}
	err := running.luid.DeleteRoute(prefix, nextHop)
	if errors.Is(err, windowsNotFound) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("wglink: withdrawing the route for %s from %s: %w", prefix, name, err)
	}
	return nil
}

// adapterAddresses reports the addresses on one adapter.
//
// Read from the IP Helper API rather than from net.Interface.Addrs, so that what Observe
// reports and what Apply writes are the same view of the same table. Two sources would drift
// exactly where it matters — an address the reconciler thinks it added and cannot see.
func adapterAddresses(luid winipcfg.LUID) ([]netip.Prefix, error) {
	rows, err := winipcfg.GetUnicastIPAddressTable(windowsUnspecified)
	if err != nil {
		return nil, fmt.Errorf("wglink: reading this host's addresses: %w", err)
	}
	var out []netip.Prefix
	for _, row := range rows {
		if row.InterfaceLUID != luid {
			continue
		}
		addr := row.Address.Addr()
		if !addr.IsValid() || addr.IsLinkLocalUnicast() {
			// Link-local addresses are the operating system's, not meshp's. Reporting them
			// would have the reconciler withdraw them on every pass.
			continue
		}
		out = append(out, netip.PrefixFrom(addr.Unmap(), int(row.OnLinkPrefixLength)))
	}
	return out, nil
}

// adapterRoutes reports the routes pointed at one adapter.
func adapterRoutes(luid winipcfg.LUID) ([]netip.Prefix, error) {
	rows, err := winipcfg.GetIPForwardTable2(windowsUnspecified)
	if err != nil {
		return nil, fmt.Errorf("wglink: reading this host's routes: %w", err)
	}
	var out []netip.Prefix
	for _, row := range rows {
		if row.InterfaceLUID != luid {
			continue
		}
		prefix := row.DestinationPrefix.Prefix()
		if !prefix.IsValid() {
			continue
		}
		out = append(out, prefix.Masked())
	}
	return out, nil
}

// The address families the IP Helper API takes, and the two error codes this file treats as
// success. Named here rather than inline because winipcfg spells them as raw Windows
// constants, and a reader should not have to know that AF_UNSPEC is 0 to follow the code.
const (
	windowsUnspecified = winipcfg.AddressFamily(windows.AF_UNSPEC)
	windowsIPv4        = winipcfg.AddressFamily(windows.AF_INET)
	windowsIPv6        = winipcfg.AddressFamily(windows.AF_INET6)
)

// windowsObjectExists and windowsNotFound are what the IP Helper API returns for "that is
// already true".
//
// Both are success here, because every writer in this file runs on the reconcile path: an
// address that is already on the adapter and a route that is already gone are both the state
// that was asked for. Treating them as failures would make a converged interface report an
// error once a minute.
var (
	windowsObjectExists = windows.ERROR_OBJECT_ALREADY_EXISTS
	windowsNotFound     = windows.ERROR_NOT_FOUND
)

// wintunHint explains the failure that will happen to whoever tries this first.
//
// wintun.dll is not part of Windows. It ships beside meshpd.exe (ADR-0028), and a binary
// moved without it fails here with a message about a module rather than about a missing
// file — and Windows looks for it beside the executable rather than in the working
// directory, so `go run` never finds it however the repository is laid out.
func wintunHint(err error) error {
	if err == nil {
		return nil
	}
	if !strings.Contains(err.Error(), "wintun.dll") {
		return err
	}
	return fmt.Errorf("%w (wintun.dll has to sit beside meshpd.exe; Windows looks for it "+
		"next to the executable, not in the working directory, so `go run` never finds it)", err)
}

// withRestorePrivilege enables SeRestorePrivilege and returns the undo.
//
// Enabled rather than assumed present, and put back rather than left on. An administrator's
// token carries this privilege disabled; a LocalSystem service's carries it enabled already,
// in which case this is a pair of no-ops that still return a working undo.
//
// A failure to enable is not a failure here. The privilege may genuinely be absent — a
// service account can be denied it by policy — and the honest place to find that out is the
// call that needed it, whose error names the pipe and the owner. Returning an error from
// this function instead would replace a specific diagnosis with a vague one.
func withRestorePrivilege() (func(), error) {
	var token windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(),
		windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY, &token); err != nil {
		return func() {}, fmt.Errorf("opening this process's token: %w", err)
	}

	var luid windows.LUID
	if err := windows.LookupPrivilegeValue(nil,
		windows.StringToUTF16Ptr("SeRestorePrivilege"), &luid); err != nil {
		_ = token.Close()
		return func() {}, fmt.Errorf("looking up SeRestorePrivilege: %w", err)
	}

	enable := windows.Tokenprivileges{PrivilegeCount: 1}
	enable.Privileges[0] = windows.LUIDAndAttributes{Luid: luid, Attributes: windows.SE_PRIVILEGE_ENABLED}
	// The error is deliberately not checked here, and neither is ERROR_NOT_ALL_ASSIGNED:
	// this call succeeds while assigning nothing when the privilege is not held, and the
	// caller finds that out from the pipe rather than from a second-guess here.
	_ = windows.AdjustTokenPrivileges(token, false, &enable, 0, nil, nil)

	return func() {
		var disable windows.Tokenprivileges
		disable.PrivilegeCount = 1
		disable.Privileges[0] = windows.LUIDAndAttributes{Luid: luid}
		_ = windows.AdjustTokenPrivileges(token, false, &disable, 0, nil, nil)
		_ = token.Close()
	}, nil
}
