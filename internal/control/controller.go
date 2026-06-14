// Package control composes the engine, enforcement, and filtering layers into the operations the
// web server exposes: scan the LAN, then block, throttle, pause, or filter individual devices. It
// owns the spoofing session so that all network state is restored when the controller is closed.
package control

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"sort"
	"sync"
	"time"

	"github.com/yusufornek/lemonet/internal/enforce"
	"github.com/yusufornek/lemonet/internal/engine"
	"github.com/yusufornek/lemonet/internal/filter"
	"github.com/yusufornek/lemonet/internal/filter/rules"
)

// DeviceView is the device state the UI renders: discovery facts plus current policy.
type DeviceView struct {
	IP              string        `json:"ip"`
	IPv6            []string      `json:"ipv6,omitempty"`
	MAC             string        `json:"mac"`
	Vendor          string        `json:"vendor"`
	Hostname        string        `json:"hostname"`
	Kind            string        `json:"kind"`
	Blocked         bool          `json:"blocked"`
	Paused          bool          `json:"paused"`
	UpKbps          int           `json:"upKbps"`
	DownKbps        int           `json:"downKbps"`
	ExpiresAt       string        `json:"expiresAt,omitempty"`
	HasUndo         bool          `json:"hasUndo"`
	Filtered        bool          `json:"filtered"`
	Protected       bool          `json:"protected"`
	ProtectedReason string        `json:"protectedReason,omitempty"`
	Packs           []string      `json:"packs"`
	CustomRules     []rules.Rule  `json:"customRules"`
	Toggles         rules.Toggles `json:"toggles"`
}

type Diagnostics struct {
	Interface        string            `json:"interface"`
	SelfIP           string            `json:"selfIP"`
	GatewayIP        string            `json:"gatewayIP"`
	IPv6Gateway      string            `json:"ipv6Gateway,omitempty"`
	Devices          int               `json:"devices"`
	ManagedDevices   int               `json:"managedDevices"`
	FilteredDevices  int               `json:"filteredDevices"`
	ProtectedDevices int               `json:"protectedDevices"`
	Packs            int               `json:"packs"`
	LoadedPacks      int               `json:"loadedPacks"`
	Relay            engine.RelayStats `json:"relay"`
}

type Preflight struct {
	Ready  bool             `json:"ready"`
	Checks []PreflightCheck `json:"checks"`
}

type PreflightCheck struct {
	ID     string `json:"id"`
	Status string `json:"status"`
	Title  string `json:"title"`
	Detail string `json:"detail"`
}

type ActionPreview struct {
	Action             string                `json:"action"`
	Reason             string                `json:"reason,omitempty"`
	Total              int                   `json:"total"`
	Allowed            int                   `json:"allowed"`
	Protected          int                   `json:"protected"`
	Unknown            int                   `json:"unknown"`
	Unavailable        int                   `json:"unavailable"`
	AlreadyManaged     int                   `json:"alreadyManaged"`
	WillStartSession   bool                  `json:"willStartSession"`
	WillStopSession    bool                  `json:"willStopSession"`
	WillRestoreDevices int                   `json:"willRestoreDevices"`
	Devices            []ActionPreviewDevice `json:"devices"`
}

type ActionPreviewDevice struct {
	IP       string `json:"ip"`
	Status   string `json:"status"`
	Reason   string `json:"reason,omitempty"`
	Managed  bool   `json:"managed"`
	Filtered bool   `json:"filtered"`
	HasUndo  bool   `json:"hasUndo"`
}

type PolicyTemplate struct {
	Version      int           `json:"version"`
	EnabledPacks []string      `json:"enabledPacks"`
	CustomRules  []rules.Rule  `json:"customRules"`
	Toggles      rules.Toggles `json:"toggles"`
}

type policyState struct {
	blocked  bool
	paused   bool
	upKbps   int
	downKbps int
	expires  time.Time
	leaseID  uint64
	restore  enforcementState
}

type enforcementState struct {
	blocked  bool
	paused   bool
	upKbps   int
	downKbps int
}

type policySnapshot struct {
	mac        string
	generation uint64
	hadManaged bool
	managed    policyState
	hadFilter  bool
	filter     rules.DevicePolicy
}

type filterChange struct {
	ip     string
	addr   netip.Addr
	device engine.Device
	policy rules.DevicePolicy
	active bool
}

type filterTarget struct {
	ip     string
	addr   netip.Addr
	device engine.Device
}

type filterApplyResult struct {
	set     []filterChange
	clear   []filterChange
	restore []filterChange
}

type sessionResult struct {
	name string
	err  error
}

type policyFilter interface {
	engine.FlowInspector
	SetPolicy(netip.Addr, rules.DevicePolicy)
	ClearPolicy(netip.Addr)
	ClearAll()
}

type trafficEnforcer interface {
	enforce.Enforcer
	Decide(netip.Addr, engine.Direction, int) (bool, time.Duration)
}

const (
	MaxTemporaryControlDuration = 24 * time.Hour
	maxBulkTargets              = 64
	maxCustomRulesPerDevice     = 128
	policyTemplateVersion       = 1
)

// Controller is the single owner of the live capture handle, the spoofing session, and the
// per-device policy. It is safe for concurrent use by the HTTP handlers.
type Controller struct {
	iface       engine.Interface
	handle      engine.Handle
	relayHandle engine.Handle
	scanner     *engine.Scanner
	spoofer     *engine.Spoofer
	relay       *engine.Relay
	enforcer    trafficEnforcer
	filter      policyFilter
	packMgr     *filter.Manager
	table       *engine.Table
	guard       engine.SessionGuard

	gwIP  net.IP
	gwIP6 net.IP // gateway IPv6 link-local for NDP poisoning; nil when the LAN has no IPv6 router
	gwMAC net.HardwareAddr

	mu          sync.Mutex
	managed     map[string]policyState
	filtered    map[string]rules.DevicePolicy
	undo        map[string]policySnapshot
	generation  map[string]uint64
	timers      map[string]*time.Timer
	nextLease   uint64
	cancel      context.CancelFunc
	sessionDone chan sessionResult
	started     bool
	closed      bool
}

// New opens the interface, resolves the gateway, and prepares the session. It does not start
// spoofing; that begins lazily the first time a device is managed.
func New(iface engine.Interface) (*Controller, error) {
	handle, err := engine.OpenLive(iface.Name)
	if err != nil {
		return nil, err
	}

	table := engine.NewTable()
	enforcer := enforce.NewUserspace()
	packMgr := filter.NewManager()

	c := &Controller{
		iface:      iface,
		handle:     handle,
		scanner:    engine.NewScanner(iface, handle, engine.LoadVendorDB()),
		spoofer:    engine.NewSpoofer(handle, table),
		enforcer:   enforcer,
		filter:     packMgr.Filter(),
		packMgr:    packMgr,
		table:      table,
		guard:      engine.NewSessionGuard(),
		managed:    make(map[string]policyState),
		filtered:   make(map[string]rules.DevicePolicy),
		undo:       make(map[string]policySnapshot),
		generation: make(map[string]uint64),
		timers:     make(map[string]*time.Timer),
	}

	gwIP, err := engine.GatewayIP()
	if err != nil {
		handle.Close()
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	gwMAC, err := c.scanner.ResolveMAC(ctx, gwIP)
	if err != nil {
		handle.Close()
		return nil, fmt.Errorf("control: could not resolve gateway %s: %w", gwIP, err)
	}
	c.gwIP, c.gwMAC = gwIP, gwMAC

	// Best-effort IPv6: learn the router's link-local so we can also poison the device's IPv6
	// default route. If the LAN has no IPv6 router, IPv6 is simply left uncontrolled.
	v6ctx, v6cancel := context.WithTimeout(context.Background(), 2*time.Second)
	if gwLL, err6 := c.scanner.DiscoverRouterLL(v6ctx); err6 == nil {
		c.gwIP6 = gwLL
		log.Printf("control: IPv6 router %s found; IPv6 interception enabled", gwLL)
	} else {
		if gwLL, routeErr := engine.GatewayIPv6LinkLocal(iface.Name); routeErr == nil {
			c.gwIP6 = gwLL
			log.Printf("control: IPv6 router %s found via route table; IPv6 interception enabled", gwLL)
		} else {
			log.Printf("control: no IPv6 router found; IPv6 not intercepted (%v; route fallback: %v)", err6, routeErr)
		}
	}
	v6cancel()

	// The relay reads on its own handle so its capture never competes with the scanner for
	// packets on the shared handle.
	relayHandle, err := engine.OpenLive(iface.Name)
	if err != nil {
		handle.Close()
		return nil, err
	}
	c.relayHandle = relayHandle
	c.relay = engine.NewRelay(relayHandle, iface, gwIP, gwMAC, table, enforcer)
	c.relay.SetInspector(c.filter)
	c.relay.SetIPv6LearnedHook(c.refreshSession)
	return c, nil
}

func (c *Controller) Gateway() (net.IP, net.HardwareAddr) { return c.gwIP, c.gwMAC }

func (c *Controller) Packs() []filter.PackInfo { return c.packMgr.Packs() }

func (c *Controller) Profiles() []PolicyProfile {
	out := make([]PolicyProfile, 0, len(policyProfiles))
	for _, p := range policyProfiles {
		out = append(out, cloneProfile(p))
	}
	return out
}

// RefreshPack forces a re-download of a remote pack's blocklist.
func (c *Controller) RefreshPack(id string) error { return c.packMgr.Refresh(id) }

func errControllerClosed() error {
	return fmt.Errorf("control: controller is closed")
}

func (c *Controller) ensureOpen() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return errControllerClosed()
	}
	return nil
}

func (c *Controller) Diagnostics() Diagnostics {
	c.mu.Lock()
	managed, filtered := len(c.managed), len(c.filtered)
	c.mu.Unlock()

	devices := c.Devices()
	protected := 0
	for _, d := range devices {
		if d.Protected {
			protected++
		}
	}
	packs := c.packMgr.Packs()
	loaded := 0
	for _, p := range packs {
		if p.Loaded {
			loaded++
		}
	}
	out := Diagnostics{
		Interface:        c.iface.Name,
		SelfIP:           c.iface.IP.String(),
		GatewayIP:        c.gwIP.String(),
		Devices:          len(devices),
		ManagedDevices:   managed,
		FilteredDevices:  filtered,
		ProtectedDevices: protected,
		Packs:            len(packs),
		LoadedPacks:      loaded,
		Relay:            c.relay.Stats(),
	}
	if c.gwIP6 != nil {
		out.IPv6Gateway = c.gwIP6.String()
	}
	return out
}

func (c *Controller) Preflight() Preflight {
	checks := []PreflightCheck{
		c.preflightInterface(),
		c.preflightGateway(),
		c.preflightCapture(),
		c.preflightRelay(),
		c.preflightIPv6(),
		c.preflightPacks(),
	}
	ready := true
	for _, check := range checks {
		if check.Status == "fail" {
			ready = false
			break
		}
	}
	return Preflight{Ready: ready, Checks: checks}
}

func (c *Controller) preflightInterface() PreflightCheck {
	if c == nil || c.iface.Name == "" || c.iface.IP == nil || len(c.iface.MAC) == 0 {
		return preflightCheck("interface", "fail", "Network interface", "No usable interface is selected.")
	}
	return preflightCheck("interface", "ok", "Network interface", fmt.Sprintf("%s is selected.", c.iface.Name))
}

func (c *Controller) preflightGateway() PreflightCheck {
	if c == nil || c.gwIP == nil {
		return preflightCheck("gateway", "fail", "Gateway", "No default gateway was resolved.")
	}
	if len(c.gwMAC) == 0 {
		return preflightCheck("gateway", "fail", "Gateway", "The gateway address was found, but its MAC was not resolved.")
	}
	return preflightCheck("gateway", "ok", "Gateway", "The default gateway is reachable.")
}

func (c *Controller) preflightCapture() PreflightCheck {
	if c == nil || c.handle == nil || c.relayHandle == nil {
		return preflightCheck("capture", "fail", "Packet capture", "Capture handles are not both open.")
	}
	return preflightCheck("capture", "ok", "Packet capture", "Scanner and relay capture handles are open.")
}

func (c *Controller) preflightRelay() PreflightCheck {
	if c == nil || c.relay == nil || c.enforcer == nil || c.filter == nil {
		return preflightCheck("relay", "fail", "Relay capture", "The relay, enforcer, or filter is not initialized.")
	}
	return preflightCheck("relay", "ok", "Relay capture", "Userspace relay components are initialized.")
}

func (c *Controller) preflightIPv6() PreflightCheck {
	if c != nil && c.gwIP6 != nil {
		return preflightCheck("ipv6", "warn", "IPv6", "An IPv6 router was discovered; IPv6 interception is best effort.")
	}
	return preflightCheck("ipv6", "warn", "IPv6", "No IPv6 router was discovered; IPv6 control is unavailable if clients use another IPv6 path.")
}

func (c *Controller) preflightPacks() PreflightCheck {
	if c == nil || c.packMgr == nil {
		return preflightCheck("packs", "fail", "Filter packs", "Filter pack metadata is not loaded.")
	}
	packs := c.packMgr.Packs()
	if len(packs) == 0 {
		return preflightCheck("packs", "fail", "Filter packs", "No filter packs are registered.")
	}
	loaded, loading := 0, 0
	for _, pack := range packs {
		if pack.Loaded {
			loaded++
		}
		if pack.Loading {
			loading++
		}
	}
	if loaded == 0 {
		return preflightCheck("packs", "fail", "Filter packs", "No filter packs are loaded.")
	}
	if loading > 0 {
		return preflightCheck("packs", "warn", "Filter packs", fmt.Sprintf("%d of %d packs are loading.", loading, len(packs)))
	}
	return preflightCheck("packs", "ok", "Filter packs", fmt.Sprintf("%d of %d packs are loaded.", loaded, len(packs)))
}

func preflightCheck(id, status, title, detail string) PreflightCheck {
	return PreflightCheck{ID: id, Status: status, Title: title, Detail: detail}
}

func (c *Controller) PreviewAction(ips []string, action string) ActionPreview {
	preview := ActionPreview{Action: action, Total: len(ips)}
	if !previewActionKnown(action) {
		for _, ip := range ips {
			preview.Unavailable++
			preview.Devices = append(preview.Devices, ActionPreviewDevice{IP: ip, Status: "unavailable", Reason: "unknown_action"})
		}
		return preview
	}
	if len(ips) > maxBulkTargets {
		preview.Unavailable = len(ips)
		preview.Reason = "too_many_targets"
		return preview
	}

	c.mu.Lock()
	managed := make(map[string]bool, len(c.managed))
	for ip := range c.managed {
		managed[ip] = true
	}
	filtered := make(map[string]bool, len(c.filtered))
	for ip := range c.filtered {
		filtered[ip] = true
	}
	undo := make(map[string]bool, len(c.undo))
	for ip := range c.undo {
		undo[ip] = true
	}
	started := c.started
	c.mu.Unlock()

	selectedAllowed := make(map[string]bool)
	seen := make(map[string]bool)
	anyManaged := len(managed) > 0 || len(filtered) > 0
	for _, ip := range ips {
		device := ActionPreviewDevice{IP: ip, Managed: managed[ip], Filtered: filtered[ip], HasUndo: undo[ip]}
		if seen[ip] {
			device.Status = "duplicate"
			device.Reason = "already_listed"
			preview.Devices = append(preview.Devices, device)
			continue
		}
		seen[ip] = true
		parsed := net.ParseIP(ip)
		if parsed == nil {
			device.Status = "unknown"
			device.Reason = "invalid_ip"
			preview.Unknown++
		} else if isProtected, reason := c.protection(ip); isProtected {
			device.Status = "protected"
			device.Reason = reason
			preview.Protected++
		} else {
			if c.table == nil {
				device.Status = "unknown"
				device.Reason = "not_scanned"
				preview.Unknown++
			} else if _, ok := c.table.GetByIP(parsed); !ok {
				device.Status = "unknown"
				device.Reason = "not_scanned"
				preview.Unknown++
			} else if action == "undo" && !undo[ip] {
				device.Status = "unavailable"
				device.Reason = "no_undo"
				preview.Unavailable++
			} else {
				device.Status = "allowed"
				preview.Allowed++
				selectedAllowed[ip] = true
				if device.Managed || device.Filtered {
					preview.AlreadyManaged++
				}
				if action == "release" && (device.Managed || device.Filtered) {
					preview.WillRestoreDevices++
				}
			}
		}
		preview.Devices = append(preview.Devices, device)
	}

	if !started && preview.Allowed > 0 && actionStartsSession(action) {
		preview.WillStartSession = true
	}
	if action == "release" && anyManaged && preview.WillRestoreDevices > 0 {
		remaining := false
		for ip := range managed {
			if !selectedAllowed[ip] {
				remaining = true
				break
			}
		}
		if !remaining {
			for ip := range filtered {
				if !selectedAllowed[ip] {
					remaining = true
					break
				}
			}
		}
		preview.WillStopSession = !remaining
	}
	return preview
}

func previewActionKnown(action string) bool {
	switch action {
	case "block", "throttle", "pause", "resume", "release", "filter", "profile", "undo", "rule", "pack", "toggle":
		return true
	default:
		return false
	}
}

func actionStartsSession(action string) bool {
	switch action {
	case "block", "throttle", "pause", "filter", "profile", "rule", "pack", "toggle":
		return true
	default:
		return false
	}
}

// Scan sweeps the subnet and merges the result into the persistent table the relay routes with.
func (c *Controller) Scan(ctx context.Context) ([]DeviceView, error) {
	found, err := c.scanner.Sweep(ctx)
	if err != nil {
		return nil, err
	}
	for _, d := range found {
		c.table.Upsert(d)
	}
	c.table.MergeByIP(c.gwIP, "", "Router / Modem", "")
	log.Printf("scan: discovered %d device(s) on %s", len(found), c.iface.Name)
	return c.Devices(), nil
}

// Devices returns the current table joined with policy state.
func (c *Controller) Devices() []DeviceView {
	c.mu.Lock()
	defer c.mu.Unlock()

	var out []DeviceView
	for _, d := range c.table.List() {
		v := DeviceView{
			IP:       d.IP.String(),
			IPv6:     ipStrings(c.table.V6Addrs(d.MAC)),
			MAC:      d.MAC.String(),
			Vendor:   d.Vendor,
			Hostname: d.Hostname,
			Kind:     d.Kind,
		}
		if p, ok := c.managed[d.IP.String()]; ok {
			v.Blocked, v.Paused, v.UpKbps, v.DownKbps = p.blocked, p.paused, p.upKbps, p.downKbps
			if !p.expires.IsZero() {
				v.ExpiresAt = p.expires.UTC().Format(time.RFC3339)
			}
		}
		if pol, ok := c.filtered[d.IP.String()]; ok {
			v.Filtered = true
			v.Packs = append([]string(nil), pol.EnabledPacks...)
			v.CustomRules = append([]rules.Rule(nil), pol.CustomRules...)
			v.Toggles = pol.Toggles
		}
		_, v.HasUndo = c.undo[d.IP.String()]
		v.Protected, v.ProtectedReason = c.protection(d.IP.String())
		out = append(out, v)
	}
	// Stable order by IP so the list does not reshuffle on every refresh.
	sort.Slice(out, func(i, j int) bool {
		a, _ := netip.ParseAddr(out[i].IP)
		b, _ := netip.ParseAddr(out[j].IP)
		return a.Compare(b) < 0
	})
	return out
}

func ipStrings(ips []net.IP) []string {
	if len(ips) == 0 {
		return nil
	}
	out := make([]string, 0, len(ips))
	for _, ip := range ips {
		out = append(out, ip.String())
	}
	sort.Strings(out)
	return out
}

// StopAll releases every managed device, restores their ARP caches, and stops the spoofing
// session, leaving the capture handle open so the user can scan or manage again.
func (c *Controller) StopAll() error {
	var err error
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.stopSessionLocked(false); err != nil {
		return err
	}
	if c.enforcer != nil {
		err = errors.Join(err, c.enforcer.ClearAll())
	}
	if err != nil {
		return err
	}
	if c.filter != nil {
		c.filter.ClearAll()
	}
	c.stopTimersLocked()
	c.managed = make(map[string]policyState)
	c.filtered = make(map[string]rules.DevicePolicy)
	c.undo = make(map[string]policySnapshot)
	c.generation = make(map[string]uint64)
	return nil
}

// teardown cancels the spoof/relay session (which restores every target's ARP cache) and undoes
// the host redirect suppression. Safe to call when no session is running.
func (c *Controller) teardown() error {
	return c.stopSession(false)
}

func (c *Controller) teardownIfIdle() error {
	return c.stopSession(true)
}

func (c *Controller) stopSession(onlyIfIdle bool) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.stopSessionLocked(onlyIfIdle)
}

func (c *Controller) stopSessionLocked(onlyIfIdle bool) error {
	if onlyIfIdle && (len(c.managed) > 0 || len(c.filtered) > 0) {
		return nil
	}
	cancel := c.cancel
	c.cancel = nil
	sessionDone := c.sessionDone
	c.sessionDone = nil
	c.started = false

	var err error
	if cancel != nil {
		cancel()
		err = errors.Join(err, waitForSessionRestore(sessionDone))
	} else if !onlyIfIdle && c.spoofer != nil && (len(c.managed) > 0 || len(c.filtered) > 0) {
		c.spoofer.Update(c.spoofConfig())
		err = errors.Join(err, c.spoofer.Restore())
	}
	endGuard := !c.started
	if onlyIfIdle {
		endGuard = endGuard && len(c.managed) == 0 && len(c.filtered) == 0
	}
	if endGuard && c.guard != nil {
		return errors.Join(err, c.guard.End())
	}
	return err
}

func waitForSessionRestore(done <-chan sessionResult) error {
	if done == nil {
		return nil
	}
	var err error
	for i := 0; i < 2; i++ {
		result := <-done
		err = errors.Join(err, result.err)
	}
	return err
}

func (c *Controller) Block(ip string) error {
	return c.apply(ip, func(p *policyState) error {
		p.blocked = true
		addr, err := netip.ParseAddr(ip)
		if err != nil {
			return err
		}
		return c.enforcer.Block(addr)
	})
}

func (c *Controller) BlockFor(ip string, duration time.Duration) error {
	return c.applyTemporary(ip, duration, func(p *policyState) {
		p.blocked = true
	}, func(addr netip.Addr) error {
		return c.enforcer.Block(addr)
	})
}

func (c *Controller) Throttle(ip string, upKbps, downKbps int) error {
	return c.apply(ip, func(p *policyState) error {
		p.upKbps, p.downKbps = upKbps, downKbps
		addr, err := netip.ParseAddr(ip)
		if err != nil {
			return err
		}
		return c.enforcer.Throttle(addr, upKbps, downKbps)
	})
}

func (c *Controller) ThrottleFor(ip string, upKbps, downKbps int, duration time.Duration) error {
	if upKbps < 0 || downKbps < 0 {
		return fmt.Errorf("control: throttle rates must be non-negative")
	}
	return c.applyTemporary(ip, duration, func(p *policyState) {
		p.upKbps, p.downKbps = upKbps, downKbps
	}, func(addr netip.Addr) error {
		return c.enforcer.Throttle(addr, upKbps, downKbps)
	})
}

func (c *Controller) Pause(ip string) error {
	return c.apply(ip, func(p *policyState) error {
		p.paused = true
		addr, err := netip.ParseAddr(ip)
		if err != nil {
			return err
		}
		return c.enforcer.Pause(addr)
	})
}

func (c *Controller) Resume(ip string) error {
	return c.apply(ip, func(p *policyState) error {
		p.paused = false
		addr, err := netip.ParseAddr(ip)
		if err != nil {
			return err
		}
		return c.enforcer.Resume(addr)
	})
}

// SetFilter installs a content-filtering policy for a device, managing (spoofing) it so the
// policy can take effect. An empty policy stops filtering the device.
func (c *Controller) SetFilter(ip string, pol rules.DevicePolicy) error {
	change, err := c.prepareFilterChange(ip, pol)
	if err != nil {
		return err
	}
	return c.applyFilterChanges([]filterChange{change})
}

func (c *Controller) prepareFilterChange(ip string, pol rules.DevicePolicy) (filterChange, error) {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return filterChange{}, err
	}
	if protected, reason := c.protection(ip); protected {
		return filterChange{}, fmt.Errorf("control: %s is protected (%s)", ip, reason)
	}
	dev, ok := c.table.GetByIP(net.ParseIP(ip))
	if !ok {
		return filterChange{}, fmt.Errorf("control: device %s must be scanned before it can be filtered", ip)
	}
	return c.makeFilterChange(filterTarget{ip: ip, addr: addr, device: dev}, pol)
}

func (c *Controller) makeFilterChange(target filterTarget, pol rules.DevicePolicy) (filterChange, error) {
	pol, err := c.cleanPolicy(pol)
	if err != nil {
		return filterChange{}, err
	}
	pol.MAC = target.device.MAC.String()

	if len(pol.EnabledPacks) > 0 || len(pol.CustomRules) > 0 {
		pol.EnabledPacks = setPack(pol.EnabledPacks, "encrypted-dns", true)
		pol.EnabledPacks = setPack(pol.EnabledPacks, "vpn", true)
		pol.Toggles.BlockQUIC = true
		pol.Toggles.BlockEncryptedDNS = true
		pol.Toggles.StripECH = true
		pol.Toggles.FirefoxCanary = true
		pol.Toggles.BlockVPNPorts = true
	}

	active := len(pol.EnabledPacks) > 0 || len(pol.CustomRules) > 0 || pol.Toggles != (rules.Toggles{})
	return filterChange{ip: target.ip, addr: target.addr, device: target.device, policy: pol, active: active}, nil
}

func (c *Controller) prepareFilterChanges(updates map[string]rules.DevicePolicy) ([]filterChange, error) {
	ips := make([]string, 0, len(updates))
	for ip := range updates {
		ips = append(ips, ip)
	}
	sort.Strings(ips)
	changes := make([]filterChange, 0, len(ips))
	for _, ip := range ips {
		change, err := c.prepareFilterChange(ip, updates[ip])
		if err != nil {
			return nil, err
		}
		changes = append(changes, change)
	}
	return changes, nil
}

func (c *Controller) applyFilterChanges(changes []filterChange) error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return errControllerClosed()
	}
	result := c.commitFilterChangesLocked(changes)
	c.mu.Unlock()
	return c.finishFilterApply(result)
}

func (c *Controller) commitFilterChangesLocked(changes []filterChange) filterApplyResult {
	var result filterApplyResult
	for _, change := range changes {
		current, hadCurrent := c.filtered[change.ip]
		if change.active {
			if hadCurrent && samePolicy(current, change.policy) {
				continue
			}
			c.recordUndoLocked(change.ip, c.snapshotLocked(change.ip))
			c.filtered[change.ip] = clonePolicy(change.policy)
			c.filter.SetPolicy(change.addr, change.policy)
			result.set = append(result.set, change)
			continue
		}
		if !hadCurrent {
			continue
		}
		c.recordUndoLocked(change.ip, c.snapshotLocked(change.ip))
		delete(c.filtered, change.ip)
		c.filter.ClearPolicy(change.addr)
		result.clear = append(result.clear, change)
		if _, stillManaged := c.managed[change.ip]; !stillManaged {
			result.restore = append(result.restore, change)
		}
	}
	return result
}

func (c *Controller) finishFilterApply(result filterApplyResult) error {
	var restoreErr error
	for _, change := range result.restore {
		restoreErr = errors.Join(restoreErr, c.restoreDeviceIfUnmanaged(change.ip, change.device))
	}

	changed := len(result.set) > 0 || len(result.clear) > 0
	if len(result.set) > 0 {
		c.ensureSessionForActiveTargets()
		return restoreErr
	}
	if changed {
		return errors.Join(restoreErr, c.refreshOrTeardown())
	}
	return restoreErr
}

func (c *Controller) applyFilterMutations(ips []string, mutate func(rules.DevicePolicy) rules.DevicePolicy) error {
	targets, err := c.prepareFilterTargets(ips)
	if err != nil {
		return err
	}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return errControllerClosed()
	}
	changes := make([]filterChange, 0, len(targets))
	for _, target := range targets {
		next := mutate(clonePolicy(c.filtered[target.ip]))
		change, err := c.makeFilterChange(target, next)
		if err != nil {
			c.mu.Unlock()
			return err
		}
		changes = append(changes, change)
	}
	result := c.commitFilterChangesLocked(changes)
	c.mu.Unlock()
	return c.finishFilterApply(result)
}

func (c *Controller) prepareFilterTargets(ips []string) ([]filterTarget, error) {
	if err := c.knownIPs(ips); err != nil {
		return nil, err
	}
	seen := make(map[string]struct{}, len(ips))
	unique := make([]string, 0, len(ips))
	for _, ip := range ips {
		if _, ok := seen[ip]; ok {
			continue
		}
		seen[ip] = struct{}{}
		unique = append(unique, ip)
	}
	sort.Strings(unique)
	targets := make([]filterTarget, 0, len(unique))
	for _, ip := range unique {
		addr, err := netip.ParseAddr(ip)
		if err != nil {
			return nil, err
		}
		dev, ok := c.table.GetByIP(net.ParseIP(ip))
		if !ok {
			return nil, fmt.Errorf("control: device %s must be scanned first", ip)
		}
		targets = append(targets, filterTarget{ip: ip, addr: addr, device: dev})
	}
	return targets, nil
}

// knownIPs verifies every IP has been discovered, so a bulk operation does not partially apply
// before failing on a stale IP.
func (c *Controller) knownIPs(ips []string) error {
	if len(ips) == 0 {
		return fmt.Errorf("control: no devices selected")
	}
	if len(ips) > maxBulkTargets {
		return fmt.Errorf("control: too many devices selected (max %d)", maxBulkTargets)
	}
	for _, ip := range ips {
		parsed := net.ParseIP(ip)
		if parsed == nil {
			return fmt.Errorf("control: invalid device IP %q", ip)
		}
		if protected, reason := c.protection(ip); protected {
			return fmt.Errorf("control: %s is protected (%s)", ip, reason)
		}
		if _, ok := c.table.GetByIP(parsed); !ok {
			return fmt.Errorf("control: device %s must be scanned first", ip)
		}
	}
	return nil
}

// currentPolicy returns a deep copy of a device's stored filter policy so callers can mutate it
// without aliasing controller state.
func (c *Controller) currentPolicy(ip string) rules.DevicePolicy {
	c.mu.Lock()
	defer c.mu.Unlock()
	p := c.filtered[ip]
	return rules.DevicePolicy{
		MAC:          p.MAC,
		EnabledPacks: append([]string(nil), p.EnabledPacks...),
		CustomRules:  append([]rules.Rule(nil), p.CustomRules...),
		Toggles:      p.Toggles,
	}
}

func (c *Controller) ApplyProfile(ips []string, profileID string) error {
	profile, ok := profileByID(profileID)
	if !ok {
		return fmt.Errorf("control: unknown profile %s", profileID)
	}
	if err := c.knownIPs(ips); err != nil {
		return err
	}
	preset, err := c.cleanPolicy(rules.DevicePolicy{
		EnabledPacks: profile.EnabledPacks,
		Toggles:      profile.Toggles,
	})
	if err != nil {
		return err
	}
	if err := c.ensureOpen(); err != nil {
		return err
	}
	for _, id := range preset.EnabledPacks {
		c.ensurePackLoaded(id)
	}
	return c.applyFilterMutations(ips, func(pol rules.DevicePolicy) rules.DevicePolicy {
		pol.EnabledPacks = append([]string(nil), preset.EnabledPacks...)
		pol.Toggles = preset.Toggles
		return pol
	})
}

func (c *Controller) Explain(ip, domain string) (rules.Decision, error) {
	dom := rules.NormalizeDomain(domain)
	if dom == "" {
		return rules.Decision{}, fmt.Errorf("control: invalid domain %q", domain)
	}
	if err := c.knownIPs([]string{ip}); err != nil {
		return rules.Decision{}, err
	}
	return c.packMgr.Explain(c.currentPolicy(ip), dom), nil
}

func (c *Controller) ExportPolicy(ip string) (PolicyTemplate, error) {
	if err := c.knownIPs([]string{ip}); err != nil {
		return PolicyTemplate{}, err
	}
	pol := c.currentPolicy(ip)
	return PolicyTemplate{
		Version:      policyTemplateVersion,
		EnabledPacks: append([]string(nil), pol.EnabledPacks...),
		CustomRules:  append([]rules.Rule(nil), pol.CustomRules...),
		Toggles:      pol.Toggles,
	}, nil
}

func (c *Controller) ImportPolicy(ips []string, template PolicyTemplate) error {
	if template.Version != policyTemplateVersion {
		return fmt.Errorf("control: unsupported policy template version %d", template.Version)
	}
	if err := c.knownIPs(ips); err != nil {
		return err
	}
	pol, err := c.cleanPolicy(rules.DevicePolicy{
		EnabledPacks: template.EnabledPacks,
		CustomRules:  template.CustomRules,
		Toggles:      template.Toggles,
	})
	if err != nil {
		return err
	}
	if err := c.ensureOpen(); err != nil {
		return err
	}
	for _, id := range pol.EnabledPacks {
		c.ensurePackLoaded(id)
	}
	updates := make(map[string]rules.DevicePolicy, len(ips))
	for _, ip := range ips {
		updates[ip] = pol
	}
	changes, err := c.prepareFilterChanges(updates)
	if err != nil {
		return err
	}
	return c.applyFilterChanges(changes)
}

func (c *Controller) Undo(ips []string) error {
	if err := c.knownIPs(ips); err != nil {
		return err
	}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return errControllerClosed()
	}
	for _, ip := range ips {
		if _, ok := c.undo[ip]; !ok {
			c.mu.Unlock()
			return fmt.Errorf("control: no undo available for %s", ip)
		}
	}
	c.mu.Unlock()
	for _, ip := range ips {
		if err := c.undoOne(ip); err != nil {
			return err
		}
	}
	return nil
}

func (c *Controller) validateTemporary(ip string, duration time.Duration) (netip.Addr, error) {
	if duration <= 0 {
		return netip.Addr{}, fmt.Errorf("control: duration must be positive")
	}
	if duration > MaxTemporaryControlDuration {
		return netip.Addr{}, fmt.Errorf("control: duration exceeds %s", MaxTemporaryControlDuration)
	}
	if err := c.knownIPs([]string{ip}); err != nil {
		return netip.Addr{}, err
	}
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return netip.Addr{}, err
	}
	return addr, nil
}

func (c *Controller) applyTemporary(ip string, duration time.Duration, mutate func(*policyState), applyEnforcer func(netip.Addr) error) error {
	addr, err := c.validateTemporary(ip, duration)
	if err != nil {
		return err
	}

	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return errControllerClosed()
	}
	snap := c.snapshotLocked(ip)
	p := c.managed[ip]
	restore := p.enforcement()
	c.nextLease++
	leaseID := c.nextLease
	mutate(&p)
	p.expires = time.Now().Add(duration).UTC()
	p.leaseID = leaseID
	p.restore = restore
	if err := applyEnforcer(addr); err != nil {
		c.mu.Unlock()
		return err
	}
	c.managed[ip] = p
	c.recordUndoLocked(ip, snap)
	c.setTimerLocked(ip, leaseID, duration)
	c.mu.Unlock()

	c.ensureSessionForActiveTargets()
	return nil
}

// AddRule adds (or replaces) a custom domain rule on each of the given devices.
func (c *Controller) AddRule(ips []string, action, domain string) error {
	dom := rules.NormalizeDomain(domain)
	if dom == "" {
		return fmt.Errorf("control: invalid domain %q", domain)
	}
	if err := c.knownIPs(ips); err != nil {
		return err
	}
	act, err := parseAction(action)
	if err != nil {
		return err
	}
	return c.applyFilterMutations(ips, func(pol rules.DevicePolicy) rules.DevicePolicy {
		pol.CustomRules = upsertRule(pol.CustomRules, rules.Rule{Action: act, Domain: dom})
		return pol
	})
}

// RemoveRule removes a custom domain rule from each of the given devices.
func (c *Controller) RemoveRule(ips []string, action, domain string) error {
	dom := rules.NormalizeDomain(domain)
	if dom == "" {
		return fmt.Errorf("control: invalid domain %q", domain)
	}
	if err := c.knownIPs(ips); err != nil {
		return err
	}
	act, err := parseAction(action)
	if err != nil {
		return err
	}
	return c.applyFilterMutations(ips, func(pol rules.DevicePolicy) rules.DevicePolicy {
		pol.CustomRules = removeRule(pol.CustomRules, act, dom)
		return pol
	})
}

// SetPack enables or disables one category pack on each of the given devices.
func (c *Controller) SetPack(ips []string, packID string, enabled bool) error {
	if !c.packMgr.HasPack(packID) {
		return fmt.Errorf("control: unknown pack %s", packID)
	}
	if err := c.knownIPs(ips); err != nil {
		return err
	}
	if err := c.ensureOpen(); err != nil {
		return err
	}
	// A remote pack downloads its list the first time it is enabled. Do it once, in the background,
	// so the request returns immediately; the pack reports Loading then Loaded via /api/packs.
	if enabled {
		c.ensurePackLoaded(packID)
	}
	return c.applyFilterMutations(ips, func(pol rules.DevicePolicy) rules.DevicePolicy {
		pol.EnabledPacks = setPack(pol.EnabledPacks, packID, enabled)
		return pol
	})
}

func (c *Controller) ensurePackLoaded(packID string) {
	go func() {
		if err := c.packMgr.EnsureLoaded(packID); err != nil {
			log.Printf("control: blocklist %s load failed: %v", packID, err)
		}
	}()
}

func (c *Controller) setTimerLocked(ip string, leaseID uint64, duration time.Duration) {
	if c.timers == nil {
		c.timers = make(map[string]*time.Timer)
	}
	c.stopTimerLocked(ip)
	c.timers[ip] = time.AfterFunc(duration, func() {
		if err := c.expireLease(ip, leaseID); err != nil {
			log.Printf("control: temporary policy release for %s failed: %v", ip, err)
		}
	})
}

func (c *Controller) expireLease(ip string, leaseID uint64) error {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return err
	}

	var restore enforcementState
	var restoreDevice *engine.Device
	c.mu.Lock()
	p, ok := c.managed[ip]
	if c.closed || !ok || p.leaseID != leaseID {
		c.mu.Unlock()
		return nil
	}
	restore = p.restore
	if err := c.applyEnforcementSnapshot(addr, restore); err != nil {
		c.mu.Unlock()
		return err
	}
	if restore.empty() {
		delete(c.managed, ip)
	} else {
		p = restore.policy()
		c.managed[ip] = p
	}
	c.stopTimerLocked(ip)
	delete(c.undo, ip)
	c.bumpGenerationLocked(ip)
	_, stillFiltered := c.filtered[ip]
	if restore.empty() && !stillFiltered {
		if d, ok := c.table.GetByIP(net.ParseIP(ip)); ok {
			device := d
			restoreDevice = &device
		}
	}
	c.mu.Unlock()

	if restoreDevice != nil {
		if err := c.restoreDeviceIfUnmanaged(ip, *restoreDevice); err != nil {
			return err
		}
	}
	return c.refreshOrTeardown()
}

func (c *Controller) stopTimerLocked(ip string) {
	if c.timers == nil {
		return
	}
	if t := c.timers[ip]; t != nil {
		t.Stop()
	}
	delete(c.timers, ip)
}

func (c *Controller) stopTimersLocked() {
	for ip, t := range c.timers {
		if t != nil {
			t.Stop()
		}
		delete(c.timers, ip)
	}
}

func (c *Controller) recordUndoLocked(ip string, snap policySnapshot) {
	if c.undo == nil {
		c.undo = make(map[string]policySnapshot)
	}
	snap.generation = c.bumpGenerationLocked(ip)
	c.undo[ip] = snap
}

func (c *Controller) bumpGenerationLocked(ip string) uint64 {
	if c.generation == nil {
		c.generation = make(map[string]uint64)
	}
	c.generation[ip]++
	return c.generation[ip]
}

func (c *Controller) snapshotLocked(ip string) policySnapshot {
	var snap policySnapshot
	if d, ok := c.table.GetByIP(net.ParseIP(ip)); ok {
		snap.mac = d.MAC.String()
	}
	if p, ok := c.managed[ip]; ok {
		snap.hadManaged = true
		p.expires = time.Time{}
		p.leaseID = 0
		p.restore = enforcementState{}
		snap.managed = p
	}
	if pol, ok := c.filtered[ip]; ok {
		snap.hadFilter = true
		snap.filter = clonePolicy(pol)
	}
	return snap
}

func clonePolicy(p rules.DevicePolicy) rules.DevicePolicy {
	return rules.DevicePolicy{
		MAC:          p.MAC,
		EnabledPacks: append([]string(nil), p.EnabledPacks...),
		CustomRules:  append([]rules.Rule(nil), p.CustomRules...),
		Toggles:      p.Toggles,
	}
}

func samePolicy(a, b rules.DevicePolicy) bool {
	if a.MAC != b.MAC || a.Toggles != b.Toggles || len(a.EnabledPacks) != len(b.EnabledPacks) || len(a.CustomRules) != len(b.CustomRules) {
		return false
	}
	for i := range a.EnabledPacks {
		if a.EnabledPacks[i] != b.EnabledPacks[i] {
			return false
		}
	}
	for i := range a.CustomRules {
		if a.CustomRules[i] != b.CustomRules[i] {
			return false
		}
	}
	return true
}

func (p policyState) enforcement() enforcementState {
	return enforcementState{
		blocked:  p.blocked,
		paused:   p.paused,
		upKbps:   p.upKbps,
		downKbps: p.downKbps,
	}
}

func (s enforcementState) empty() bool {
	return !s.blocked && !s.paused && s.upKbps == 0 && s.downKbps == 0
}

func (s enforcementState) policy() policyState {
	return policyState{
		blocked:  s.blocked,
		paused:   s.paused,
		upKbps:   s.upKbps,
		downKbps: s.downKbps,
	}
}

func (c *Controller) applyEnforcementSnapshot(addr netip.Addr, s enforcementState) error {
	if s.empty() {
		return c.enforcer.Clear(addr)
	}
	if err := c.enforcer.Clear(addr); err != nil {
		return err
	}
	if s.blocked {
		if err := c.enforcer.Block(addr); err != nil {
			return err
		}
	}
	if s.paused {
		if err := c.enforcer.Pause(addr); err != nil {
			return err
		}
	}
	if s.upKbps > 0 || s.downKbps > 0 {
		if err := c.enforcer.Throttle(addr, s.upKbps, s.downKbps); err != nil {
			return err
		}
	}
	return nil
}

func (c *Controller) undoOne(ip string) error {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return err
	}
	dev, ok := c.table.GetByIP(net.ParseIP(ip))
	if !ok {
		return fmt.Errorf("control: unknown device %s", ip)
	}

	c.mu.Lock()
	snap, ok := c.undo[ip]
	if !ok {
		c.mu.Unlock()
		return fmt.Errorf("control: no undo available for %s", ip)
	}
	if snap.mac != "" && snap.mac != dev.MAC.String() {
		c.mu.Unlock()
		return fmt.Errorf("control: device %s changed since the undo snapshot was recorded", ip)
	}
	if snap.generation != c.generation[ip] {
		c.mu.Unlock()
		return fmt.Errorf("control: undo snapshot for %s is stale", ip)
	}

	if err := c.applyEnforcementSnapshot(addr, snap.managed.enforcement()); err != nil {
		c.mu.Unlock()
		return err
	}
	if snap.hadFilter {
		c.filter.SetPolicy(addr, snap.filter)
	} else {
		c.filter.ClearPolicy(addr)
	}

	c.stopTimerLocked(ip)
	delete(c.undo, ip)
	if snap.hadManaged {
		c.managed[ip] = snap.managed
	} else {
		delete(c.managed, ip)
	}
	if snap.hadFilter {
		c.filtered[ip] = clonePolicy(snap.filter)
	} else {
		delete(c.filtered, ip)
	}
	c.bumpGenerationLocked(ip)
	c.mu.Unlock()

	if snap.hadManaged || snap.hadFilter {
		c.ensureSessionForActiveTargets()
		return nil
	}
	if err := c.restoreDeviceIfUnmanaged(ip, dev); err != nil {
		return err
	}
	return c.refreshOrTeardown()
}

// SetToggle flips a single transport toggle on each device, leaving its other toggles intact so a
// multi-device change does not clobber per-device state.
func (c *Controller) SetToggle(ips []string, key string, enabled bool) error {
	if err := c.knownIPs(ips); err != nil {
		return err
	}
	if _, err := applyToggle(rules.Toggles{}, key, enabled); err != nil {
		return err
	}
	return c.applyFilterMutations(ips, func(pol rules.DevicePolicy) rules.DevicePolicy {
		toggles, _ := applyToggle(pol.Toggles, key, enabled)
		pol.Toggles = toggles
		return pol
	})
}

func applyToggle(t rules.Toggles, key string, on bool) (rules.Toggles, error) {
	switch key {
	case "blockQuic":
		t.BlockQUIC = on
	case "blockVpnPorts":
		t.BlockVPNPorts = on
	case "blockEncryptedDns":
		t.BlockEncryptedDNS = on
	case "stripEch":
		t.StripECH = on
	case "firefoxCanary":
		t.FirefoxCanary = on
	default:
		return t, fmt.Errorf("control: unknown toggle %s", key)
	}
	return t, nil
}

func parseAction(action string) (rules.Action, error) {
	switch rules.Action(action) {
	case rules.Block:
		return rules.Block, nil
	case rules.Allow:
		return rules.Allow, nil
	default:
		return "", fmt.Errorf("control: unknown rule action %s", action)
	}
}

func upsertRule(rs []rules.Rule, r rules.Rule) []rules.Rule {
	var out []rules.Rule
	for _, x := range rs {
		if rules.NormalizeDomain(x.Domain) == r.Domain {
			continue // one rule per domain; the new action replaces the old
		}
		out = append(out, x)
	}
	return append(out, r)
}

func removeRule(rs []rules.Rule, act rules.Action, dom string) []rules.Rule {
	var out []rules.Rule
	for _, x := range rs {
		if x.Action == act && rules.NormalizeDomain(x.Domain) == dom {
			continue
		}
		out = append(out, x)
	}
	return out
}

func setPack(packs []string, id string, enabled bool) []string {
	var out []string
	for _, p := range packs {
		if p != id {
			out = append(out, p)
		}
	}
	if enabled {
		out = append(out, id)
	}
	return out
}

func (c *Controller) cleanPolicy(pol rules.DevicePolicy) (rules.DevicePolicy, error) {
	var clean rules.DevicePolicy
	for _, id := range pol.EnabledPacks {
		if !c.packMgr.HasPack(id) {
			return rules.DevicePolicy{}, fmt.Errorf("control: unknown pack %s", id)
		}
		clean.EnabledPacks = setPack(clean.EnabledPacks, id, true)
	}
	for _, r := range pol.CustomRules {
		act, err := parseAction(string(r.Action))
		if err != nil {
			return rules.DevicePolicy{}, err
		}
		dom := rules.NormalizeDomain(r.Domain)
		if dom == "" {
			return rules.DevicePolicy{}, fmt.Errorf("control: invalid domain %q", r.Domain)
		}
		clean.CustomRules = upsertRule(clean.CustomRules, rules.Rule{Action: act, Domain: dom})
	}
	if len(clean.CustomRules) > maxCustomRulesPerDevice {
		return rules.DevicePolicy{}, fmt.Errorf("control: too many custom rules (max %d)", maxCustomRulesPerDevice)
	}
	clean.Toggles = pol.Toggles
	return clean, nil
}

// Release stops managing a device entirely: it clears enforcement and filtering, then restores
// the device's ARP cache so its connectivity recovers at once.
func (c *Controller) Release(ip string) error {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return err
	}
	if protected, reason := c.protection(ip); protected {
		return fmt.Errorf("control: %s is protected (%s)", ip, reason)
	}
	dev, ok := c.table.GetByIP(net.ParseIP(ip))
	if !ok {
		return fmt.Errorf("control: unknown device %s", ip)
	}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return errControllerClosed()
	}
	_, hadManaged := c.managed[ip]
	_, hadFiltered := c.filtered[ip]
	if !hadManaged && !hadFiltered {
		c.mu.Unlock()
		return nil
	}
	c.spoofer.Update(c.spoofConfig())
	if err := c.spoofer.RestoreDevice(dev); err != nil {
		c.mu.Unlock()
		return err
	}
	if err := c.enforcer.Clear(addr); err != nil {
		c.mu.Unlock()
		return err
	}
	c.filter.ClearPolicy(addr)
	c.recordUndoLocked(ip, c.snapshotLocked(ip))
	c.stopTimerLocked(ip)
	delete(c.managed, ip)
	delete(c.filtered, ip)
	c.mu.Unlock()

	return c.refreshOrTeardown()
}

// apply mutates a device's enforcement policy, ensures the session is running, and updates its
// target set. A device must have been discovered (so we know its MAC) before it can be managed.
func (c *Controller) apply(ip string, mutate func(*policyState) error) error {
	if protected, reason := c.protection(ip); protected {
		return fmt.Errorf("control: %s is protected (%s)", ip, reason)
	}
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return err
	}
	dev, ok := c.table.GetByIP(net.ParseIP(ip))
	if !ok {
		return fmt.Errorf("control: device %s must be scanned before it can be managed", ip)
	}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return errControllerClosed()
	}
	snap := c.snapshotLocked(ip)
	_, hadManaged := c.managed[ip]
	p := c.managed[ip]
	if err := mutate(&p); err != nil {
		c.mu.Unlock()
		return err
	}
	p.expires = time.Time{}
	p.leaseID = 0
	p.restore = enforcementState{}
	if p.enforcement().empty() {
		if !hadManaged {
			c.mu.Unlock()
			_ = c.enforcer.Clear(addr)
			return nil
		}
		if err := c.enforcer.Clear(addr); err != nil {
			c.mu.Unlock()
			return err
		}
		c.recordUndoLocked(ip, snap)
		c.stopTimerLocked(ip)
		delete(c.managed, ip)
		_, stillFiltered := c.filtered[ip]
		c.mu.Unlock()
		if !stillFiltered {
			if err := c.restoreDeviceIfUnmanaged(ip, dev); err != nil {
				return err
			}
		}
		return c.refreshOrTeardown()
	}
	c.recordUndoLocked(ip, snap)
	c.stopTimerLocked(ip)
	c.managed[ip] = p
	c.mu.Unlock()

	c.ensureSessionForActiveTargets()
	return nil
}

func (c *Controller) protection(ip string) (bool, string) {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false, ""
	}
	if parsed.Equal(c.iface.IP) {
		return true, "host"
	}
	if parsed.Equal(c.gwIP) {
		return true, "gateway"
	}
	return false, ""
}

// ensureSession starts the spoof and relay goroutines on first use.
func (c *Controller) ensureSession() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.started {
		return
	}
	c.started = true

	// Suppress host ICMP redirects for the session so the kernel cannot steer the target back to
	// the real gateway around our relay. Restored in StopAll/Close.
	if c.guard != nil {
		if err := c.guard.Begin(); err != nil {
			log.Printf("control: could not adjust redirects: %v", err)
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan sessionResult, 2)
	c.cancel = cancel
	c.sessionDone = done
	cfg := c.spoofConfig()
	spoofer := c.spoofer
	relay := c.relay
	go func() {
		err := runSessionTask("spoofer", func() error { return spoofer.Start(ctx, cfg) }, spoofer.Restore)
		if err != nil {
			cancel()
		}
		done <- sessionResult{name: "spoofer", err: err}
	}()
	go func() {
		err := runSessionTask("relay", func() error { return relay.Run(ctx) }, nil)
		if err != nil {
			cancel()
		}
		done <- sessionResult{name: "relay", err: err}
	}()
}

// runSessionTask recovers a session goroutine panic and runs the supplied cleanup before returning
// the error to the session owner.
func runSessionTask(name string, fn func() error, cleanup func() error) (err error) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("control: %s goroutine recovered from panic: %v", name, r)
			if cleanup != nil {
				err = errors.Join(err, cleanup())
			}
			err = errors.Join(err, fmt.Errorf("control: %s goroutine recovered from panic", name))
		}
	}()
	return fn()
}

// refreshSession pushes the current managed set into the running spoofer.
func (c *Controller) refreshSession() {
	c.mu.Lock()
	running := c.started
	cfg := c.spoofConfig()
	c.mu.Unlock()
	if running {
		c.spoofer.UpdateNow(cfg)
	}
}

func (c *Controller) ensureSessionForActiveTargets() {
	c.mu.Lock()
	active := len(c.managed) > 0 || len(c.filtered) > 0
	running := c.started
	c.mu.Unlock()
	if !active {
		return
	}
	if running {
		c.refreshSession()
		return
	}
	c.ensureSession()
}

func (c *Controller) refreshOrTeardown() error {
	c.mu.Lock()
	active := len(c.managed) > 0 || len(c.filtered) > 0
	c.mu.Unlock()
	if active {
		c.refreshSession()
		return nil
	}
	return c.teardownIfIdle()
}

func (c *Controller) restoreDeviceIfUnmanaged(ip string, dev engine.Device) error {
	c.mu.Lock()
	_, managed := c.managed[ip]
	_, filtered := c.filtered[ip]
	cfg := c.spoofConfig()
	c.mu.Unlock()
	if !managed && !filtered {
		c.spoofer.Update(cfg)
		return c.spoofer.RestoreDevice(dev)
	}
	return nil
}

// spoofConfig builds a full-duplex poison config for every device under enforcement or filtering.
// Callers hold c.mu.
func (c *Controller) spoofConfig() engine.SpoofConfig {
	seen := make(map[string]struct{})
	var targets []engine.Device
	add := func(ip string) {
		if _, dup := seen[ip]; dup {
			return
		}
		if d, ok := c.table.GetByIP(net.ParseIP(ip)); ok {
			seen[ip] = struct{}{}
			targets = append(targets, d)
		}
	}
	for ip := range c.managed {
		add(ip)
	}
	for ip := range c.filtered {
		add(ip)
	}
	return engine.SpoofConfig{
		Targets:    targets,
		GatewayIP:  c.gwIP,
		GatewayIP6: c.gwIP6,
		GatewayMAC: c.gwMAC,
		SelfMAC:    c.iface.MAC,
		FullDuplex: true,
	}
}

// Close cancels the session (which restores every target's ARP cache), clears all policy, and
// closes the capture handle. It is safe to call even if no session ever started.
func (c *Controller) Close() error {
	var err error
	c.mu.Lock()
	c.closed = true
	c.stopTimersLocked()
	c.mu.Unlock()
	err = errors.Join(err, c.teardown())
	if c.enforcer != nil {
		err = errors.Join(err, c.enforcer.ClearAll())
	}
	c.mu.Lock()
	c.managed = make(map[string]policyState)
	c.filtered = make(map[string]rules.DevicePolicy)
	c.undo = make(map[string]policySnapshot)
	c.generation = make(map[string]uint64)
	c.mu.Unlock()
	c.filter.ClearAll()
	if c.relayHandle != nil {
		err = errors.Join(err, c.relayHandle.Close())
	}
	if c.handle != nil {
		err = errors.Join(err, c.handle.Close())
	}
	return err
}
