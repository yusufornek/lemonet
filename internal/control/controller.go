// Package control composes the engine, enforcement, and filtering layers into the operations the
// web server exposes: scan the LAN, then block, throttle, pause, or filter individual devices. It
// owns the spoofing session so that all network state is restored when the controller is closed.
package control

import (
	"context"
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
	IP          string        `json:"ip"`
	MAC         string        `json:"mac"`
	Vendor      string        `json:"vendor"`
	Hostname    string        `json:"hostname"`
	Kind        string        `json:"kind"`
	Blocked     bool          `json:"blocked"`
	Paused      bool          `json:"paused"`
	UpKbps      int           `json:"upKbps"`
	DownKbps    int           `json:"downKbps"`
	Filtered    bool          `json:"filtered"`
	Packs       []string      `json:"packs"`
	CustomRules []rules.Rule  `json:"customRules"`
	Toggles     rules.Toggles `json:"toggles"`
}

type policyState struct {
	blocked  bool
	paused   bool
	upKbps   int
	downKbps int
}

// Controller is the single owner of the live capture handle, the spoofing session, and the
// per-device policy. It is safe for concurrent use by the HTTP handlers.
type Controller struct {
	iface       engine.Interface
	handle      engine.Handle
	relayHandle engine.Handle
	scanner     *engine.Scanner
	spoofer     *engine.Spoofer
	relay       *engine.Relay
	enforcer    *enforce.Userspace
	filter      *filter.Filter
	packs       []filter.PackInfo
	table       *engine.Table
	guard       engine.SessionGuard

	gwIP  net.IP
	gwIP6 net.IP // gateway IPv6 link-local for NDP poisoning; nil when the LAN has no IPv6 router
	gwMAC net.HardwareAddr

	mu       sync.Mutex
	managed  map[string]policyState
	filtered map[string]rules.DevicePolicy
	cancel   context.CancelFunc
	started  bool
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
	rulesEngine, packs := filter.DefaultEngine()
	flt := filter.New(rulesEngine)

	c := &Controller{
		iface:    iface,
		handle:   handle,
		scanner:  engine.NewScanner(iface, handle, engine.LoadVendorDB()),
		spoofer:  engine.NewSpoofer(handle),
		enforcer: enforcer,
		filter:   flt,
		packs:    packs,
		table:    table,
		guard:    engine.NewSessionGuard(),
		managed:  make(map[string]policyState),
		filtered: make(map[string]rules.DevicePolicy),
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
		log.Printf("control: no IPv6 router found; IPv6 not intercepted (%v)", err6)
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
	c.relay = engine.NewRelay(relayHandle, iface, gwMAC, table, enforcer)
	c.relay.SetInspector(flt)
	return c, nil
}

func (c *Controller) Gateway() (net.IP, net.HardwareAddr) { return c.gwIP, c.gwMAC }

func (c *Controller) Packs() []filter.PackInfo { return c.packs }

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
			MAC:      d.MAC.String(),
			Vendor:   d.Vendor,
			Hostname: d.Hostname,
			Kind:     d.Kind,
		}
		if p, ok := c.managed[d.IP.String()]; ok {
			v.Blocked, v.Paused, v.UpKbps, v.DownKbps = p.blocked, p.paused, p.upKbps, p.downKbps
		}
		if pol, ok := c.filtered[d.IP.String()]; ok {
			v.Filtered = true
			v.Packs = pol.EnabledPacks
			v.CustomRules = pol.CustomRules
			v.Toggles = pol.Toggles
		}
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

// StopAll releases every managed device, restores their ARP caches, and stops the spoofing
// session, leaving the capture handle open so the user can scan or manage again.
func (c *Controller) StopAll() error {
	c.mu.Lock()
	c.managed = make(map[string]policyState)
	c.filtered = make(map[string]rules.DevicePolicy)
	c.mu.Unlock()
	c.teardown()
	_ = c.enforcer.ClearAll()
	c.filter.ClearAll()
	return nil
}

// teardown cancels the spoof/relay session (which restores every target's ARP cache) and undoes
// the host redirect suppression. Safe to call when no session is running.
func (c *Controller) teardown() {
	c.mu.Lock()
	cancel := c.cancel
	c.cancel = nil
	c.started = false
	c.mu.Unlock()
	if cancel != nil {
		cancel()
		time.Sleep(300 * time.Millisecond) // let the spoofer send its restore frames
	}
	_ = c.guard.End()
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
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return err
	}
	dev, ok := c.table.GetByIP(net.ParseIP(ip))
	if !ok {
		return fmt.Errorf("control: device %s must be scanned before it can be filtered", ip)
	}

	// Domain filtering is ineffective against QUIC (social and video apps lean on UDP/443), so any
	// active pack or custom rule also forces QUIC blocking, pushing traffic onto TCP where the SNI
	// and DNS layers can act.
	if len(pol.EnabledPacks) > 0 || len(pol.CustomRules) > 0 {
		pol.Toggles.BlockQUIC = true
	}

	active := len(pol.EnabledPacks) > 0 || len(pol.CustomRules) > 0 || pol.Toggles != (rules.Toggles{})
	if active {
		c.filter.SetPolicy(addr, pol)
		c.mu.Lock()
		c.filtered[ip] = pol
		c.mu.Unlock()
		c.ensureSession()
		c.refreshSession()
		return nil
	}

	// Inactive: stop filtering this device. Do not start a session for an empty policy.
	c.filter.ClearPolicy(addr)
	c.mu.Lock()
	delete(c.filtered, ip)
	_, stillManaged := c.managed[ip]
	anyManaged := len(c.managed) > 0 || len(c.filtered) > 0
	c.mu.Unlock()

	if !stillManaged {
		c.spoofer.RestoreDevice(dev) // recover the device's connectivity immediately
	}
	if anyManaged {
		c.refreshSession()
	} else {
		c.teardown()
	}
	return nil
}

// knownIPs verifies every IP has been discovered, so a bulk operation does not partially apply
// before failing on a stale IP.
func (c *Controller) knownIPs(ips []string) error {
	for _, ip := range ips {
		if _, ok := c.table.GetByIP(net.ParseIP(ip)); !ok {
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

// AddRule adds (or replaces) a custom domain rule on each of the given devices.
func (c *Controller) AddRule(ips []string, action, domain string) error {
	dom := rules.NormalizeDomain(domain)
	if dom == "" {
		return fmt.Errorf("control: invalid domain %q", domain)
	}
	if err := c.knownIPs(ips); err != nil {
		return err
	}
	act := rules.Block
	if action == string(rules.Allow) {
		act = rules.Allow
	}
	for _, ip := range ips {
		pol := c.currentPolicy(ip)
		pol.CustomRules = upsertRule(pol.CustomRules, rules.Rule{Action: act, Domain: dom})
		if err := c.SetFilter(ip, pol); err != nil {
			return err
		}
	}
	return nil
}

// RemoveRule removes a custom domain rule from each of the given devices.
func (c *Controller) RemoveRule(ips []string, action, domain string) error {
	dom := rules.NormalizeDomain(domain)
	if err := c.knownIPs(ips); err != nil {
		return err
	}
	act := rules.Block
	if action == string(rules.Allow) {
		act = rules.Allow
	}
	for _, ip := range ips {
		pol := c.currentPolicy(ip)
		pol.CustomRules = removeRule(pol.CustomRules, act, dom)
		if err := c.SetFilter(ip, pol); err != nil {
			return err
		}
	}
	return nil
}

// SetPack enables or disables one category pack on each of the given devices.
func (c *Controller) SetPack(ips []string, packID string, enabled bool) error {
	if err := c.knownIPs(ips); err != nil {
		return err
	}
	for _, ip := range ips {
		pol := c.currentPolicy(ip)
		pol.EnabledPacks = setPack(pol.EnabledPacks, packID, enabled)
		if err := c.SetFilter(ip, pol); err != nil {
			return err
		}
	}
	return nil
}

// SetToggle flips a single transport toggle on each device, leaving its other toggles intact so a
// multi-device change does not clobber per-device state.
func (c *Controller) SetToggle(ips []string, key string, enabled bool) error {
	if err := c.knownIPs(ips); err != nil {
		return err
	}
	for _, ip := range ips {
		pol := c.currentPolicy(ip)
		pol.Toggles = applyToggle(pol.Toggles, key, enabled)
		if err := c.SetFilter(ip, pol); err != nil {
			return err
		}
	}
	return nil
}

func applyToggle(t rules.Toggles, key string, on bool) rules.Toggles {
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
	}
	return t
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

// Release stops managing a device entirely: it clears enforcement and filtering, then restores
// the device's ARP cache so its connectivity recovers at once.
func (c *Controller) Release(ip string) error {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return err
	}
	dev, ok := c.table.GetByIP(net.ParseIP(ip))
	if !ok {
		return fmt.Errorf("control: unknown device %s", ip)
	}
	if err := c.enforcer.Clear(addr); err != nil {
		return err
	}
	c.filter.ClearPolicy(addr)

	c.mu.Lock()
	delete(c.managed, ip)
	delete(c.filtered, ip)
	c.mu.Unlock()

	c.spoofer.RestoreDevice(dev)
	c.refreshSession()
	return nil
}

// apply mutates a device's enforcement policy, ensures the session is running, and updates its
// target set. A device must have been discovered (so we know its MAC) before it can be managed.
func (c *Controller) apply(ip string, mutate func(*policyState) error) error {
	if _, ok := c.table.GetByIP(net.ParseIP(ip)); !ok {
		return fmt.Errorf("control: device %s must be scanned before it can be managed", ip)
	}
	c.mu.Lock()
	p := c.managed[ip]
	if err := mutate(&p); err != nil {
		c.mu.Unlock()
		return err
	}
	c.managed[ip] = p
	c.mu.Unlock()

	c.ensureSession()
	c.refreshSession()
	return nil
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
	if err := c.guard.Begin(); err != nil {
		log.Printf("control: could not adjust redirects: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	c.cancel = cancel
	go safely("spoofer", func() { _ = c.spoofer.Start(ctx, c.spoofConfig()) })
	go safely("relay", func() { _ = c.relay.Run(ctx) })
}

// safely runs fn and recovers from a panic so a fault in one session goroutine cannot crash the
// process and skip the redirect/ARP restoration that runs on shutdown.
func safely(name string, fn func()) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("control: %s goroutine recovered from panic: %v", name, r)
		}
	}()
	fn()
}

// refreshSession pushes the current managed set into the running spoofer.
func (c *Controller) refreshSession() {
	c.mu.Lock()
	running := c.started
	cfg := c.spoofConfig()
	c.mu.Unlock()
	if running {
		c.spoofer.Update(cfg)
	}
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
	c.teardown()
	_ = c.enforcer.ClearAll()
	_ = c.relayHandle.Close()
	return c.handle.Close()
}
