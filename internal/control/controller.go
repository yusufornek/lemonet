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
	IP       string   `json:"ip"`
	MAC      string   `json:"mac"`
	Vendor   string   `json:"vendor"`
	Hostname string   `json:"hostname"`
	Kind     string   `json:"kind"`
	Blocked  bool     `json:"blocked"`
	Paused   bool     `json:"paused"`
	UpKbps   int      `json:"upKbps"`
	DownKbps int      `json:"downKbps"`
	Filtered bool     `json:"filtered"`
	Packs    []string `json:"packs"`
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

	gwIP  net.IP
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
	cancel := c.cancel
	c.cancel = nil
	c.started = false
	c.managed = make(map[string]policyState)
	c.filtered = make(map[string]rules.DevicePolicy)
	c.mu.Unlock()

	if cancel != nil {
		cancel()
		time.Sleep(300 * time.Millisecond) // let the spoofer send its restore frames
	}
	_ = c.enforcer.ClearAll()
	c.filter.ClearAll()
	return nil
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
	if _, ok := c.table.GetByIP(net.ParseIP(ip)); !ok {
		return fmt.Errorf("control: device %s must be scanned before it can be filtered", ip)
	}

	// Category packs are ineffective against QUIC (social and video apps lean on UDP/443), so
	// enabling any pack also forces QUIC blocking, which pushes traffic onto TCP where the SNI and
	// DNS layers can act.
	if len(pol.EnabledPacks) > 0 {
		pol.Toggles.BlockQUIC = true
	}

	active := len(pol.EnabledPacks) > 0 || len(pol.CustomRules) > 0 || pol.Toggles != (rules.Toggles{})
	if active {
		c.filter.SetPolicy(addr, pol)
	} else {
		c.filter.ClearPolicy(addr)
	}

	c.mu.Lock()
	if active {
		c.filtered[ip] = pol
	} else {
		delete(c.filtered, ip)
	}
	c.mu.Unlock()

	c.ensureSession()
	c.refreshSession()
	return nil
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

	ctx, cancel := context.WithCancel(context.Background())
	c.cancel = cancel
	go func() { _ = c.spoofer.Start(ctx, c.spoofConfig()) }()
	go func() { _ = c.relay.Run(ctx) }()
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
		GatewayMAC: c.gwMAC,
		SelfMAC:    c.iface.MAC,
		FullDuplex: true,
	}
}

// Close cancels the session (which restores every target's ARP cache), clears all policy, and
// closes the capture handle. It is safe to call even if no session ever started.
func (c *Controller) Close() error {
	c.mu.Lock()
	cancel := c.cancel
	c.mu.Unlock()
	if cancel != nil {
		cancel()
		time.Sleep(300 * time.Millisecond) // let the spoofer send its restore frames
	}
	_ = c.enforcer.ClearAll()
	_ = c.relayHandle.Close()
	return c.handle.Close()
}
