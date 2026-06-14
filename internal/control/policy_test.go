package control

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gopacket/gopacket"

	"github.com/yusufornek/lemonet/internal/enforce"
	"github.com/yusufornek/lemonet/internal/engine"
	"github.com/yusufornek/lemonet/internal/filter"
	"github.com/yusufornek/lemonet/internal/filter/rules"
)

func TestPolicyHelpers(t *testing.T) {
	rs := upsertRule(nil, rules.Rule{Action: rules.Block, Domain: "example.com"})
	rs = upsertRule(rs, rules.Rule{Action: rules.Allow, Domain: "example.com"})
	if len(rs) != 1 || rs[0].Action != rules.Allow {
		t.Fatalf("upsertRule should replace by domain, got %+v", rs)
	}
	rs = removeRule(rs, rules.Allow, "example.com")
	if len(rs) != 0 {
		t.Fatalf("removeRule left %+v", rs)
	}

	packs := setPack([]string{"ads"}, "ads", true)
	if len(packs) != 1 || packs[0] != "ads" {
		t.Fatalf("setPack should not duplicate, got %v", packs)
	}
	packs = setPack(packs, "ads", false)
	if len(packs) != 0 {
		t.Fatalf("setPack disable left %v", packs)
	}
}

func TestApplyToggleRejectsUnknownKeys(t *testing.T) {
	toggles, err := applyToggle(rules.Toggles{}, "blockQuic", true)
	if err != nil {
		t.Fatal(err)
	}
	if !toggles.BlockQUIC {
		t.Fatal("blockQuic should be enabled")
	}
	if _, err := applyToggle(toggles, "madeUp", true); err == nil {
		t.Fatal("unknown toggle should be rejected")
	}
}

func TestParseAction(t *testing.T) {
	if act, err := parseAction("allow"); err != nil || act != rules.Allow {
		t.Fatalf("parseAction allow = %q, %v", act, err)
	}
	if _, err := parseAction("maybe"); err == nil {
		t.Fatal("unknown action should be rejected")
	}
}

func TestCleanPolicyNormalizesAndValidates(t *testing.T) {
	c := &Controller{packMgr: filter.NewManager()}
	pol, err := c.cleanPolicy(rules.DevicePolicy{
		EnabledPacks: []string{"ads", "ads"},
		CustomRules: []rules.Rule{
			{Action: rules.Block, Domain: "HTTPS://Example.com/path"},
			{Action: rules.Allow, Domain: "example.com"},
		},
		Toggles: rules.Toggles{BlockVPNPorts: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(pol.EnabledPacks) != 1 || pol.EnabledPacks[0] != "ads" {
		t.Fatalf("enabled packs = %v", pol.EnabledPacks)
	}
	if len(pol.CustomRules) != 1 || pol.CustomRules[0].Action != rules.Allow || pol.CustomRules[0].Domain != "example.com" {
		t.Fatalf("custom rules = %+v", pol.CustomRules)
	}
	if !pol.Toggles.BlockVPNPorts {
		t.Fatal("toggles should be preserved")
	}

	if _, err := c.cleanPolicy(rules.DevicePolicy{EnabledPacks: []string{"unknown"}}); err == nil {
		t.Fatal("unknown pack should be rejected")
	}
	if _, err := c.cleanPolicy(rules.DevicePolicy{CustomRules: []rules.Rule{{Action: rules.Block, Domain: "bad_label.example"}}}); err == nil {
		t.Fatal("invalid domain should be rejected")
	}
}

func TestCleanPolicyRejectsTooManyCustomRules(t *testing.T) {
	c := &Controller{packMgr: filter.NewManager()}
	custom := make([]rules.Rule, maxCustomRulesPerDevice+1)
	for i := range custom {
		custom[i] = rules.Rule{Action: rules.Block, Domain: fmt.Sprintf("site-%d.example.com", i)}
	}
	if _, err := c.cleanPolicy(rules.DevicePolicy{CustomRules: custom[:maxCustomRulesPerDevice]}); err != nil {
		t.Fatalf("max custom rule count should be accepted: %v", err)
	}
	if _, err := c.cleanPolicy(rules.DevicePolicy{CustomRules: custom}); err == nil || !strings.Contains(err.Error(), "too many custom rules") {
		t.Fatalf("cleanPolicy error = %v, want too many custom rules", err)
	}
}

func TestKnownIPsProtectsHostAndGateway(t *testing.T) {
	c := &Controller{
		iface: engine.Interface{IP: net.ParseIP("192.168.1.10")},
		gwIP:  net.ParseIP("192.168.1.1"),
		table: engine.NewTable(),
	}
	for _, d := range []engine.Device{
		{IP: net.ParseIP("192.168.1.1"), MAC: mustMAC(t, "00:11:22:33:44:55")},
		{IP: net.ParseIP("192.168.1.10"), MAC: mustMAC(t, "00:11:22:33:44:66")},
		{IP: net.ParseIP("192.168.1.50"), MAC: mustMAC(t, "00:11:22:33:44:77")},
	} {
		c.table.Upsert(d)
	}
	if err := c.knownIPs([]string{"192.168.1.50"}); err != nil {
		t.Fatal(err)
	}
	for _, ip := range []string{"192.168.1.1", "192.168.1.10"} {
		if err := c.knownIPs([]string{ip}); err == nil {
			t.Fatalf("%s should be protected", ip)
		}
	}
	if err := c.knownIPs(nil); err == nil {
		t.Fatal("empty device list should be rejected")
	}
}

func TestKnownIPsRejectsTooManyTargets(t *testing.T) {
	c := newSyntheticController(t)
	ips := addScannedDevices(t, c, maxBulkTargets+1)

	if err := c.knownIPs(ips); err == nil || !strings.Contains(err.Error(), "too many devices") {
		t.Fatalf("knownIPs error = %v, want too many devices", err)
	}
}

func TestActionPreviewRejectsTooManyTargets(t *testing.T) {
	c := newSyntheticController(t)
	ips := addScannedDevices(t, c, maxBulkTargets+1)

	got := c.PreviewAction(ips, "block")
	if got.Allowed != 0 || got.Unavailable != len(ips) || len(got.Devices) != 0 || got.Reason != "too_many_targets" {
		t.Fatalf("preview = %+v, want too_many_targets rejection", got)
	}
}

func TestDiagnosticsSummarizesSafeState(t *testing.T) {
	c := &Controller{
		iface:    engine.Interface{Name: "en0", IP: net.ParseIP("192.168.1.10")},
		gwIP:     net.ParseIP("192.168.1.1"),
		table:    engine.NewTable(),
		packMgr:  filter.NewManager(),
		managed:  map[string]policyState{"192.168.1.50": {blocked: true}},
		filtered: map[string]rules.DevicePolicy{"192.168.1.60": {EnabledPacks: []string{"ads"}}},
	}
	for _, d := range []engine.Device{
		{IP: net.ParseIP("192.168.1.1"), MAC: mustMAC(t, "00:11:22:33:44:55")},
		{IP: net.ParseIP("192.168.1.10"), MAC: mustMAC(t, "00:11:22:33:44:66")},
		{IP: net.ParseIP("192.168.1.50"), MAC: mustMAC(t, "00:11:22:33:44:77")},
		{IP: net.ParseIP("192.168.1.60"), MAC: mustMAC(t, "00:11:22:33:44:88")},
	} {
		c.table.Upsert(d)
	}

	got := c.Diagnostics()
	if got.Interface != "en0" || got.SelfIP != "192.168.1.10" || got.GatewayIP != "192.168.1.1" {
		t.Fatalf("bad interface summary: %+v", got)
	}
	if got.Devices != 4 || got.ManagedDevices != 1 || got.FilteredDevices != 1 || got.ProtectedDevices != 2 {
		t.Fatalf("bad device counts: %+v", got)
	}
	if got.Packs == 0 || got.LoadedPacks == 0 {
		t.Fatalf("pack counts should be populated: %+v", got)
	}
}

func TestPreflightSummarizesReadinessWithoutSensitiveDetails(t *testing.T) {
	c := newSyntheticController(t)
	c.handle = noopHandle{}
	c.relayHandle = noopHandle{}
	c.relay = engine.NewRelay(noopHandle{}, c.iface, c.gwIP, c.gwMAC, c.table, c.enforcer)

	got := c.Preflight()
	if !got.Ready {
		t.Fatalf("preflight should be ready with warnings only: %+v", got)
	}
	checks := preflightChecksByID(got.Checks)
	for _, id := range []string{"interface", "gateway", "capture", "relay", "packs"} {
		if checks[id].Status != "ok" {
			t.Fatalf("%s status = %q, want ok in %+v", id, checks[id].Status, got.Checks)
		}
	}
	if checks["ipv6"].Status != "warn" {
		t.Fatalf("ipv6 status = %q, want warn when router was not discovered", checks["ipv6"].Status)
	}
	body, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	for _, sensitive := range [][]byte{
		[]byte("00:11:22:33:44"),
		[]byte("blocked.example"),
		[]byte("hostname"),
		[]byte("token"),
		[]byte("/Users/"),
		[]byte("raw packet access"),
		[]byte("sourceUrl"),
		[]byte("https://"),
	} {
		if bytes.Contains(body, sensitive) {
			t.Fatalf("preflight leaked sensitive detail %q in %s", sensitive, body)
		}
	}
}

func TestPreflightFailsWhenCaptureOrRelayIsMissing(t *testing.T) {
	c := newSyntheticController(t)
	c.handle = noopHandle{}
	c.relay = nil

	got := c.Preflight()
	if got.Ready {
		t.Fatalf("preflight should not be ready when relay capture is missing: %+v", got)
	}
	checks := preflightChecksByID(got.Checks)
	if checks["capture"].Status != "fail" || checks["relay"].Status != "fail" {
		t.Fatalf("capture/relay checks = %+v, want failures", got.Checks)
	}
}

func TestActionPreviewIsReadOnlyAndCoarse(t *testing.T) {
	c := newSyntheticController(t)
	c.table.Upsert(engine.Device{IP: net.ParseIP("192.168.1.10"), MAC: mustMAC(t, "00:11:22:33:44:66"), Hostname: "owner-laptop"})
	c.table.Upsert(engine.Device{IP: net.ParseIP("192.168.1.1"), MAC: mustMAC(t, "00:11:22:33:44:55")})
	c.managed["192.168.1.50"] = policyState{blocked: true}
	c.filtered["192.168.1.50"] = rules.DevicePolicy{EnabledPacks: []string{"gaming"}}
	c.undo["192.168.1.50"] = policySnapshot{hadManaged: true}
	beforeManaged := len(c.managed)
	beforeFiltered := len(c.filtered)
	beforeUndo := len(c.undo)
	beforeStarted := c.started

	got := c.PreviewAction([]string{"192.168.1.50", "192.168.1.10", "192.168.1.99"}, "release")
	if got.Action != "release" || got.Total != 3 || got.Allowed != 1 || got.Protected != 1 || got.Unknown != 1 {
		t.Fatalf("preview counts = %+v", got)
	}
	if got.AlreadyManaged != 1 || got.WillRestoreDevices != 1 || !got.WillStopSession || got.WillStartSession {
		t.Fatalf("preview impact = %+v", got)
	}
	if len(c.managed) != beforeManaged || len(c.filtered) != beforeFiltered || len(c.undo) != beforeUndo || c.started != beforeStarted {
		t.Fatalf("preview mutated controller state: managed=%d filtered=%d undo=%d started=%v", len(c.managed), len(c.filtered), len(c.undo), c.started)
	}
	devices := actionPreviewDevicesByIP(got.Devices)
	if devices["192.168.1.50"].Status != "allowed" || !devices["192.168.1.50"].Managed || !devices["192.168.1.50"].Filtered {
		t.Fatalf("managed device preview = %+v", devices["192.168.1.50"])
	}
	if devices["192.168.1.10"].Status != "protected" || devices["192.168.1.10"].Reason != "host" {
		t.Fatalf("host preview = %+v", devices["192.168.1.10"])
	}
	if devices["192.168.1.99"].Status != "unknown" || devices["192.168.1.99"].Reason != "not_scanned" {
		t.Fatalf("unknown preview = %+v", devices["192.168.1.99"])
	}
	body, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	for _, sensitive := range [][]byte{
		[]byte("00:11:22:33:44"),
		[]byte("owner-laptop"),
		[]byte("gaming"),
		[]byte("blocked.example"),
		[]byte("token"),
	} {
		if bytes.Contains(body, sensitive) {
			t.Fatalf("preview leaked sensitive detail %q in %s", sensitive, body)
		}
	}
}

func TestActionPreviewReportsSessionStart(t *testing.T) {
	c := newSyntheticController(t)
	c.started = false

	got := c.PreviewAction([]string{"192.168.1.50"}, "block")
	if got.Total != 1 || got.Allowed != 1 || got.AlreadyManaged != 0 || !got.WillStartSession || got.WillStopSession {
		t.Fatalf("block preview = %+v", got)
	}

	resume := c.PreviewAction([]string{"192.168.1.50"}, "resume")
	if resume.WillStartSession {
		t.Fatalf("resume preview should not claim a session start for an unmanaged device: %+v", resume)
	}
}

func TestActionPreviewDeduplicatesImpactAndCountsFilteredTargets(t *testing.T) {
	c := newSyntheticController(t)
	c.managed = map[string]policyState{}
	c.filtered["192.168.1.50"] = rules.DevicePolicy{EnabledPacks: []string{"gaming"}}

	got := c.PreviewAction([]string{"192.168.1.50", "192.168.1.50"}, "release")
	if got.Total != 2 || got.Allowed != 1 || got.AlreadyManaged != 1 || got.WillRestoreDevices != 1 || !got.WillStopSession {
		t.Fatalf("filtered-only duplicate release preview = %+v", got)
	}
	if len(got.Devices) != 2 || got.Devices[1].Status != "duplicate" {
		t.Fatalf("duplicate device entries = %+v", got.Devices)
	}

	unknown := c.PreviewAction([]string{"192.168.1.50"}, "made-up")
	if unknown.Unavailable != 1 || unknown.Devices[0].Reason != "unknown_action" {
		t.Fatalf("unknown action preview = %+v", unknown)
	}
}

func TestNoopEnforcementActionsDoNotStartSession(t *testing.T) {
	c := newSyntheticController(t)
	c.started = false

	if err := c.Resume("192.168.1.50"); err != nil {
		t.Fatal(err)
	}
	if c.started || len(c.managed) != 0 || len(c.undo) != 0 {
		t.Fatalf("resume no-op started or mutated state: started=%v managed=%d undo=%d", c.started, len(c.managed), len(c.undo))
	}

	if err := c.Throttle("192.168.1.50", 0, 0); err != nil {
		t.Fatal(err)
	}
	if c.started || len(c.managed) != 0 || len(c.undo) != 0 {
		t.Fatalf("full-speed throttle no-op started or mutated state: started=%v managed=%d undo=%d", c.started, len(c.managed), len(c.undo))
	}
}

func TestClearingOnlyEnforcementStopsSession(t *testing.T) {
	c := newSyntheticController(t)
	ip := "192.168.1.50"
	addr := netip.MustParseAddr(ip)
	c.managed[ip] = policyState{upKbps: 128, downKbps: 128}
	if err := c.enforcer.Throttle(addr, 128, 128); err != nil {
		t.Fatal(err)
	}

	if err := c.Throttle(ip, 0, 0); err != nil {
		t.Fatal(err)
	}
	if c.started {
		t.Fatal("clearing the only enforcement policy should stop the session")
	}
	if len(c.managed) != 0 {
		t.Fatalf("managed entries = %d, want 0", len(c.managed))
	}
	if len(c.undo) != 1 {
		t.Fatalf("undo snapshots = %d, want 1", len(c.undo))
	}
	if drop, delay := c.enforcer.Decide(addr, engine.Upload, 1000); drop || delay > 0 {
		t.Fatalf("enforcer still active after clear: drop=%v delay=%s", drop, delay)
	}
}

func TestReleaseRejectsProtectedDevices(t *testing.T) {
	c := newSyntheticController(t)
	for _, ip := range []string{"192.168.1.10", "192.168.1.1"} {
		err := c.Release(ip)
		if err == nil || !strings.Contains(err.Error(), "protected") {
			t.Fatalf("Release(%s) error = %v, want protected rejection", ip, err)
		}
	}
}

func TestReleaseNoopDoesNotMutateInactiveDevice(t *testing.T) {
	c := newSyntheticController(t)
	c.started = false

	if err := c.Release("192.168.1.50"); err != nil {
		t.Fatal(err)
	}
	if c.started || len(c.managed) != 0 || len(c.filtered) != 0 || len(c.undo) != 0 || len(c.generation) != 0 {
		t.Fatalf("inactive release mutated state: started=%v managed=%d filtered=%d undo=%d generation=%d", c.started, len(c.managed), len(c.filtered), len(c.undo), len(c.generation))
	}
}

func TestReleaseNoopDoesNotClearLowerLayerState(t *testing.T) {
	c := newSyntheticController(t)
	c.started = false
	ip := "192.168.1.50"
	addr := netip.MustParseAddr(ip)
	if err := c.enforcer.Block(addr); err != nil {
		t.Fatal(err)
	}
	c.filter.SetPolicy(addr, rules.DevicePolicy{Toggles: rules.Toggles{BlockQUIC: true}})

	if err := c.Release(ip); err != nil {
		t.Fatal(err)
	}
	if drop, _ := c.enforcer.Decide(addr, engine.Upload, 1000); !drop {
		t.Fatal("inactive release should not clear lower-layer enforcement state")
	}
	action := c.filter.InspectFlow(addr, engine.Upload, true, 54000, 443, nil)
	if action.Kind != engine.FlowDrop {
		t.Fatalf("inactive release should not clear lower-layer filter state, got %v", action.Kind)
	}
}

func TestReleaseStopsSessionWhenLastPolicyIsCleared(t *testing.T) {
	c := newSyntheticController(t)
	ip := "192.168.1.50"
	addr := netip.MustParseAddr(ip)
	c.managed[ip] = policyState{blocked: true}
	if err := c.enforcer.Block(addr); err != nil {
		t.Fatal(err)
	}

	if err := c.Release(ip); err != nil {
		t.Fatal(err)
	}
	if c.started {
		t.Fatal("release should stop the session when no managed or filtered devices remain")
	}
	if len(c.managed) != 0 || len(c.filtered) != 0 {
		t.Fatalf("release left policies: managed=%d filtered=%d", len(c.managed), len(c.filtered))
	}
	if len(c.undo) != 1 {
		t.Fatalf("release undo snapshots = %d, want 1", len(c.undo))
	}
	if drop, delay := c.enforcer.Decide(addr, engine.Upload, 1000); drop || delay > 0 {
		t.Fatalf("enforcer still active after release: drop=%v delay=%s", drop, delay)
	}
}

func TestReleaseKeepsSessionWhenOtherPoliciesRemain(t *testing.T) {
	c := newSyntheticController(t)
	firstIP := "192.168.1.50"
	secondIP := "192.168.1.60"
	firstAddr := netip.MustParseAddr(firstIP)
	secondAddr := netip.MustParseAddr(secondIP)
	c.table.Upsert(engine.Device{IP: net.ParseIP(secondIP), MAC: mustMAC(t, "00:11:22:33:44:88")})
	c.managed[firstIP] = policyState{blocked: true}
	c.managed[secondIP] = policyState{blocked: true}
	if err := c.enforcer.Block(firstAddr); err != nil {
		t.Fatal(err)
	}
	if err := c.enforcer.Block(secondAddr); err != nil {
		t.Fatal(err)
	}

	if err := c.Release(firstIP); err != nil {
		t.Fatal(err)
	}
	if !c.started {
		t.Fatal("release should keep the session active while another policy remains")
	}
	if _, ok := c.managed[firstIP]; ok {
		t.Fatal("release should clear the selected device")
	}
	if !c.managed[secondIP].blocked {
		t.Fatal("release should not clear the remaining device")
	}
	if drop, _ := c.enforcer.Decide(firstAddr, engine.Upload, 1000); drop {
		t.Fatal("released device should no longer be blocked")
	}
	if drop, _ := c.enforcer.Decide(secondAddr, engine.Upload, 1000); !drop {
		t.Fatal("remaining device should still be blocked")
	}
}

func TestDevicesClonesPolicySlices(t *testing.T) {
	c := newSyntheticController(t)
	ip := "192.168.1.50"
	if err := c.SetFilter(ip, rules.DevicePolicy{
		EnabledPacks: []string{"ads"},
		CustomRules:  []rules.Rule{{Action: rules.Block, Domain: "blocked.example"}},
	}); err != nil {
		t.Fatal(err)
	}

	views := c.Devices()
	if len(views) != 1 || len(views[0].Packs) != 3 || len(views[0].CustomRules) != 1 {
		t.Fatalf("unexpected device view: %+v", views)
	}
	views[0].Packs[0] = "mutated"
	views[0].CustomRules[0].Domain = "mutated.example"

	pol := c.currentPolicy(ip)
	if pol.EnabledPacks[0] != "ads" {
		t.Fatalf("device view pack alias mutated stored policy: %+v", pol.EnabledPacks)
	}
	if pol.CustomRules[0].Domain != "blocked.example" {
		t.Fatalf("device view rule alias mutated stored policy: %+v", pol.CustomRules)
	}
}

func TestSetFilterEnablesDomainHardeningToggles(t *testing.T) {
	c := newSyntheticController(t)
	ip := "192.168.1.50"
	if err := c.SetFilter(ip, rules.DevicePolicy{EnabledPacks: []string{"ads"}}); err != nil {
		t.Fatal(err)
	}

	pol := c.currentPolicy(ip)
	if !pol.Toggles.BlockQUIC || !pol.Toggles.BlockEncryptedDNS || !pol.Toggles.StripECH || !pol.Toggles.FirefoxCanary || !pol.Toggles.BlockVPNPorts {
		t.Fatalf("domain filter hardening toggles = %+v, want QUIC, encrypted DNS, ECH, Firefox canary, and VPN defaults enabled", pol.Toggles)
	}
}

func TestSetFilterAddsEncryptedDNSPackForDomainPolicies(t *testing.T) {
	for _, tc := range []struct {
		name   string
		policy rules.DevicePolicy
	}{
		{name: "pack", policy: rules.DevicePolicy{EnabledPacks: []string{"ads"}}},
		{name: "custom rule", policy: rules.DevicePolicy{CustomRules: []rules.Rule{{Action: rules.Block, Domain: "blocked.example"}}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := newSyntheticController(t)
			ip := "192.168.1.50"
			if err := c.SetFilter(ip, tc.policy); err != nil {
				t.Fatal(err)
			}

			pol := c.currentPolicy(ip)
			if !containsString(pol.EnabledPacks, "encrypted-dns") {
				t.Fatalf("domain policy packs = %v, want encrypted-dns hardening pack", pol.EnabledPacks)
			}
		})
	}
}

func TestSetFilterAddsVPNHardeningForDomainPolicies(t *testing.T) {
	for _, tc := range []struct {
		name   string
		policy rules.DevicePolicy
	}{
		{name: "pack", policy: rules.DevicePolicy{EnabledPacks: []string{"ads"}}},
		{name: "custom rule", policy: rules.DevicePolicy{CustomRules: []rules.Rule{{Action: rules.Block, Domain: "blocked.example"}}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := newSyntheticController(t)
			ip := "192.168.1.50"
			if err := c.SetFilter(ip, tc.policy); err != nil {
				t.Fatal(err)
			}

			pol := c.currentPolicy(ip)
			if !containsString(pol.EnabledPacks, "vpn") {
				t.Fatalf("domain policy packs = %v, want vpn hardening pack", pol.EnabledPacks)
			}
			if !pol.Toggles.BlockVPNPorts {
				t.Fatalf("domain policy toggles = %+v, want VPN port hardening", pol.Toggles)
			}
		})
	}
}

func TestDevicesIncludesLearnedIPv6Addresses(t *testing.T) {
	c := newSyntheticController(t)
	dev, ok := c.table.GetByIP(net.ParseIP("192.168.1.50"))
	if !ok {
		t.Fatal("missing synthetic device")
	}
	c.table.RecordV6(dev.MAC, net.ParseIP("fe80::211:22ff:fe33:4477"))
	c.table.RecordV6(dev.MAC, net.ParseIP("2001:db8::50"))

	views := c.Devices()
	if len(views) != 1 {
		t.Fatalf("device views len = %d, want 1", len(views))
	}
	want := []string{"2001:db8::50", "fe80::211:22ff:fe33:4477"}
	if !reflect.DeepEqual(views[0].IPv6, want) {
		t.Fatalf("ipv6 = %+v, want %+v", views[0].IPv6, want)
	}
}

func TestSetFilterConcurrentReleaseDoesNotLeaveStaleFilterState(t *testing.T) {
	c := newSyntheticController(t)
	ip := "192.168.1.50"
	addr := netip.MustParseAddr(ip)
	spy := &blockingPolicyFilter{
		base:         c.packMgr.Filter(),
		setEntered:   make(chan struct{}, 1),
		allowSet:     make(chan struct{}),
		clearEntered: make(chan struct{}, 1),
	}
	c.filter = spy

	setErr := make(chan error, 1)
	go func() {
		setErr <- c.SetFilter(ip, rules.DevicePolicy{Toggles: rules.Toggles{BlockQUIC: true}})
	}()
	<-spy.setEntered

	releaseErr := make(chan error, 1)
	go func() {
		releaseErr <- c.Release(ip)
	}()
	select {
	case <-spy.clearEntered:
	case <-time.After(100 * time.Millisecond):
	}
	close(spy.allowSet)

	if err := <-setErr; err != nil {
		t.Fatal(err)
	}
	if err := <-releaseErr; err != nil {
		t.Fatal(err)
	}
	c.mu.Lock()
	_, stillFiltered := c.filtered[ip]
	c.mu.Unlock()
	if stillFiltered {
		t.Fatal("release should clear controller filter state")
	}
	action := spy.base.InspectFlow(addr, engine.Upload, true, 54000, 443, nil)
	if action.Kind != engine.FlowAllow {
		t.Fatalf("release left stale lower-layer filter action: %v", action.Kind)
	}
}

func TestFilterMutationsMergeWithCurrentPolicyAtCommit(t *testing.T) {
	c := newSyntheticController(t)
	ip := "192.168.1.50"

	if err := c.applyFilterMutations([]string{ip}, func(pol rules.DevicePolicy) rules.DevicePolicy {
		pol.EnabledPacks = setPack(pol.EnabledPacks, "ads", true)
		return pol
	}); err != nil {
		t.Fatal(err)
	}
	if err := c.applyFilterMutations([]string{ip}, func(pol rules.DevicePolicy) rules.DevicePolicy {
		pol.Toggles.BlockVPNPorts = true
		return pol
	}); err != nil {
		t.Fatal(err)
	}

	pol := c.currentPolicy(ip)
	if !reflect.DeepEqual(pol.EnabledPacks, []string{"ads", "encrypted-dns", "vpn"}) {
		t.Fatalf("pack mutation was clobbered: %+v", pol)
	}
	if !pol.Toggles.BlockVPNPorts {
		t.Fatalf("toggle mutation was not merged: %+v", pol.Toggles)
	}
}

func TestProfilesAreCloned(t *testing.T) {
	c := &Controller{}
	profiles := c.Profiles()
	if len(profiles) < 3 {
		t.Fatalf("profiles = %d, want at least 3", len(profiles))
	}
	profiles[0].EnabledPacks[0] = "mutated"
	fresh := c.Profiles()
	if fresh[0].EnabledPacks[0] == "mutated" {
		t.Fatal("profiles should not expose mutable global slices")
	}
	if _, ok := profileByID("missing"); ok {
		t.Fatal("unknown profile should not resolve")
	}
}

func TestApplyProfilePreservesCustomRules(t *testing.T) {
	table := engine.NewTable()
	table.Upsert(engine.Device{IP: net.ParseIP("192.168.1.50"), MAC: mustMAC(t, "00:11:22:33:44:77")})
	packMgr := filter.NewManager()
	c := &Controller{
		iface:   engine.Interface{IP: net.ParseIP("192.168.1.10")},
		gwIP:    net.ParseIP("192.168.1.1"),
		table:   table,
		filter:  packMgr.Filter(),
		packMgr: packMgr,
		spoofer: engine.NewSpoofer(nil, table),
		managed: make(map[string]policyState),
		filtered: map[string]rules.DevicePolicy{"192.168.1.50": {
			CustomRules: []rules.Rule{{Action: rules.Allow, Domain: "chat.example"}},
		}},
		started: true,
	}

	if err := c.ApplyProfile([]string{"192.168.1.50"}, "focus"); err != nil {
		t.Fatal(err)
	}
	pol := c.filtered["192.168.1.50"]
	if len(pol.CustomRules) != 1 || pol.CustomRules[0].Domain != "chat.example" {
		t.Fatalf("custom rules should be preserved, got %+v", pol.CustomRules)
	}
	if len(pol.EnabledPacks) != 6 || pol.EnabledPacks[0] != "social" || pol.EnabledPacks[1] != "streaming" {
		t.Fatalf("profile packs not applied: %+v", pol.EnabledPacks)
	}
	if !pol.Toggles.BlockQUIC || !pol.Toggles.BlockEncryptedDNS || !pol.Toggles.StripECH || !pol.Toggles.FirefoxCanary || !pol.Toggles.BlockVPNPorts {
		t.Fatalf("profile toggles not applied: %+v", pol.Toggles)
	}
	if pol.MAC != "00:11:22:33:44:77" {
		t.Fatalf("policy MAC = %q", pol.MAC)
	}

	if err := c.ApplyProfile([]string{"192.168.1.50"}, "missing"); err == nil {
		t.Fatal("unknown profile should be rejected")
	}
}

func TestFocusProfileBlocksStreamingVideoDomains(t *testing.T) {
	table := engine.NewTable()
	table.Upsert(engine.Device{IP: net.ParseIP("192.168.1.50"), MAC: mustMAC(t, "00:11:22:33:44:77")})
	packMgr := filter.NewManager()
	c := &Controller{
		iface:    engine.Interface{IP: net.ParseIP("192.168.1.10")},
		gwIP:     net.ParseIP("192.168.1.1"),
		table:    table,
		filter:   packMgr.Filter(),
		packMgr:  packMgr,
		spoofer:  engine.NewSpoofer(nil, table),
		managed:  make(map[string]policyState),
		filtered: make(map[string]rules.DevicePolicy),
		started:  true,
	}

	if err := c.ApplyProfile([]string{"192.168.1.50"}, "focus"); err != nil {
		t.Fatal(err)
	}
	for _, domain := range []string{"youtube.com", "youtubei.googleapis.com", "googlevideo.com", "ytimg.com"} {
		decision, err := c.Explain("192.168.1.50", domain)
		if err != nil {
			t.Fatal(err)
		}
		if !decision.Blocked || decision.Source != rules.DecisionPack {
			t.Fatalf("focus should block %s by pack, got %+v", domain, decision)
		}
	}
}

func TestFocusProfileEnablesVPNHardening(t *testing.T) {
	c := newSyntheticController(t)

	if err := c.ApplyProfile([]string{"192.168.1.50"}, "focus"); err != nil {
		t.Fatal(err)
	}

	pol := c.currentPolicy("192.168.1.50")
	if !containsString(pol.EnabledPacks, "vpn") {
		t.Fatalf("focus packs = %v, want vpn hardening pack", pol.EnabledPacks)
	}
	if !pol.Toggles.BlockVPNPorts {
		t.Fatalf("focus toggles = %+v, want VPN port hardening", pol.Toggles)
	}
}

func TestExplainValidatesDeviceAndDomain(t *testing.T) {
	table := engine.NewTable()
	table.Upsert(engine.Device{IP: net.ParseIP("192.168.1.50"), MAC: mustMAC(t, "00:11:22:33:44:77")})
	c := &Controller{
		iface:   engine.Interface{IP: net.ParseIP("192.168.1.10")},
		gwIP:    net.ParseIP("192.168.1.1"),
		table:   table,
		packMgr: filter.NewManager(),
		filtered: map[string]rules.DevicePolicy{"192.168.1.50": {
			CustomRules: []rules.Rule{{Action: rules.Block, Domain: "tracker.test"}},
		}},
	}

	decision, err := c.Explain("192.168.1.50", "https://a.tracker.test/path")
	if err != nil {
		t.Fatal(err)
	}
	if !decision.Blocked || decision.Source != rules.DecisionCustomBlock || decision.MatchedDomain != "tracker.test" {
		t.Fatalf("decision = %+v", decision)
	}
	if _, err := c.Explain("192.168.1.50", "localhost"); err == nil {
		t.Fatal("invalid domain should be rejected")
	}
	if _, err := c.Explain("192.168.1.60", "example.com"); err == nil {
		t.Fatal("unknown device should be rejected")
	}
}

func TestPolicyTemplateExportImport(t *testing.T) {
	c := newSyntheticController(t)
	c.table.Upsert(engine.Device{IP: net.ParseIP("192.168.1.60"), MAC: mustMAC(t, "00:11:22:33:44:88")})
	if err := c.SetFilter("192.168.1.50", rules.DevicePolicy{
		EnabledPacks: []string{"gaming"},
		CustomRules:  []rules.Rule{{Action: rules.Allow, Domain: "store.game.example"}},
		Toggles:      rules.Toggles{BlockEncryptedDNS: true},
	}); err != nil {
		t.Fatal(err)
	}

	template, err := c.ExportPolicy("192.168.1.50")
	if err != nil {
		t.Fatal(err)
	}
	if template.Version != 1 || !reflect.DeepEqual(template.EnabledPacks, []string{"gaming", "encrypted-dns", "vpn"}) {
		t.Fatalf("bad export: %+v", template)
	}
	if err := c.ImportPolicy([]string{"192.168.1.60"}, template); err != nil {
		t.Fatal(err)
	}
	imported := c.filtered["192.168.1.60"]
	if imported.MAC != "00:11:22:33:44:88" {
		t.Fatalf("import should bind to target MAC, got %q", imported.MAC)
	}
	if len(imported.CustomRules) != 1 || imported.CustomRules[0].Domain != "store.game.example" {
		t.Fatalf("custom rules not imported: %+v", imported.CustomRules)
	}
	if !imported.Toggles.BlockQUIC || !imported.Toggles.BlockEncryptedDNS || !imported.Toggles.BlockVPNPorts {
		t.Fatalf("toggles not imported/normalized: %+v", imported.Toggles)
	}

	if err := c.ImportPolicy([]string{"192.168.1.60"}, PolicyTemplate{Version: 99}); err == nil {
		t.Fatal("unsupported template version should be rejected")
	}
	if err := c.ImportPolicy([]string{"192.168.1.60"}, PolicyTemplate{Version: 1, EnabledPacks: []string{"missing"}}); err == nil {
		t.Fatal("unknown pack should be rejected")
	}
	if _, err := c.ExportPolicy("192.168.1.10"); err == nil {
		t.Fatal("protected host export should be rejected")
	}
}

func TestNoOpFilterChangeDoesNotReplaceUndo(t *testing.T) {
	c := newSyntheticController(t)
	ip := "192.168.1.50"
	if err := c.SetFilter(ip, rules.DevicePolicy{EnabledPacks: []string{"ads"}}); err != nil {
		t.Fatal(err)
	}
	c.undo = make(map[string]policySnapshot)
	beforeGeneration := c.generation[ip]

	if err := c.SetFilter(ip, c.currentPolicy(ip)); err != nil {
		t.Fatal(err)
	}
	if len(c.undo) != 0 {
		t.Fatalf("no-op filter change should not create undo, got %d", len(c.undo))
	}
	if c.generation[ip] != beforeGeneration {
		t.Fatalf("no-op filter change changed generation from %d to %d", beforeGeneration, c.generation[ip])
	}
}

func TestBulkPolicyValidationHappensBeforeMutation(t *testing.T) {
	c := newSyntheticController(t)
	if err := c.ApplyProfile([]string{"192.168.1.50", "192.168.1.10"}, "focus"); err == nil {
		t.Fatal("bulk apply including the host should be rejected")
	}
	if _, ok := c.filtered["192.168.1.50"]; ok {
		t.Fatal("bulk validation failure should not partially apply to valid devices")
	}
	if len(c.undo) != 0 {
		t.Fatalf("bulk validation failure should not create undo, got %d", len(c.undo))
	}
}

func TestUndoRestoresFilterAfterBlock(t *testing.T) {
	c := newSyntheticController(t)
	ip := "192.168.1.50"
	addr := netip.MustParseAddr(ip)
	if err := c.SetFilter(ip, rules.DevicePolicy{EnabledPacks: []string{"ads"}}); err != nil {
		t.Fatal(err)
	}
	c.undo = make(map[string]policySnapshot)

	if err := c.Block(ip); err != nil {
		t.Fatal(err)
	}
	if !c.Devices()[0].HasUndo {
		t.Fatal("device should expose undo after a policy change")
	}
	if drop, _ := c.enforcer.Decide(addr, engine.Upload, 1000); !drop {
		t.Fatal("block should be active before undo")
	}
	if err := c.Undo([]string{ip}); err != nil {
		t.Fatal(err)
	}
	if _, ok := c.filtered[ip]; !ok {
		t.Fatal("undo should preserve the previous filter policy")
	}
	if _, ok := c.managed[ip]; ok {
		t.Fatal("undo should clear the block enforcement")
	}
	if drop, _ := c.enforcer.Decide(addr, engine.Upload, 1000); drop {
		t.Fatal("undo should clear the block decision")
	}
	if c.Devices()[0].HasUndo {
		t.Fatal("undo should be one-step and consume the snapshot")
	}
}

func TestUndoRestoresRelease(t *testing.T) {
	c := newSyntheticController(t)
	ip := "192.168.1.50"
	addr := netip.MustParseAddr(ip)
	if err := c.SetFilter(ip, rules.DevicePolicy{EnabledPacks: []string{"gaming"}}); err != nil {
		t.Fatal(err)
	}
	if err := c.Block(ip); err != nil {
		t.Fatal(err)
	}

	if err := c.Release(ip); err != nil {
		t.Fatal(err)
	}
	if _, ok := c.filtered[ip]; ok {
		t.Fatal("release should clear filter before undo")
	}
	if err := c.Undo([]string{ip}); err != nil {
		t.Fatal(err)
	}
	if _, ok := c.filtered[ip]; !ok {
		t.Fatal("undo should restore filter after release")
	}
	if !c.managed[ip].blocked {
		t.Fatal("undo should restore block enforcement after release")
	}
	if drop, _ := c.enforcer.Decide(addr, engine.Upload, 1000); !drop {
		t.Fatal("restored block should drop traffic")
	}
}

func TestUndoClearsTemporaryTimer(t *testing.T) {
	c := newSyntheticController(t)
	ip := "192.168.1.50"
	if err := c.BlockFor(ip, time.Hour); err != nil {
		t.Fatal(err)
	}
	if len(c.timers) != 1 {
		t.Fatalf("timers = %d, want 1", len(c.timers))
	}
	if err := c.Undo([]string{ip}); err != nil {
		t.Fatal(err)
	}
	if len(c.timers) != 0 {
		t.Fatalf("undo left timers=%d", len(c.timers))
	}
	if _, ok := c.managed[ip]; ok {
		t.Fatal("undo should restore the empty previous enforcement state")
	}
}

func TestUndoRejectsIPReuse(t *testing.T) {
	c := newSyntheticController(t)
	ip := "192.168.1.50"
	if err := c.Block(ip); err != nil {
		t.Fatal(err)
	}
	table := engine.NewTable()
	table.Upsert(engine.Device{IP: net.ParseIP(ip), MAC: mustMAC(t, "00:11:22:33:44:99")})
	c.table = table

	if err := c.Undo([]string{ip}); err == nil {
		t.Fatal("undo should reject a different MAC at the same IP")
	}
	if !c.managed[ip].blocked {
		t.Fatal("failed undo should leave current enforcement unchanged")
	}
}

func TestUndoRejectsMissingSnapshot(t *testing.T) {
	c := newSyntheticController(t)
	if err := c.Undo([]string{"192.168.1.50"}); err == nil {
		t.Fatal("undo without a snapshot should be rejected")
	}
}

func TestUndoConcurrentBlockDoesNotClearNewEnforcement(t *testing.T) {
	c := newSyntheticController(t)
	ip := "192.168.1.50"
	addr := netip.MustParseAddr(ip)
	allowBlock := make(chan struct{})
	close(allowBlock)
	spy := &blockingEnforcer{
		base:         enforce.NewUserspace(),
		allowBlock:   allowBlock,
		clearEntered: make(chan struct{}, 1),
		allowClear:   make(chan struct{}),
	}
	c.enforcer = spy

	if err := c.Block(ip); err != nil {
		t.Fatal(err)
	}
	undoErr := make(chan error, 1)
	go func() {
		undoErr <- c.Undo([]string{ip})
	}()
	<-spy.clearEntered

	blockErr := make(chan error, 1)
	go func() {
		blockErr <- c.Block(ip)
	}()
	blockCompletedBeforeUndoClear := false
	select {
	case err := <-blockErr:
		if err != nil {
			t.Fatal(err)
		}
		blockCompletedBeforeUndoClear = true
	case <-time.After(200 * time.Millisecond):
	}
	close(spy.allowClear)

	if err := <-undoErr; err != nil {
		t.Fatal(err)
	}
	if !blockCompletedBeforeUndoClear {
		if err := <-blockErr; err != nil {
			t.Fatal(err)
		}
	}
	if !c.managed[ip].blocked {
		t.Fatal("new block should remain in controller state after racing undo")
	}
	if drop, _ := c.enforcer.Decide(addr, engine.Upload, 1000); !drop {
		t.Fatal("new block should remain in lower-layer enforcement after racing undo")
	}
}

func TestTemporaryBlockExpiryPreservesFiltering(t *testing.T) {
	c := newSyntheticController(t)
	ip := "192.168.1.50"
	addr := netip.MustParseAddr(ip)
	c.filtered[ip] = rules.DevicePolicy{EnabledPacks: []string{"ads"}}

	if err := c.BlockFor(ip, time.Hour); err != nil {
		t.Fatal(err)
	}
	c.mu.Lock()
	leaseID := c.managed[ip].leaseID
	c.mu.Unlock()
	if drop, _ := c.enforcer.Decide(addr, engine.Upload, 1000); !drop {
		t.Fatal("temporary block should drop traffic before expiry")
	}

	if err := c.expireLease(ip, leaseID); err != nil {
		t.Fatal(err)
	}
	if _, ok := c.filtered[ip]; !ok {
		t.Fatal("expiry should preserve filter policy")
	}
	if _, ok := c.managed[ip]; ok {
		t.Fatal("empty previous enforcement should remove managed enforcement only")
	}
	if drop, _ := c.enforcer.Decide(addr, engine.Upload, 1000); drop {
		t.Fatal("expiry should clear temporary block")
	}
	if len(c.undo) != 0 {
		t.Fatalf("expiry should clear stale undo snapshots, got %d", len(c.undo))
	}
}

func TestTemporaryThrottleRestoresPreviousState(t *testing.T) {
	c := newSyntheticController(t)
	ip := "192.168.1.50"
	addr := netip.MustParseAddr(ip)
	c.managed[ip] = policyState{upKbps: 128, downKbps: 128}
	if err := c.enforcer.Throttle(addr, 128, 128); err != nil {
		t.Fatal(err)
	}

	if err := c.ThrottleFor(ip, 512, 512, time.Hour); err != nil {
		t.Fatal(err)
	}
	c.mu.Lock()
	leaseID := c.managed[ip].leaseID
	c.mu.Unlock()

	if err := c.expireLease(ip, leaseID); err != nil {
		t.Fatal(err)
	}
	got := c.managed[ip]
	if got.upKbps != 128 || got.downKbps != 128 || !got.expires.IsZero() || got.leaseID != 0 {
		t.Fatalf("previous throttle not restored: %+v", got)
	}
}

func TestOldTemporaryLeaseCannotUndoNewerPermanentAction(t *testing.T) {
	c := newSyntheticController(t)
	ip := "192.168.1.50"
	addr := netip.MustParseAddr(ip)

	if err := c.BlockFor(ip, time.Hour); err != nil {
		t.Fatal(err)
	}
	c.mu.Lock()
	leaseID := c.managed[ip].leaseID
	c.mu.Unlock()
	if err := c.Block(ip); err != nil {
		t.Fatal(err)
	}
	if err := c.expireLease(ip, leaseID); err != nil {
		t.Fatal(err)
	}
	got := c.managed[ip]
	if !got.blocked || !got.expires.IsZero() || got.leaseID != 0 {
		t.Fatalf("stale lease changed permanent block: %+v", got)
	}
	if drop, _ := c.enforcer.Decide(addr, engine.Upload, 1000); !drop {
		t.Fatal("permanent block should still be active")
	}
}

func TestTemporaryControlValidation(t *testing.T) {
	c := newSyntheticController(t)
	if err := c.BlockFor("192.168.1.50", 0); err == nil {
		t.Fatal("zero duration should be rejected")
	}
	if err := c.BlockFor("192.168.1.50", MaxTemporaryControlDuration+time.Second); err == nil {
		t.Fatal("excessive duration should be rejected")
	}
	if err := c.ThrottleFor("192.168.1.50", -1, 128, time.Minute); err == nil {
		t.Fatal("negative throttle should be rejected")
	}
	if err := c.BlockFor("192.168.1.10", time.Minute); err == nil {
		t.Fatal("host device should be protected")
	}
}

func TestTemporaryBlockConcurrentReleaseDoesNotLeaveStaleEnforcement(t *testing.T) {
	c := newSyntheticController(t)
	ip := "192.168.1.50"
	addr := netip.MustParseAddr(ip)
	spy := &blockingEnforcer{
		base:         enforce.NewUserspace(),
		blockEntered: make(chan struct{}, 1),
		allowBlock:   make(chan struct{}),
	}
	c.enforcer = spy

	blockErr := make(chan error, 1)
	go func() {
		blockErr <- c.BlockFor(ip, time.Hour)
	}()
	<-spy.blockEntered

	releaseErr := make(chan error, 1)
	go func() {
		releaseErr <- c.Release(ip)
	}()
	select {
	case err := <-releaseErr:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(100 * time.Millisecond):
	}
	close(spy.allowBlock)

	if err := <-blockErr; err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-releaseErr:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("release did not finish after temporary block completed")
	}
	c.mu.Lock()
	_, stillManaged := c.managed[ip]
	c.mu.Unlock()
	if stillManaged {
		t.Fatal("release should clear temporary controller state")
	}
	if drop, _ := c.enforcer.Decide(addr, engine.Upload, 1000); drop {
		t.Fatal("release left stale lower-layer enforcement after temporary block")
	}
}

func TestStopAllStopsTemporaryTimers(t *testing.T) {
	c := newSyntheticController(t)
	if err := c.BlockFor("192.168.1.50", time.Hour); err != nil {
		t.Fatal(err)
	}
	if len(c.timers) != 1 {
		t.Fatalf("timers = %d, want 1", len(c.timers))
	}
	if err := c.StopAll(); err != nil {
		t.Fatal(err)
	}
	if len(c.timers) != 0 || len(c.managed) != 0 {
		t.Fatalf("StopAll left timers=%d managed=%d", len(c.timers), len(c.managed))
	}
	if len(c.undo) != 0 {
		t.Fatalf("StopAll left undo=%d", len(c.undo))
	}
}

func TestStopAllReturnsClearAllErrorAndKeepsControllerStateForRetry(t *testing.T) {
	c := newSyntheticController(t)
	c.enforcer = &failingClearAllEnforcer{
		base: enforce.NewUserspace(),
		err:  errors.New("clear all failed"),
	}
	if err := c.Block("192.168.1.50"); err != nil {
		t.Fatal(err)
	}

	err := c.StopAll()
	if !errors.Is(err, c.enforcer.(*failingClearAllEnforcer).err) {
		t.Fatalf("StopAll error = %v, want clear all error", err)
	}
	if len(c.managed) != 1 || len(c.undo) != 1 {
		t.Fatalf("StopAll should keep retry state after ClearAll failure: managed=%d undo=%d", len(c.managed), len(c.undo))
	}
}

func TestStopAllReturnsGuardEndError(t *testing.T) {
	guardErr := errors.New("restore redirects failed")
	c := newSyntheticController(t)
	c.guard = failingGuard{err: guardErr}

	err := c.StopAll()
	if !errors.Is(err, guardErr) {
		t.Fatalf("StopAll error = %v, want guard end error", err)
	}
}

func TestStopAllWaitsForSpooferRestore(t *testing.T) {
	c := newSyntheticController(t)
	h := newBlockingRestoreHandle(4)
	c.spoofer = engine.NewSpoofer(h, c.table)
	c.relay = engine.NewRelay(noopHandle{}, c.iface, c.gwIP, c.gwMAC, c.table, c.enforcer)
	c.started = false

	if err := c.Block("192.168.1.50"); err != nil {
		t.Fatal(err)
	}
	h.waitForSends(t, 4)

	done := make(chan error, 1)
	go func() { done <- c.StopAll() }()
	h.waitForBlockedRestore(t)

	select {
	case err := <-done:
		t.Fatalf("StopAll returned before restore completed: %v", err)
	case <-time.After(400 * time.Millisecond):
	}

	h.releaseRestore()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestSetFilterRefreshesRunningSpooferImmediately(t *testing.T) {
	c := newSyntheticController(t)
	h := newFailAfterSendHandle(1000, errors.New("unexpected send failure"))
	c.spoofer = engine.NewSpoofer(h, c.table)
	c.started = true

	if err := c.SetFilter("192.168.1.50", rules.DevicePolicy{EnabledPacks: []string{"streaming"}}); err != nil {
		t.Fatal(err)
	}
	h.waitForSends(t, 4)
}

func TestStopSessionBlocksNewSessionUntilRestoreCompletes(t *testing.T) {
	c := newSyntheticController(t)
	c.relay = engine.NewRelay(noopHandle{}, c.iface, c.gwIP, c.gwMAC, c.table, c.enforcer)
	oldIP := "192.168.1.50"
	newIP := "192.168.1.60"
	c.table.Upsert(engine.Device{IP: net.ParseIP(newIP), MAC: mustMAC(t, "00:11:22:33:44:88")})
	c.managed[oldIP] = policyState{blocked: true}
	c.spoofer.Update(c.spoofConfig())
	c.started = true

	cancelCalled := make(chan struct{})
	c.cancel = func() { close(cancelCalled) }
	sessionDone := make(chan sessionResult, 2)
	c.sessionDone = sessionDone

	stopErr := make(chan error, 1)
	go func() { stopErr <- c.stopSession(false) }()
	<-cancelCalled

	blockErr := make(chan error, 1)
	go func() { blockErr <- c.Block(newIP) }()
	select {
	case err := <-blockErr:
		t.Fatalf("new session refreshed before old restore completed: %v", err)
	case <-time.After(150 * time.Millisecond):
	}

	sessionDone <- sessionResult{name: "spoofer"}
	select {
	case err := <-blockErr:
		t.Fatalf("new session refreshed before relay stopped: %v", err)
	case <-time.After(150 * time.Millisecond):
	}
	sessionDone <- sessionResult{name: "relay"}
	if err := <-stopErr; err != nil {
		t.Fatal(err)
	}
	if err := <-blockErr; err != nil {
		t.Fatal(err)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestStopAllReturnsSpooferRestoreErrorAndKeepsStateForRetry(t *testing.T) {
	restoreErr := errors.New("restore send failed")
	c := newSyntheticController(t)
	h := newFailAfterSendHandle(4, restoreErr)
	c.spoofer = engine.NewSpoofer(h, c.table)
	c.relay = engine.NewRelay(noopHandle{}, c.iface, c.gwIP, c.gwMAC, c.table, c.enforcer)
	c.started = false
	ip := "192.168.1.50"
	if err := c.Block(ip); err != nil {
		t.Fatal(err)
	}
	h.waitForSends(t, 4)

	err := c.StopAll()
	if !errors.Is(err, restoreErr) {
		t.Fatalf("StopAll error = %v, want restore send error", err)
	}
	if _, ok := c.managed[ip]; !ok {
		t.Fatal("managed state should remain after restore failure so stop can be retried")
	}
	h.failAfter.Store(1000)
	if err := c.StopAll(); err != nil {
		t.Fatal(err)
	}
	if len(c.managed) != 0 || len(c.filtered) != 0 || len(c.undo) != 0 {
		t.Fatalf("retry left managed=%d filtered=%d undo=%d", len(c.managed), len(c.filtered), len(c.undo))
	}
}

func TestReleaseReturnsRestoreDeviceErrorAndKeepsStateForRetry(t *testing.T) {
	restoreErr := errors.New("restore device failed")
	c := newSyntheticController(t)
	ip := "192.168.1.50"
	otherIP := "192.168.1.60"
	c.table.Upsert(engine.Device{IP: net.ParseIP(otherIP), MAC: mustMAC(t, "00:11:22:33:44:88")})
	h := newFailAfterSendHandle(0, restoreErr)
	c.spoofer = engine.NewSpoofer(h, c.table)
	c.managed[ip] = policyState{blocked: true}
	c.managed[otherIP] = policyState{blocked: true}
	c.spoofer.Update(c.spoofConfig())

	err := c.Release(ip)
	if !errors.Is(err, restoreErr) {
		t.Fatalf("Release error = %v, want restore device error", err)
	}
	if _, ok := c.managed[ip]; !ok {
		t.Fatal("managed state should remain after restore-device failure so release can be retried")
	}
	h.failAfter.Store(1000)
	if err := c.Release(ip); err != nil {
		t.Fatal(err)
	}
	if _, ok := c.managed[ip]; ok {
		t.Fatal("managed state should be cleared after successful retry")
	}
	if _, ok := c.managed[otherIP]; !ok {
		t.Fatal("release retry should leave other managed devices intact")
	}
}

func TestStopAllConcurrentBlockDoesNotClearNewEnforcement(t *testing.T) {
	c := newSyntheticController(t)
	ip := "192.168.1.50"
	addr := netip.MustParseAddr(ip)
	allowBlock := make(chan struct{})
	close(allowBlock)
	spy := &blockingEnforcer{
		base:            enforce.NewUserspace(),
		allowBlock:      allowBlock,
		clearAllEntered: make(chan struct{}, 1),
		allowClearAll:   make(chan struct{}),
	}
	c.enforcer = spy

	stopErr := make(chan error, 1)
	go func() {
		stopErr <- c.StopAll()
	}()
	<-spy.clearAllEntered

	blockErr := make(chan error, 1)
	go func() {
		blockErr <- c.Block(ip)
	}()
	blockCompletedBeforeClearAll := false
	select {
	case err := <-blockErr:
		if err != nil {
			t.Fatal(err)
		}
		blockCompletedBeforeClearAll = true
	case <-time.After(200 * time.Millisecond):
	}
	close(spy.allowClearAll)

	if err := <-stopErr; err != nil {
		t.Fatal(err)
	}
	if !blockCompletedBeforeClearAll {
		if err := <-blockErr; err != nil {
			t.Fatal(err)
		}
	}
	if !c.managed[ip].blocked {
		t.Fatal("new block should remain in controller state after racing StopAll")
	}
	if drop, _ := c.enforcer.Decide(addr, engine.Upload, 1000); !drop {
		t.Fatal("new block should remain in lower-layer enforcement after racing StopAll")
	}
}

func TestCloseReturnsClearAllErrorAndStillClosesHandles(t *testing.T) {
	clearErr := errors.New("clear all failed")
	handle := &recordingHandle{}
	relayHandle := &recordingHandle{}
	c := newSyntheticController(t)
	c.handle = handle
	c.relayHandle = relayHandle
	c.enforcer = &failingClearAllEnforcer{base: enforce.NewUserspace(), err: clearErr}

	err := c.Close()
	if !errors.Is(err, clearErr) {
		t.Fatalf("Close error = %v, want clear all error", err)
	}
	if !handle.closed || !relayHandle.closed {
		t.Fatalf("Close did not close handles: handle=%v relay=%v", handle.closed, relayHandle.closed)
	}
	if len(c.managed) != 0 || len(c.filtered) != 0 || len(c.undo) != 0 {
		t.Fatalf("Close left managed=%d filtered=%d undo=%d", len(c.managed), len(c.filtered), len(c.undo))
	}
}

func TestReleaseReturnsGuardEndErrorWhenLastTargetCleared(t *testing.T) {
	guardErr := errors.New("restore redirects failed")
	c := newSyntheticController(t)
	c.guard = failingGuard{err: guardErr}
	if err := c.Block("192.168.1.50"); err != nil {
		t.Fatal(err)
	}

	err := c.Release("192.168.1.50")
	if !errors.Is(err, guardErr) {
		t.Fatalf("Release error = %v, want guard end error", err)
	}
}

func TestRunSessionTaskRunsPanicCleanup(t *testing.T) {
	cleanupErr := errors.New("cleanup failed")
	cleanupCalled := false
	err := runSessionTask("spoofer", func() error {
		panic("boom")
	}, func() error {
		cleanupCalled = true
		return cleanupErr
	})
	if !cleanupCalled {
		t.Fatal("panic cleanup was not called")
	}
	if !errors.Is(err, cleanupErr) {
		t.Fatalf("runSessionTask error = %v, want cleanup error", err)
	}
}

func TestCloseRejectsLaterMutations(t *testing.T) {
	c := newSyntheticController(t)
	c.handle = noopHandle{}
	c.relayHandle = noopHandle{}

	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	checks := []struct {
		name string
		run  func() error
	}{
		{name: "block", run: func() error { return c.Block("192.168.1.50") }},
		{name: "temporary block", run: func() error { return c.BlockFor("192.168.1.50", time.Minute) }},
		{name: "filter", run: func() error { return c.SetFilter("192.168.1.50", rules.DevicePolicy{EnabledPacks: []string{"ads"}}) }},
		{name: "pack", run: func() error { return c.SetPack([]string{"192.168.1.50"}, "ads", true) }},
		{name: "release", run: func() error { return c.Release("192.168.1.50") }},
	}
	for _, check := range checks {
		if err := check.run(); err == nil {
			t.Fatalf("%s after close should be rejected", check.name)
		}
	}
	if len(c.managed) != 0 || len(c.filtered) != 0 || c.started {
		t.Fatalf("closed controller mutated state: started=%v managed=%d filtered=%d", c.started, len(c.managed), len(c.filtered))
	}
}

func preflightChecksByID(checks []PreflightCheck) map[string]PreflightCheck {
	out := make(map[string]PreflightCheck, len(checks))
	for _, c := range checks {
		out[c.ID] = c
	}
	return out
}

func actionPreviewDevicesByIP(devices []ActionPreviewDevice) map[string]ActionPreviewDevice {
	out := make(map[string]ActionPreviewDevice, len(devices))
	for _, d := range devices {
		out[d.IP] = d
	}
	return out
}

func newSyntheticController(t *testing.T) *Controller {
	t.Helper()
	table := engine.NewTable()
	table.Upsert(engine.Device{IP: net.ParseIP("192.168.1.50"), MAC: mustMAC(t, "00:11:22:33:44:77")})
	packMgr := filter.NewManager()
	enforcer := enforce.NewUserspace()
	return &Controller{
		iface:      engine.Interface{Name: "en0", IP: net.ParseIP("192.168.1.10"), MAC: mustMAC(t, "00:11:22:33:44:aa")},
		gwIP:       net.ParseIP("192.168.1.1"),
		gwMAC:      mustMAC(t, "00:11:22:33:44:55"),
		table:      table,
		enforcer:   enforcer,
		filter:     packMgr.Filter(),
		packMgr:    packMgr,
		spoofer:    engine.NewSpoofer(noopHandle{}, table),
		relay:      engine.NewRelay(noopHandle{}, engine.Interface{Name: "en0", IP: net.ParseIP("192.168.1.10"), MAC: mustMAC(t, "00:11:22:33:44:aa")}, net.ParseIP("192.168.1.1"), mustMAC(t, "00:11:22:33:44:55"), table, enforcer),
		guard:      noopGuard{},
		managed:    make(map[string]policyState),
		filtered:   make(map[string]rules.DevicePolicy),
		undo:       make(map[string]policySnapshot),
		generation: make(map[string]uint64),
		timers:     make(map[string]*time.Timer),
		started:    true,
	}
}

func containsString(values []string, needle string) bool {
	for _, value := range values {
		if value == needle {
			return true
		}
	}
	return false
}

type noopHandle struct{}

func (noopHandle) Send([]byte) error              { return nil }
func (noopHandle) Recv() (gopacket.Packet, error) { return nil, errors.New("empty") }
func (noopHandle) SetBPF(string) error            { return nil }
func (noopHandle) Close() error                   { return nil }

type recordingHandle struct {
	noopHandle
	closed bool
}

func (h *recordingHandle) Close() error {
	h.closed = true
	return nil
}

type blockingRestoreHandle struct {
	noopHandle
	blockAfter int64
	sends      atomic.Int64
	blocked    chan struct{}
	release    chan struct{}
}

func newBlockingRestoreHandle(blockAfter int64) *blockingRestoreHandle {
	return &blockingRestoreHandle{
		blockAfter: blockAfter,
		blocked:    make(chan struct{}),
		release:    make(chan struct{}),
	}
}

func (h *blockingRestoreHandle) Send([]byte) error {
	n := h.sends.Add(1)
	if n > h.blockAfter {
		select {
		case <-h.blocked:
		default:
			close(h.blocked)
		}
		<-h.release
	}
	return nil
}

func (h *blockingRestoreHandle) waitForSends(t *testing.T, want int64) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for h.sends.Load() < want {
		if time.Now().After(deadline) {
			t.Fatalf("send count = %d, want at least %d", h.sends.Load(), want)
		}
		time.Sleep(time.Millisecond)
	}
}

func (h *blockingRestoreHandle) waitForBlockedRestore(t *testing.T) {
	t.Helper()
	select {
	case <-h.blocked:
	case <-time.After(time.Second):
		t.Fatal("restore send did not block")
	}
}

func (h *blockingRestoreHandle) releaseRestore() {
	close(h.release)
}

type failAfterSendHandle struct {
	noopHandle
	failAfter atomic.Int64
	sends     atomic.Int64
	err       error
}

func newFailAfterSendHandle(failAfter int64, err error) *failAfterSendHandle {
	h := &failAfterSendHandle{err: err}
	h.failAfter.Store(failAfter)
	return h
}

func (h *failAfterSendHandle) Send([]byte) error {
	n := h.sends.Add(1)
	if n > h.failAfter.Load() {
		return h.err
	}
	return nil
}

func (h *failAfterSendHandle) waitForSends(t *testing.T, want int64) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for h.sends.Load() < want {
		if time.Now().After(deadline) {
			t.Fatalf("send count = %d, want at least %d", h.sends.Load(), want)
		}
		time.Sleep(time.Millisecond)
	}
}

func (noopGuard) Begin() error { return nil }
func (noopGuard) End() error   { return nil }

type noopGuard struct{}

type failingGuard struct {
	err error
}

func (f failingGuard) Begin() error { return nil }
func (f failingGuard) End() error   { return f.err }

type blockingPolicyFilter struct {
	base         *filter.Filter
	setEntered   chan struct{}
	allowSet     chan struct{}
	clearEntered chan struct{}
}

func (f *blockingPolicyFilter) SetPolicy(ip netip.Addr, p rules.DevicePolicy) {
	select {
	case f.setEntered <- struct{}{}:
	default:
	}
	<-f.allowSet
	f.base.SetPolicy(ip, p)
}

func (f *blockingPolicyFilter) ClearPolicy(ip netip.Addr) {
	select {
	case f.clearEntered <- struct{}{}:
	default:
	}
	f.base.ClearPolicy(ip)
}

func (f *blockingPolicyFilter) ClearAll() {
	f.base.ClearAll()
}

func (f *blockingPolicyFilter) InspectFlow(device netip.Addr, dir engine.Direction, udp bool, srcPort, dstPort uint16, payload []byte) engine.FlowAction {
	return f.base.InspectFlow(device, dir, udp, srcPort, dstPort, payload)
}

type blockingEnforcer struct {
	base            *enforce.Userspace
	blockEntered    chan struct{}
	allowBlock      chan struct{}
	clearEntered    chan struct{}
	allowClear      chan struct{}
	clearAllEntered chan struct{}
	allowClearAll   chan struct{}
}

type failingClearAllEnforcer struct {
	base *enforce.Userspace
	err  error
}

func (e *failingClearAllEnforcer) Block(ip netip.Addr) error { return e.base.Block(ip) }

func (e *failingClearAllEnforcer) Throttle(ip netip.Addr, upKbps, downKbps int) error {
	return e.base.Throttle(ip, upKbps, downKbps)
}

func (e *failingClearAllEnforcer) Pause(ip netip.Addr) error { return e.base.Pause(ip) }

func (e *failingClearAllEnforcer) Resume(ip netip.Addr) error { return e.base.Resume(ip) }

func (e *failingClearAllEnforcer) Clear(ip netip.Addr) error { return e.base.Clear(ip) }

func (e *failingClearAllEnforcer) ClearAll() error { return e.err }

func (e *failingClearAllEnforcer) Decide(device netip.Addr, dir engine.Direction, length int) (bool, time.Duration) {
	return e.base.Decide(device, dir, length)
}

func (e *blockingEnforcer) Block(ip netip.Addr) error {
	select {
	case e.blockEntered <- struct{}{}:
	default:
	}
	if e.allowBlock != nil {
		<-e.allowBlock
	}
	return e.base.Block(ip)
}

func (e *blockingEnforcer) Throttle(ip netip.Addr, upKbps, downKbps int) error {
	return e.base.Throttle(ip, upKbps, downKbps)
}

func (e *blockingEnforcer) Pause(ip netip.Addr) error {
	return e.base.Pause(ip)
}

func (e *blockingEnforcer) Resume(ip netip.Addr) error {
	return e.base.Resume(ip)
}

func (e *blockingEnforcer) Clear(ip netip.Addr) error {
	select {
	case e.clearEntered <- struct{}{}:
	default:
	}
	if e.allowClear != nil {
		<-e.allowClear
	}
	return e.base.Clear(ip)
}

func (e *blockingEnforcer) ClearAll() error {
	select {
	case e.clearAllEntered <- struct{}{}:
	default:
	}
	if e.allowClearAll != nil {
		<-e.allowClearAll
	}
	return e.base.ClearAll()
}

func (e *blockingEnforcer) Decide(device netip.Addr, dir engine.Direction, length int) (bool, time.Duration) {
	return e.base.Decide(device, dir, length)
}

func mustMAC(t *testing.T, s string) net.HardwareAddr {
	t.Helper()
	mac, err := net.ParseMAC(s)
	if err != nil {
		t.Fatal(err)
	}
	return mac
}

func addScannedDevices(t *testing.T, c *Controller, n int) []string {
	t.Helper()
	ips := make([]string, 0, n)
	for i := 0; i < n; i++ {
		ip := net.IPv4(192, 168, 1, byte(50+i)).String()
		mac := net.HardwareAddr{0x00, 0x11, 0x22, 0x33, byte(i >> 8), byte(i)}
		c.table.Upsert(engine.Device{IP: net.ParseIP(ip), MAC: mac})
		ips = append(ips, ip)
	}
	return ips
}
