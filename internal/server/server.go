// Package server exposes the controller over a loopback-only HTTP API and serves the embedded
// web panel. Every API call must carry the per-launch capability token, and Host/Origin are
// validated to defend against DNS rebinding and cross-site requests.
package server

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"log"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/html"

	"github.com/yusufornek/lemonet/internal/config"
	"github.com/yusufornek/lemonet/internal/control"
	"github.com/yusufornek/lemonet/internal/filter/rules"
)

type Server struct {
	token           string
	version         string
	ctrl            *control.Controller
	static          fs.FS
	iface           string
	selfIP          string
	stopAll         func() error
	consentAccepted func() bool
	saveConsent     func() error
	cspOnce         sync.Once
	csp             string
}

func New(token, version string, ctrl *control.Controller, static fs.FS, iface, selfIP string) *Server {
	return &Server{
		token:           token,
		version:         version,
		ctrl:            ctrl,
		static:          static,
		iface:           iface,
		selfIP:          selfIP,
		stopAll:         ctrl.StopAll,
		consentAccepted: consentAccepted(version),
		saveConsent:     func() error { return config.SaveConsent(version) },
	}
}

const maxJSONBody = 64 << 10

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	// Read endpoints are GET; every state-changing endpoint is POST-only so a GET-with-body cannot
	// reach it and slip past the same-origin check (which secure() applies to non-GET requests).
	mux.HandleFunc("GET /api/state", s.handleState)
	mux.HandleFunc("GET /api/devices", s.handleDevices)
	mux.HandleFunc("GET /api/diagnostics", s.handleDiagnostics)
	mux.HandleFunc("GET /api/preflight", s.handlePreflight)
	mux.HandleFunc("GET /api/packs", s.handlePacks)
	mux.HandleFunc("GET /api/profiles", s.handleProfiles)
	mux.HandleFunc("GET /api/events", s.handleEvents)
	mux.HandleFunc("POST /api/consent", s.handleConsent)
	mux.HandleFunc("POST /api/scan", s.handleScan)
	mux.HandleFunc("POST /api/device", s.handleDevice)
	mux.HandleFunc("POST /api/filter", s.handleFilter)
	mux.HandleFunc("POST /api/profiles/apply", s.handleProfileApply)
	mux.HandleFunc("POST /api/devices/action/preview", s.handleActionPreview)
	mux.HandleFunc("POST /api/policy/export", s.handlePolicyExport)
	mux.HandleFunc("POST /api/policy/import", s.handlePolicyImport)
	mux.HandleFunc("POST /api/device/undo", s.handleUndo)
	mux.HandleFunc("POST /api/rules/add", s.handleRuleAdd)
	mux.HandleFunc("POST /api/rules/remove", s.handleRuleRemove)
	mux.HandleFunc("POST /api/rules/explain", s.handleRuleExplain)
	mux.HandleFunc("POST /api/packs/set", s.handlePackSet)
	mux.HandleFunc("POST /api/packs/refresh", s.handlePackRefresh)
	mux.HandleFunc("POST /api/toggles/set", s.handleTogglesSet)
	mux.HandleFunc("POST /api/stop", s.handleStop)
	mux.Handle("/", http.FileServer(http.FS(s.static)))
	return s.secure(mux)
}

// secure enforces loopback Host, the capability token on API routes, and same-origin on
// state-changing requests. Static assets are served without the token since they carry no data.
func (s *Server) secure(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.setBrowserHardeningHeaders(w)
		if !loopbackHost(r.Host) {
			http.Error(w, "forbidden host", http.StatusForbidden)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/api/") {
			w.Header().Set("Cache-Control", "no-store")
			if !s.tokenOK(r) {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			if s.requiresConsent(r.URL.Path) && !s.consentOK() {
				http.Error(w, "consent required", http.StatusForbidden)
				return
			}
			if r.Method != http.MethodGet && !sameOrigin(r) {
				http.Error(w, "bad origin", http.StatusForbidden)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) setBrowserHardeningHeaders(w http.ResponseWriter) {
	w.Header().Set("Content-Security-Policy", s.contentSecurityPolicy())
	w.Header().Set("Cross-Origin-Opener-Policy", "same-origin")
	w.Header().Set("Cross-Origin-Resource-Policy", "same-origin")
	w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=()")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
}

func (s *Server) contentSecurityPolicy() string {
	if s == nil {
		return buildContentSecurityPolicy("")
	}
	s.cspOnce.Do(func() {
		var html string
		if s.static != nil {
			if b, err := fs.ReadFile(s.static, "index.html"); err == nil {
				html = string(b)
			}
		}
		s.csp = buildContentSecurityPolicy(html)
	})
	return s.csp
}

func buildContentSecurityPolicy(html string) string {
	styleSrc := cspDirective("style-src", inlineCSPHashes(html, "style"))
	scriptSrc := cspDirective("script-src", inlineCSPHashes(html, "script"))
	return strings.Join([]string{
		"default-src 'self'",
		"connect-src 'self'",
		"img-src 'self' data:",
		styleSrc,
		scriptSrc,
		"object-src 'none'",
		"base-uri 'none'",
		"form-action 'none'",
		"frame-ancestors 'none'",
	}, "; ")
}

func cspDirective(name string, hashes []string) string {
	parts := []string{name, "'self'"}
	parts = append(parts, hashes...)
	return strings.Join(parts, " ")
}

func inlineCSPHashes(markup, tag string) []string {
	root, err := html.Parse(strings.NewReader(markup))
	if err != nil {
		return nil
	}
	var hashes []string
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode && strings.EqualFold(n.Data, tag) {
			sum := sha256.Sum256([]byte(nodeText(n)))
			hashes = append(hashes, "'sha256-"+base64.StdEncoding.EncodeToString(sum[:])+"'")
			return
		}
		for child := n.FirstChild; child != nil; child = child.NextSibling {
			walk(child)
		}
	}
	walk(root)
	return hashes
}

func nodeText(n *html.Node) string {
	var b strings.Builder
	for child := n.FirstChild; child != nil; child = child.NextSibling {
		if child.Type == html.TextNode {
			b.WriteString(child.Data)
		}
	}
	return b.String()
}

func (s *Server) requiresConsent(path string) bool {
	return path != "/api/state" && path != "/api/consent" && path != "/api/packs"
}

func (s *Server) consentOK() bool {
	return s.consentAccepted != nil && s.consentAccepted()
}

func consentAccepted(version string) func() bool {
	return func() bool {
		consent, err := config.LoadConsent()
		return err == nil && consent.Accepted && consent.Version == version
	}
}

func (s *Server) tokenOK(r *http.Request) bool {
	if s.token == "" {
		return false
	}
	got := r.Header.Get("X-Lemonet-Token")
	if got == "" {
		got = strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	}
	if got == "" && r.URL.Path == "/api/events" {
		// EventSource cannot set headers, so SSE passes the token as a query parameter.
		got = r.URL.Query().Get("token")
	}
	return subtle.ConstantTimeCompare([]byte(got), []byte(s.token)) == 1
}

func sameOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		origin = r.Header.Get("X-Lemonet-Origin")
	}
	if origin == "" {
		return false
	}
	u, err := url.Parse(origin)
	if err != nil || u.Scheme != "http" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return false
	}
	originHost, originPort, ok := parseHTTPAuthority(u.Host)
	if !ok || !loopbackAuthorityHost(originHost) {
		return false
	}
	requestHost, requestPort, ok := parseHTTPAuthority(r.Host)
	if !ok || !loopbackAuthorityHost(requestHost) {
		return false
	}
	return sameAuthorityHost(originHost, requestHost) && originPort == requestPort
}

func loopbackHost(host string) bool {
	h, _, ok := parseHTTPAuthority(host)
	return ok && loopbackAuthorityHost(h)
}

func parseHTTPAuthority(authority string) (string, string, bool) {
	if authority == "" {
		return "", "", false
	}
	host := authority
	port := ""
	if strings.HasPrefix(authority, "[") {
		end := strings.LastIndex(authority, "]")
		if end < 0 {
			return "", "", false
		}
		host = authority[1:end]
		rest := authority[end+1:]
		if rest != "" {
			if !strings.HasPrefix(rest, ":") || !validHostPort(rest[1:]) {
				return "", "", false
			}
			port = rest[1:]
		}
	} else if strings.Contains(authority, ":") {
		parsedHost, parsedPort, err := net.SplitHostPort(authority)
		if err != nil || !validHostPort(parsedPort) {
			return "", "", false
		}
		host = parsedHost
		port = parsedPort
	}
	if host == "" {
		return "", "", false
	}
	if port == "" {
		port = "80"
	}
	return host, port, true
}

func loopbackAuthorityHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	addr, err := netip.ParseAddr(host)
	return err == nil && addr.IsLoopback()
}

func sameAuthorityHost(a, b string) bool {
	if strings.EqualFold(a, "localhost") || strings.EqualFold(b, "localhost") {
		return strings.EqualFold(a, b)
	}
	left, leftErr := netip.ParseAddr(a)
	right, rightErr := netip.ParseAddr(b)
	return leftErr == nil && rightErr == nil && left == right
}

func validHostPort(port string) bool {
	n, err := strconv.Atoi(port)
	return err == nil && n > 0 && n <= 65535
}

func (s *Server) handleState(w http.ResponseWriter, _ *http.Request) {
	gwIP, _ := s.ctrl.Gateway()
	writeJSON(w, map[string]any{
		"version":   s.version,
		"consent":   s.consentOK(),
		"interface": s.iface,
		"selfIP":    s.selfIP,
		"gateway":   gwIP.String(),
	})
}

func (s *Server) handleConsent(w http.ResponseWriter, _ *http.Request) {
	if err := s.saveConsent(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]bool{"accepted": true})
}

func (s *Server) handleScan(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()
	devices, err := s.ctrl.Scan(ctx)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, devices)
}

func (s *Server) handleDevices(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, s.ctrl.Devices())
}

func (s *Server) handleDiagnostics(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, s.ctrl.Diagnostics())
}

func (s *Server) handlePreflight(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, s.ctrl.Preflight())
}

func (s *Server) handleDevice(w http.ResponseWriter, r *http.Request) {
	var req struct {
		IP              string `json:"ip"`
		Action          string `json:"action"`
		UpKbps          int    `json:"upKbps"`
		DownKbps        int    `json:"downKbps"`
		DurationSeconds int    `json:"durationSeconds"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.DurationSeconds < 0 {
		http.Error(w, "duration must be non-negative", http.StatusBadRequest)
		return
	}
	if req.DurationSeconds > 0 {
		if req.Action != "block" && req.Action != "throttle" {
			http.Error(w, "duration is only supported for block and throttle", http.StatusBadRequest)
			return
		}
		if req.DurationSeconds > int(control.MaxTemporaryControlDuration/time.Second) {
			http.Error(w, "duration is too long", http.StatusBadRequest)
			return
		}
	}

	var err error
	duration := time.Duration(req.DurationSeconds) * time.Second
	switch req.Action {
	case "block":
		if req.DurationSeconds > 0 {
			err = s.ctrl.BlockFor(req.IP, duration)
		} else {
			err = s.ctrl.Block(req.IP)
		}
	case "throttle":
		if req.DurationSeconds > 0 {
			err = s.ctrl.ThrottleFor(req.IP, req.UpKbps, req.DownKbps, duration)
		} else {
			err = s.ctrl.Throttle(req.IP, req.UpKbps, req.DownKbps)
		}
	case "pause":
		err = s.ctrl.Pause(req.IP)
	case "resume":
		err = s.ctrl.Resume(req.IP)
	case "release":
		err = s.ctrl.Release(req.IP)
	default:
		http.Error(w, "unknown action", http.StatusBadRequest)
		return
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, s.ctrl.Devices())
}

func (s *Server) handlePacks(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, s.ctrl.Packs())
}

func (s *Server) handleProfiles(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, s.ctrl.Profiles())
}

func (s *Server) handleProfileApply(w http.ResponseWriter, r *http.Request) {
	var req struct {
		IPs       []string `json:"ips"`
		ProfileID string   `json:"profileId"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	if err := s.ctrl.ApplyProfile(req.IPs, req.ProfileID); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, s.ctrl.Devices())
}

func (s *Server) handleActionPreview(w http.ResponseWriter, r *http.Request) {
	var req struct {
		IPs    []string `json:"ips"`
		Action string   `json:"action"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	writeJSON(w, s.ctrl.PreviewAction(req.IPs, req.Action))
}

func (s *Server) handlePolicyExport(w http.ResponseWriter, r *http.Request) {
	var req struct {
		IP string `json:"ip"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	template, err := s.ctrl.ExportPolicy(req.IP)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, template)
}

func (s *Server) handlePolicyImport(w http.ResponseWriter, r *http.Request) {
	var req struct {
		IPs    []string               `json:"ips"`
		Policy control.PolicyTemplate `json:"policy"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	if err := s.ctrl.ImportPolicy(req.IPs, req.Policy); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, s.ctrl.Devices())
}

func (s *Server) handleUndo(w http.ResponseWriter, r *http.Request) {
	var req struct {
		IPs []string `json:"ips"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	if err := s.ctrl.Undo(req.IPs); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, s.ctrl.Devices())
}

func (s *Server) handleRuleAdd(w http.ResponseWriter, r *http.Request) {
	var req struct {
		IPs    []string `json:"ips"`
		Action string   `json:"action"`
		Domain string   `json:"domain"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	if err := s.ctrl.AddRule(req.IPs, req.Action, req.Domain); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, s.ctrl.Devices())
}

func (s *Server) handleRuleRemove(w http.ResponseWriter, r *http.Request) {
	var req struct {
		IPs    []string `json:"ips"`
		Action string   `json:"action"`
		Domain string   `json:"domain"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	if err := s.ctrl.RemoveRule(req.IPs, req.Action, req.Domain); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, s.ctrl.Devices())
}

func (s *Server) handleRuleExplain(w http.ResponseWriter, r *http.Request) {
	var req struct {
		IP     string `json:"ip"`
		Domain string `json:"domain"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	decision, err := s.ctrl.Explain(req.IP, req.Domain)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, decision)
}

func (s *Server) handlePackSet(w http.ResponseWriter, r *http.Request) {
	var req struct {
		IPs     []string `json:"ips"`
		PackID  string   `json:"packId"`
		Enabled bool     `json:"enabled"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	if err := s.ctrl.SetPack(req.IPs, req.PackID, req.Enabled); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, s.ctrl.Devices())
}

func (s *Server) handlePackRefresh(w http.ResponseWriter, r *http.Request) {
	var req struct {
		PackID string `json:"packId"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	// Run the (possibly slow) download in the background; the panel polls /api/packs for progress.
	go func() {
		if err := s.ctrl.RefreshPack(req.PackID); err != nil {
			log.Printf("server: refresh pack %s failed: %v", req.PackID, err)
		}
	}()
	writeJSON(w, s.ctrl.Packs())
}

func (s *Server) handleTogglesSet(w http.ResponseWriter, r *http.Request) {
	var req struct {
		IPs     []string `json:"ips"`
		Key     string   `json:"key"`
		Enabled bool     `json:"enabled"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	if err := s.ctrl.SetToggle(req.IPs, req.Key, req.Enabled); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, s.ctrl.Devices())
}

func (s *Server) handleStop(w http.ResponseWriter, _ *http.Request) {
	stopAll := s.stopAll
	if stopAll == nil && s.ctrl != nil {
		stopAll = s.ctrl.StopAll
	}
	if stopAll == nil {
		http.Error(w, "stop unavailable", http.StatusInternalServerError)
		return
	}
	if err := stopAll(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, s.ctrl.Devices())
}

func (s *Server) handleFilter(w http.ResponseWriter, r *http.Request) {
	var req struct {
		IP           string        `json:"ip"`
		EnabledPacks []string      `json:"enabledPacks"`
		CustomRules  []rules.Rule  `json:"customRules"`
		Toggles      rules.Toggles `json:"toggles"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	pol := rules.DevicePolicy{
		EnabledPacks: req.EnabledPacks,
		CustomRules:  req.CustomRules,
		Toggles:      req.Toggles,
	}
	if err := s.ctrl.SetFilter(req.IP, pol); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, s.ctrl.Devices())
}

// handleEvents streams the device list over SSE so the panel updates live without polling.
func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	clearWriteDeadline(w)
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache, no-store")
	w.Header().Set("Connection", "keep-alive")

	if !s.writeEventSnapshot(w, flusher) {
		return
	}
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-ticker.C:
			if !s.writeEventSnapshot(w, flusher) {
				return
			}
		}
	}
}

func clearWriteDeadline(w http.ResponseWriter) {
	_ = http.NewResponseController(w).SetWriteDeadline(time.Time{})
}

func (s *Server) writeEventSnapshot(w http.ResponseWriter, flusher http.Flusher) bool {
	devices := []control.DeviceView{}
	if s.ctrl != nil {
		devices = s.ctrl.Devices()
		if devices == nil {
			devices = []control.DeviceView{}
		}
	}
	b, err := json.Marshal(devices)
	if err != nil {
		return false
	}
	if _, err := w.Write([]byte("data: " + string(b) + "\n\n")); err != nil {
		return false
	}
	flusher.Flush()
	return true
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func decodeJSON(w http.ResponseWriter, r *http.Request, dst any) bool {
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		http.Error(w, "unsupported media type", http.StatusUnsupportedMediaType)
		return false
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxJSONBody)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return false
	}
	if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		http.Error(w, "bad request", http.StatusBadRequest)
		return false
	}
	return true
}
