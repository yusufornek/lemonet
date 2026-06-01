// Package server exposes the controller over a loopback-only HTTP API and serves the embedded
// web panel. Every API call must carry the per-launch capability token, and Host/Origin are
// validated to defend against DNS rebinding and cross-site requests.
package server

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"io/fs"
	"net/http"
	"strings"
	"time"

	"github.com/yusufornek/lemonet/internal/config"
	"github.com/yusufornek/lemonet/internal/control"
	"github.com/yusufornek/lemonet/internal/filter/rules"
)

type Server struct {
	token   string
	version string
	ctrl    *control.Controller
	static  fs.FS
	iface   string
	selfIP  string
}

func New(token, version string, ctrl *control.Controller, static fs.FS, iface, selfIP string) *Server {
	return &Server{token: token, version: version, ctrl: ctrl, static: static, iface: iface, selfIP: selfIP}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/state", s.handleState)
	mux.HandleFunc("/api/consent", s.handleConsent)
	mux.HandleFunc("/api/scan", s.handleScan)
	mux.HandleFunc("/api/devices", s.handleDevices)
	mux.HandleFunc("/api/device", s.handleDevice)
	mux.HandleFunc("/api/packs", s.handlePacks)
	mux.HandleFunc("/api/filter", s.handleFilter)
	mux.HandleFunc("/api/rules/add", s.handleRuleAdd)
	mux.HandleFunc("/api/rules/remove", s.handleRuleRemove)
	mux.HandleFunc("/api/packs/set", s.handlePackSet)
	mux.HandleFunc("/api/packs/refresh", s.handlePackRefresh)
	mux.HandleFunc("/api/toggles/set", s.handleTogglesSet)
	mux.HandleFunc("/api/stop", s.handleStop)
	mux.HandleFunc("/api/events", s.handleEvents)
	mux.Handle("/", http.FileServer(http.FS(s.static)))
	return s.secure(mux)
}

// secure enforces loopback Host, the capability token on API routes, and same-origin on
// state-changing requests. Static assets are served without the token since they carry no data.
func (s *Server) secure(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !loopbackHost(r.Host) {
			http.Error(w, "forbidden host", http.StatusForbidden)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/api/") {
			if !s.tokenOK(r) {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
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

func (s *Server) tokenOK(r *http.Request) bool {
	got := r.Header.Get("X-Lemonet-Token")
	if got == "" {
		got = strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	}
	if got == "" {
		// EventSource cannot set headers, so SSE passes the token as a query parameter.
		got = r.URL.Query().Get("token")
	}
	return subtle.ConstantTimeCompare([]byte(got), []byte(s.token)) == 1
}

func sameOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true // non-browser client; token already authenticated it
	}
	return origin == "http://"+r.Host
}

func loopbackHost(host string) bool {
	h := host
	if i := strings.LastIndex(host, ":"); i >= 0 {
		h = host[:i]
	}
	h = strings.Trim(h, "[]")
	return h == "127.0.0.1" || h == "localhost" || h == "::1"
}

func (s *Server) handleState(w http.ResponseWriter, _ *http.Request) {
	consent, _ := config.LoadConsent()
	gwIP, _ := s.ctrl.Gateway()
	writeJSON(w, map[string]any{
		"version":   s.version,
		"consent":   consent.Accepted,
		"interface": s.iface,
		"selfIP":    s.selfIP,
		"gateway":   gwIP.String(),
	})
}

func (s *Server) handleConsent(w http.ResponseWriter, _ *http.Request) {
	if err := config.SaveConsent(s.version); err != nil {
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

func (s *Server) handleDevice(w http.ResponseWriter, r *http.Request) {
	var req struct {
		IP       string `json:"ip"`
		Action   string `json:"action"`
		UpKbps   int    `json:"upKbps"`
		DownKbps int    `json:"downKbps"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	var err error
	switch req.Action {
	case "block":
		err = s.ctrl.Block(req.IP)
	case "throttle":
		err = s.ctrl.Throttle(req.IP, req.UpKbps, req.DownKbps)
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

func (s *Server) handleRuleAdd(w http.ResponseWriter, r *http.Request) {
	var req struct {
		IPs    []string `json:"ips"`
		Action string   `json:"action"`
		Domain string   `json:"domain"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
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
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if err := s.ctrl.RemoveRule(req.IPs, req.Action, req.Domain); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, s.ctrl.Devices())
}

func (s *Server) handlePackSet(w http.ResponseWriter, r *http.Request) {
	var req struct {
		IPs     []string `json:"ips"`
		PackID  string   `json:"packId"`
		Enabled bool     `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
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
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if err := s.ctrl.RefreshPack(req.PackID); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, s.ctrl.Packs())
}

func (s *Server) handleTogglesSet(w http.ResponseWriter, r *http.Request) {
	var req struct {
		IPs     []string `json:"ips"`
		Key     string   `json:"key"`
		Enabled bool     `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if err := s.ctrl.SetToggle(req.IPs, req.Key, req.Enabled); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, s.ctrl.Devices())
}

func (s *Server) handleStop(w http.ResponseWriter, _ *http.Request) {
	if err := s.ctrl.StopAll(); err != nil {
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
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
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
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-ticker.C:
			b, _ := json.Marshal(s.ctrl.Devices())
			if _, err := w.Write([]byte("data: " + string(b) + "\n\n")); err != nil {
				return
			}
			flusher.Flush()
		}
	}
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
