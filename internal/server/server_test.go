package server

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"testing/fstest"
	"time"

	"github.com/yusufornek/lemonet/internal/control"
	"github.com/yusufornek/lemonet/web"
)

type eventRecorder struct {
	mu     sync.Mutex
	header http.Header
	body   strings.Builder
	code   int

	writeDeadlineSet bool
	writeDeadline    time.Time
}

type countingFS struct {
	fs.FS
	opens int
}

func (c *countingFS) Open(name string) (fs.File, error) {
	c.opens++
	return c.FS.Open(name)
}

func newEventRecorder() *eventRecorder {
	return &eventRecorder{header: make(http.Header)}
}

func (r *eventRecorder) Header() http.Header {
	return r.header
}

func (r *eventRecorder) WriteHeader(code int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.code == 0 {
		r.code = code
	}
}

func (r *eventRecorder) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.code == 0 {
		r.code = http.StatusOK
	}
	return r.body.Write(p)
}

func (r *eventRecorder) Flush() {}

func (r *eventRecorder) SetWriteDeadline(t time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.writeDeadlineSet = true
	r.writeDeadline = t
	return nil
}

func (r *eventRecorder) Code() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.code == 0 {
		return http.StatusOK
	}
	return r.code
}

func (r *eventRecorder) Body() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.body.String()
}

func (r *eventRecorder) WriteDeadline() (time.Time, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.writeDeadline, r.writeDeadlineSet
}

func TestSecureAuthAndOrigin(t *testing.T) {
	tests := []struct {
		name        string
		method      string
		path        string
		host        string
		token       string
		origin      string
		panelOrigin string
		want        int
		consent     bool
	}{
		{name: "bad host", method: http.MethodGet, path: "/api/devices", host: "evil.test", token: "secret", want: http.StatusForbidden, consent: true},
		{name: "preflight bad host", method: http.MethodGet, path: "/api/preflight", host: "evil.test", token: "secret", want: http.StatusForbidden, consent: true},
		{name: "preview bad host", method: http.MethodPost, path: "/api/devices/action/preview", host: "evil.test", token: "secret", want: http.StatusForbidden, consent: true},
		{name: "missing token", method: http.MethodGet, path: "/api/devices", host: "127.0.0.1", want: http.StatusUnauthorized, consent: true},
		{name: "preflight missing token", method: http.MethodGet, path: "/api/preflight", host: "127.0.0.1", want: http.StatusUnauthorized, consent: true},
		{name: "preview missing token", method: http.MethodPost, path: "/api/devices/action/preview", host: "127.0.0.1", want: http.StatusUnauthorized, consent: true},
		{name: "state rejects query token", method: http.MethodGet, path: "/api/state?token=secret", host: "127.0.0.1", want: http.StatusUnauthorized, consent: true},
		{name: "post rejects query token", method: http.MethodPost, path: "/api/stop?token=secret", host: "127.0.0.1", want: http.StatusUnauthorized, consent: true},
		{name: "events allow query token", method: http.MethodGet, path: "/api/events?token=secret", host: "127.0.0.1", want: http.StatusNoContent, consent: true},
		{name: "bearer token", method: http.MethodGet, path: "/api/devices", host: "127.0.0.1", token: "Bearer secret", want: http.StatusNoContent, consent: true},
		{name: "empty server token fails closed", method: http.MethodGet, path: "/api/state", host: "127.0.0.1", token: "secret", want: http.StatusUnauthorized, consent: true},
		{name: "bad origin", method: http.MethodPost, path: "/api/scan", host: "127.0.0.1", token: "secret", origin: "http://evil.test", want: http.StatusForbidden, consent: true},
		{name: "missing origin", method: http.MethodPost, path: "/api/scan", host: "127.0.0.1", token: "secret", want: http.StatusForbidden, consent: true},
		{name: "panel origin fallback", method: http.MethodPost, path: "/api/scan", host: "127.0.0.1", token: "secret", panelOrigin: "http://127.0.0.1", want: http.StatusNoContent, consent: true},
		{name: "origin overrides panel fallback", method: http.MethodPost, path: "/api/scan", host: "127.0.0.1", token: "secret", origin: "http://evil.test", panelOrigin: "http://127.0.0.1", want: http.StatusForbidden, consent: true},
		{name: "preview bad origin", method: http.MethodPost, path: "/api/devices/action/preview", host: "127.0.0.1", token: "secret", origin: "http://evil.test", want: http.StatusForbidden, consent: true},
		{name: "good origin", method: http.MethodPost, path: "/api/scan", host: "127.0.0.1", token: "secret", origin: "http://127.0.0.1", want: http.StatusNoContent, consent: true},
		{name: "consent required", method: http.MethodGet, path: "/api/devices", host: "127.0.0.1", token: "secret", want: http.StatusForbidden},
		{name: "diagnostics consent required", method: http.MethodGet, path: "/api/diagnostics", host: "127.0.0.1", token: "secret", want: http.StatusForbidden},
		{name: "preflight consent required", method: http.MethodGet, path: "/api/preflight", host: "127.0.0.1", token: "secret", want: http.StatusForbidden},
		{name: "preview consent required", method: http.MethodPost, path: "/api/devices/action/preview", host: "127.0.0.1", token: "secret", want: http.StatusForbidden},
		{name: "profiles consent required", method: http.MethodGet, path: "/api/profiles", host: "127.0.0.1", token: "secret", want: http.StatusForbidden},
		{name: "undo consent required", method: http.MethodPost, path: "/api/device/undo", host: "127.0.0.1", token: "secret", want: http.StatusForbidden},
		{name: "state before consent", method: http.MethodGet, path: "/api/state", host: "127.0.0.1", token: "secret", want: http.StatusNoContent},
		{name: "packs before consent", method: http.MethodGet, path: "/api/packs", host: "127.0.0.1", token: "secret", want: http.StatusNoContent},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token := "secret"
			if tt.name == "empty server token fails closed" {
				token = ""
			}
			s := &Server{token: token, consentAccepted: func() bool { return tt.consent }}
			h := s.secure(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusNoContent)
			}))
			req := httptest.NewRequest(tt.method, tt.path, nil)
			req.Host = tt.host
			if tt.token != "" {
				if strings.HasPrefix(tt.token, "Bearer ") {
					req.Header.Set("Authorization", tt.token)
				} else {
					req.Header.Set("X-Lemonet-Token", tt.token)
				}
			}
			if tt.origin != "" {
				req.Header.Set("Origin", tt.origin)
			}
			if tt.panelOrigin != "" {
				req.Header.Set("X-Lemonet-Origin", tt.panelOrigin)
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != tt.want {
				t.Fatalf("status = %d, want %d", rec.Code, tt.want)
			}
		})
	}
}

func TestSecureRejectsEmptyConfiguredToken(t *testing.T) {
	s := &Server{token: "", consentAccepted: func() bool { return true }}
	h := s.secure(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	req := httptest.NewRequest(http.MethodGet, "/api/state", nil)
	req.Host = "127.0.0.1"
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestSecureDisablesAPICache(t *testing.T) {
	s := &Server{token: "secret", consentAccepted: func() bool { return true }}
	h := s.secure(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	req := httptest.NewRequest(http.MethodGet, "/api/state", nil)
	req.Host = "127.0.0.1"
	req.Header.Set("X-Lemonet-Token", "secret")
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusNoContent)
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("cache control = %q, want no-store", got)
	}
}

func TestHandlerEventsDisablesCache(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := &Server{token: "secret", consentAccepted: func() bool { return true }}
	req := httptest.NewRequest(http.MethodGet, "/api/events?token=secret", nil).WithContext(ctx)
	req.Host = "127.0.0.1"
	rec := newEventRecorder()
	done := make(chan struct{})

	go func() {
		defer close(done)
		s.Handler().ServeHTTP(rec, req)
	}()

	deadline := time.After(200 * time.Millisecond)
	for {
		if strings.Contains(rec.Body(), "data: []\n\n") {
			cancel()
			<-done
			break
		}
		select {
		case <-deadline:
			cancel()
			<-done
			t.Fatal("event stream did not write an initial snapshot")
		default:
			time.Sleep(5 * time.Millisecond)
		}
	}

	if got := rec.Header().Get("Cache-Control"); got != "no-cache, no-store" {
		t.Fatalf("cache control = %q, want no-cache, no-store", got)
	}
}

func TestSameOrigin(t *testing.T) {
	tests := []struct {
		name        string
		host        string
		origin      string
		panelOrigin string
		want        bool
	}{
		{name: "localhost with port", host: "localhost:49152", origin: "http://localhost:49152", want: true},
		{name: "mixed case localhost", host: "LOCALHOST:49152", origin: "http://localhost:49152", want: true},
		{name: "ipv4 with port", host: "127.0.0.1:49152", origin: "http://127.0.0.1:49152", want: true},
		{name: "ipv6 with port", host: "[::1]:49152", origin: "http://[::1]:49152", want: true},
		{name: "default port", host: "127.0.0.1", origin: "http://127.0.0.1", want: true},
		{name: "panel origin fallback", host: "127.0.0.1:49152", panelOrigin: "http://127.0.0.1:49152", want: true},
		{name: "origin overrides panel fallback", host: "127.0.0.1:49152", origin: "http://evil.test:49152", panelOrigin: "http://127.0.0.1:49152"},
		{name: "missing origin", host: "127.0.0.1"},
		{name: "bad scheme", host: "127.0.0.1:49152", origin: "https://127.0.0.1:49152"},
		{name: "bad panel scheme", host: "127.0.0.1:49152", panelOrigin: "https://127.0.0.1:49152"},
		{name: "bad port", host: "127.0.0.1:notaport", origin: "http://127.0.0.1:notaport"},
		{name: "port mismatch", host: "127.0.0.1:49152", origin: "http://127.0.0.1:49153"},
		{name: "loopback alias mismatch", host: "localhost:49152", origin: "http://127.0.0.1:49152"},
		{name: "evil origin", host: "127.0.0.1:49152", origin: "http://evil.test:49152"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/api/scan", nil)
			req.Host = tt.host
			if tt.origin != "" {
				req.Header.Set("Origin", tt.origin)
			}
			if tt.panelOrigin != "" {
				req.Header.Set("X-Lemonet-Origin", tt.panelOrigin)
			}
			if got := sameOrigin(req); got != tt.want {
				t.Fatalf("sameOrigin(host=%q, origin=%q) = %v, want %v", tt.host, tt.origin, got, tt.want)
			}
		})
	}
}

func TestLoopbackHost(t *testing.T) {
	tests := []struct {
		host string
		want bool
	}{
		{host: "127.0.0.1", want: true},
		{host: "127.0.0.1:49152", want: true},
		{host: "localhost", want: true},
		{host: "LOCALHOST:49152", want: true},
		{host: "localhost:49152", want: true},
		{host: "[::1]", want: true},
		{host: "[::1]:49152", want: true},
		{host: "evil.test"},
		{host: "127.0.0.1.evil.test"},
		{host: "127.0.0.1:"},
		{host: "127.0.0.1:notaport"},
		{host: "localhost:notaport"},
		{host: "[::1]:notaport"},
		{host: "::1"},
	}
	for _, tt := range tests {
		t.Run(tt.host, func(t *testing.T) {
			if got := loopbackHost(tt.host); got != tt.want {
				t.Fatalf("loopbackHost(%q) = %v, want %v", tt.host, got, tt.want)
			}
		})
	}
}

func TestHandlerEventsWritesInitialSnapshot(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req := httptest.NewRequest(http.MethodGet, "/api/events", nil).WithContext(ctx)
	rec := newEventRecorder()
	done := make(chan struct{})

	go func() {
		defer close(done)
		(&Server{}).handleEvents(rec, req)
	}()

	deadline := time.After(200 * time.Millisecond)
	for {
		if strings.Contains(rec.Body(), "data: []\n\n") {
			cancel()
			<-done
			break
		}
		select {
		case <-deadline:
			cancel()
			<-done
			t.Fatalf("initial event body = %q, want empty device snapshot", rec.Body())
		default:
			time.Sleep(5 * time.Millisecond)
		}
	}

	if rec.Code() != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code(), http.StatusOK)
	}
	if got := rec.Header().Get("Content-Type"); got != "text/event-stream" {
		t.Fatalf("content type = %q, want text/event-stream", got)
	}
}

func TestHandlerEventsClearsWriteDeadline(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req := httptest.NewRequest(http.MethodGet, "/api/events", nil).WithContext(ctx)
	rec := newEventRecorder()
	done := make(chan struct{})

	go func() {
		defer close(done)
		(&Server{}).handleEvents(rec, req)
	}()

	deadline := time.After(200 * time.Millisecond)
	for {
		if strings.Contains(rec.Body(), "data: []\n\n") {
			cancel()
			<-done
			break
		}
		select {
		case <-deadline:
			cancel()
			<-done
			t.Fatal("event stream did not write an initial snapshot")
		default:
			time.Sleep(5 * time.Millisecond)
		}
	}

	got, ok := rec.WriteDeadline()
	if !ok || !got.IsZero() {
		t.Fatalf("write deadline = %v, set = %v; want cleared deadline", got, ok)
	}
}

func TestHandlerSetsBrowserHardeningHeaders(t *testing.T) {
	s := &Server{
		static: fstest.MapFS{"index.html": &fstest.MapFile{Data: []byte("ok")}},
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "127.0.0.1"
	rec := httptest.NewRecorder()

	s.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	tests := map[string]string{
		"Content-Security-Policy":      "default-src 'self'; connect-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
		"Cross-Origin-Opener-Policy":   "same-origin",
		"Cross-Origin-Resource-Policy": "same-origin",
		"Permissions-Policy":           "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
		"Referrer-Policy":              "no-referrer",
		"X-Content-Type-Options":       "nosniff",
	}
	for header, want := range tests {
		if got := rec.Header().Get(header); got != want {
			t.Fatalf("%s = %q, want %q", header, got, want)
		}
	}
}

func TestContentSecurityPolicyHashesEmbeddedPanel(t *testing.T) {
	html, err := fs.ReadFile(web.Dist(), "index.html")
	if err != nil {
		t.Fatal(err)
	}
	styleHash := cspHash(inlineBlock(t, string(html), "<style>", "</style>"))
	scriptHash := cspHash(inlineBlock(t, string(html), "<script>", "</script>"))
	s := &Server{static: web.Dist()}
	policy := s.contentSecurityPolicy()

	if strings.Contains(policy, "unsafe-inline") {
		t.Fatalf("content security policy still allows unsafe-inline: %s", policy)
	}
	for _, want := range []string{"style-src 'self' '" + styleHash + "'", "script-src 'self' '" + scriptHash + "'"} {
		if !strings.Contains(policy, want) {
			t.Fatalf("content security policy = %q, want %q", policy, want)
		}
	}
}

func TestContentSecurityPolicyHashesHTMLTagVariants(t *testing.T) {
	style := "body{color:red}"
	moduleScript := "import './panel.js';"
	plainScript := "window.ready = true;"
	html := `<!doctype html><html><head><STYLE media="screen">` + style + `</STYLE></head><body><script type="module">` + moduleScript + `</script><script>` + plainScript + `</script></body></html>`
	s := &Server{static: fstest.MapFS{"index.html": &fstest.MapFile{Data: []byte(html)}}}
	policy := s.contentSecurityPolicy()

	for _, want := range []string{
		"style-src 'self' '" + cspHash(style) + "'",
		"script-src 'self' '" + cspHash(moduleScript) + "' '" + cspHash(plainScript) + "'",
	} {
		if !strings.Contains(policy, want) {
			t.Fatalf("content security policy = %q, want %q", policy, want)
		}
	}
}

func TestContentSecurityPolicyCachesIndexHashes(t *testing.T) {
	store := &countingFS{FS: fstest.MapFS{"index.html": &fstest.MapFile{Data: []byte(`<style>body{}</style><script>window.ready=true;</script>`)}}}
	s := &Server{static: store}

	first := s.contentSecurityPolicy()
	second := s.contentSecurityPolicy()

	if first != second {
		t.Fatalf("content security policy changed between calls:\n%s\n%s", first, second)
	}
	if store.opens != 1 {
		t.Fatalf("index.html opens = %d, want 1", store.opens)
	}
}

func TestEmbeddedPanelDoesNotUseInlineStyleAttributes(t *testing.T) {
	html, err := fs.ReadFile(web.Dist(), "index.html")
	if err != nil {
		t.Fatal(err)
	}
	body := string(html)
	for _, marker := range []string{`style:`, ` style=`} {
		if strings.Contains(body, marker) {
			t.Fatalf("embedded panel uses inline style marker %q", marker)
		}
	}
}

func TestEmbeddedPanelStopUsesSharedPostHelper(t *testing.T) {
	html, err := fs.ReadFile(web.Dist(), "index.html")
	if err != nil {
		t.Fatal(err)
	}
	body := string(html)
	if strings.Contains(body, `api("/api/stop"`) {
		t.Fatal("stop button bypasses the shared POST helper")
	}
	if !strings.Contains(body, `const next = await post("/api/stop", {})`) {
		t.Fatal("stop button does not surface stop errors through the shared POST helper")
	}
}

func TestEmbeddedPanelCriticalMutationsUseSharedPostHelper(t *testing.T) {
	html, err := fs.ReadFile(web.Dist(), "index.html")
	if err != nil {
		t.Fatal(err)
	}
	body := string(html)
	for _, path := range []string{"/api/consent", "/api/scan", "/api/stop"} {
		if strings.Contains(body, `api("`+path+`"`) {
			t.Fatalf("%s bypasses the shared POST helper", path)
		}
		if !strings.Contains(body, `post("`+path+`", {}`) {
			t.Fatalf("%s does not use the shared POST helper", path)
		}
	}
	if !strings.Contains(body, `catch (err)`) || !strings.Contains(body, `Request failed`) {
		t.Fatal("shared POST helper does not surface network errors")
	}
	if !strings.Contains(body, `finally {`) {
		t.Fatal("scan path does not guarantee button state restoration")
	}
	for _, marker := range []string{
		`if (next) { setDevices(next); renderList(); } else { renderList(); }`,
		`if (d) { setDevices(d); render(); refreshPacks(); } else { render(); }`,
		`if (d) { setDevices(d); render(); } else { render(); }`,
	} {
		if !strings.Contains(body, marker) {
			t.Fatalf("embedded panel is missing failure re-render marker %q", marker)
		}
	}
}

func TestEmbeddedPanelPersistsLaunchTokenAndSendsPanelOrigin(t *testing.T) {
	html, err := fs.ReadFile(web.Dist(), "index.html")
	if err != nil {
		t.Fatal(err)
	}
	body := string(html)
	for _, marker := range []string{
		`storageGet("lemonet.token")`,
		`storageSet("lemonet.token", tok)`,
		`"X-Lemonet-Origin": location.origin`,
	} {
		if !strings.Contains(body, marker) {
			t.Fatalf("embedded panel is missing token/origin marker %q", marker)
		}
	}
}

func TestEmbeddedPanelShowsPackDomainSamples(t *testing.T) {
	html, err := fs.ReadFile(web.Dist(), "index.html")
	if err != nil {
		t.Fatal(err)
	}
	body := string(html)
	for _, marker := range []string{
		`p.sampleDomains`,
		`packDomainPreview(p)`,
		`domainExamples`,
	} {
		if !strings.Contains(body, marker) {
			t.Fatalf("embedded panel is missing pack domain transparency marker %q", marker)
		}
	}
}

func TestEmbeddedPanelShowsLearnedIPv6Addresses(t *testing.T) {
	html, err := fs.ReadFile(web.Dist(), "index.html")
	if err != nil {
		t.Fatal(err)
	}
	body := string(html)
	for _, marker := range []string{
		`function deviceAddressLine`,
		`d.ipv6 || []`,
		`IPv6 ${d.ipv6[0]}`,
	} {
		if !strings.Contains(body, marker) {
			t.Fatalf("embedded panel is missing IPv6 display marker %q", marker)
		}
	}
}

func inlineBlock(t *testing.T, html, open, close string) string {
	t.Helper()
	start := strings.Index(html, open)
	if start < 0 {
		t.Fatalf("missing %s block", open)
	}
	start += len(open)
	end := strings.Index(html[start:], close)
	if end < 0 {
		t.Fatalf("missing %s close", close)
	}
	return html[start : start+end]
}

func cspHash(content string) string {
	sum := sha256.Sum256([]byte(content))
	return "sha256-" + base64.StdEncoding.EncodeToString(sum[:])
}

func TestHandlerServesPreflight(t *testing.T) {
	s := &Server{
		token:           "secret",
		ctrl:            &control.Controller{},
		static:          fstest.MapFS{"index.html": &fstest.MapFile{Data: []byte("ok")}},
		consentAccepted: func() bool { return true },
	}
	req := httptest.NewRequest(http.MethodGet, "/api/preflight", nil)
	req.Host = "127.0.0.1"
	req.Header.Set("X-Lemonet-Token", "secret")
	rec := httptest.NewRecorder()

	s.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d: %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	var got struct {
		Ready  bool `json:"ready"`
		Checks []struct {
			ID     string `json:"id"`
			Status string `json:"status"`
		} `json:"checks"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Checks) == 0 {
		t.Fatalf("preflight checks should not be empty: %+v", got)
	}
}

func TestHandlerServesActionPreview(t *testing.T) {
	s := &Server{
		token:           "secret",
		ctrl:            &control.Controller{},
		static:          fstest.MapFS{"index.html": &fstest.MapFile{Data: []byte("ok")}},
		consentAccepted: func() bool { return true },
	}
	req := httptest.NewRequest(http.MethodPost, "/api/devices/action/preview", strings.NewReader(`{"ips":["192.168.1.50"],"action":"block"}`))
	req.Host = "127.0.0.1"
	req.Header.Set("X-Lemonet-Token", "secret")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "http://127.0.0.1")
	rec := httptest.NewRecorder()

	s.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d: %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	var got struct {
		Action string `json:"action"`
		Total  int    `json:"total"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Action != "block" || got.Total != 1 {
		t.Fatalf("preview = %+v, want block total 1", got)
	}
}

func TestHandlerAcceptsConsentWithPanelOriginFallback(t *testing.T) {
	saved := false
	s := &Server{
		token:           "secret",
		static:          fstest.MapFS{"index.html": &fstest.MapFile{Data: []byte("ok")}},
		consentAccepted: func() bool { return false },
		saveConsent: func() error {
			saved = true
			return nil
		},
	}
	req := httptest.NewRequest(http.MethodPost, "/api/consent", strings.NewReader(`{}`))
	req.Host = "127.0.0.1"
	req.Header.Set("X-Lemonet-Token", "secret")
	req.Header.Set("X-Lemonet-Origin", "http://127.0.0.1")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	s.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d: %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	if !saved {
		t.Fatal("consent was not saved")
	}
	var got struct {
		Accepted bool `json:"accepted"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if !got.Accepted {
		t.Fatalf("accepted = %v, want true", got.Accepted)
	}
}

func TestHandlerStopReturnsCleanupError(t *testing.T) {
	clearErr := errors.New("clear all failed")
	s := &Server{
		token:           "secret",
		static:          fstest.MapFS{"index.html": &fstest.MapFile{Data: []byte("ok")}},
		stopAll:         func() error { return clearErr },
		consentAccepted: func() bool { return true },
	}
	req := httptest.NewRequest(http.MethodPost, "/api/stop", nil)
	req.Host = "127.0.0.1"
	req.Header.Set("X-Lemonet-Token", "secret")
	req.Header.Set("Origin", "http://127.0.0.1")
	rec := httptest.NewRecorder()

	s.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusInternalServerError)
	}
	if !strings.Contains(rec.Body.String(), clearErr.Error()) {
		t.Fatalf("body = %q, want cleanup error", rec.Body.String())
	}
}

func TestHandlerRejectsActionPreviewUnknownField(t *testing.T) {
	s := &Server{
		token:           "secret",
		ctrl:            &control.Controller{},
		static:          fstest.MapFS{"index.html": &fstest.MapFile{Data: []byte("ok")}},
		consentAccepted: func() bool { return true },
	}
	req := httptest.NewRequest(http.MethodPost, "/api/devices/action/preview", strings.NewReader(`{"ips":["192.168.1.50"],"action":"block","extra":true}`))
	req.Host = "127.0.0.1"
	req.Header.Set("X-Lemonet-Token", "secret")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "http://127.0.0.1")
	rec := httptest.NewRecorder()

	s.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

func TestDecodeJSONStrictness(t *testing.T) {
	tests := []struct {
		name        string
		body        string
		contentType string
		want        int
	}{
		{name: "valid", body: `{"name":"router"}`, contentType: "application/json", want: http.StatusNoContent},
		{name: "json with charset", body: `{"name":"router"}`, contentType: "application/json; charset=utf-8", want: http.StatusNoContent},
		{name: "missing content type", body: `{"name":"router"}`, want: http.StatusUnsupportedMediaType},
		{name: "text content type", body: `{"name":"router"}`, contentType: "text/plain", want: http.StatusUnsupportedMediaType},
		{name: "unknown field", body: `{"name":"router","extra":true}`, contentType: "application/json", want: http.StatusBadRequest},
		{name: "trailing body", body: `{"name":"router"} {}`, contentType: "application/json", want: http.StatusBadRequest},
		{name: "oversized", body: `{"name":"` + strings.Repeat("x", maxJSONBody) + `"}`, contentType: "application/json", want: http.StatusBadRequest},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/api/test", strings.NewReader(tt.body))
			if tt.contentType != "" {
				req.Header.Set("Content-Type", tt.contentType)
			}
			rec := httptest.NewRecorder()
			var dst struct {
				Name string `json:"name"`
			}
			if decodeJSON(rec, req, &dst) {
				rec.WriteHeader(http.StatusNoContent)
			}
			if rec.Code != tt.want {
				t.Fatalf("status = %d, want %d", rec.Code, tt.want)
			}
		})
	}
}
