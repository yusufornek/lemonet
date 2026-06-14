package filter

import (
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/yusufornek/lemonet/internal/filter/rules"
)

func TestParseList(t *testing.T) {
	in := strings.NewReader("# comment\n\n0.0.0.0 ads.example\n0.0.0.0 inline.example # tracker\nplain.example\n! adblock comment\n  spaced.example  \n")
	got, err := parseList(in)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{"ads.example": true, "inline.example": true, "plain.example": true, "spaced.example": true}
	if len(got) != len(want) {
		t.Fatalf("parsed %v, want %d entries", got, len(want))
	}
	for _, d := range got {
		if !want[d] {
			t.Errorf("unexpected entry %q", d)
		}
	}
}

func TestParseListRejectsOversizedLine(t *testing.T) {
	_, err := parseList(strings.NewReader("ok.example\n" + strings.Repeat("x", 8*1024*1024+1) + "\n"))
	if err == nil {
		t.Fatal("expected oversized line to fail parsing")
	}
}

func TestFetchListWritesAndHonorsETag(t *testing.T) {
	const body = "a.example\nb.example\n"
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.Header.Get("If-None-Match") == "v1" {
			return response(http.StatusNotModified, "", nil), nil
		}
		header := make(http.Header)
		header.Set("ETag", "v1")
		return response(http.StatusOK, body, header), nil
	})}

	path := filepath.Join(t.TempDir(), "list.txt")

	if err := fetchListWithClient(client, "https://lists.test/ads.txt", path); err != nil {
		t.Fatalf("first fetch: %v", err)
	}
	got, _ := os.ReadFile(path)
	if string(got) != body {
		t.Fatalf("cached body = %q, want %q", got, body)
	}
	if etag, _ := os.ReadFile(path + ".etag"); string(etag) != "v1" {
		t.Fatalf("etag = %q, want v1", etag)
	}

	if err := fetchListWithClient(client, "https://lists.test/ads.txt", path); !errors.Is(err, errNotModified) {
		t.Fatalf("second fetch err = %v, want errNotModified", err)
	}
}

func TestFetchListBadStatus(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(_ *http.Request) (*http.Response, error) {
		return response(http.StatusNotFound, "", nil), nil
	})}
	path := filepath.Join(t.TempDir(), "list.txt")
	if err := fetchListWithClient(client, "https://lists.test/missing.txt", path); err == nil {
		t.Fatal("expected error on 404")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("no file should be written on a failed fetch")
	}
}

func TestRefreshMalformedListKeepsExistingDomains(t *testing.T) {
	engine := rules.NewEngine()
	pack := &rules.ListPack{ID: "ads", Category: rules.CategoryAds}
	pack.Domains().Add("existing.example")
	engine.AddPack(pack)
	cacheDir := t.TempDir()
	manager := &Manager{
		engine: engine,
		filter: New(engine),
		dir:    cacheDir,
		states: map[string]*packState{
			"ads": {
				def:  packDef{id: "ads", url: "://invalid"},
				info: PackInfo{ID: "ads", Loaded: true, Count: 1},
			},
		},
	}
	if err := os.WriteFile(manager.listPath("ads"), []byte(strings.Repeat("x", 8*1024*1024+1)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := manager.Refresh("ads"); err == nil {
		t.Fatal("expected malformed refresh to fail")
	}
	if !pack.Domains().Match("existing.example") {
		t.Fatal("malformed refresh replaced the existing in-memory domain set")
	}
	if got := pack.Domains().Len(); got != 1 {
		t.Fatalf("domain count = %d, want 1", got)
	}
	if _, err := os.Stat(manager.listPath("ads")); !os.IsNotExist(err) {
		t.Fatalf("malformed cache file still exists: %v", err)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func response(status int, body string, header http.Header) *http.Response {
	if header == nil {
		header = make(http.Header)
	}
	return &http.Response{
		StatusCode: status,
		Header:     header,
		Body:       io.NopCloser(strings.NewReader(body)),
	}
}
