package filter

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseList(t *testing.T) {
	in := strings.NewReader("# comment\n\n0.0.0.0 ads.example\nplain.example\n! adblock comment\n  spaced.example  \n")
	got := parseList(in)
	want := map[string]bool{"ads.example": true, "plain.example": true, "spaced.example": true}
	if len(got) != len(want) {
		t.Fatalf("parsed %v, want %d entries", got, len(want))
	}
	for _, d := range got {
		if !want[d] {
			t.Errorf("unexpected entry %q", d)
		}
	}
}

func TestFetchListWritesAndHonorsETag(t *testing.T) {
	const body = "a.example\nb.example\n"
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		if r.Header.Get("If-None-Match") == "v1" {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", "v1")
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	path := filepath.Join(t.TempDir(), "list.txt")

	if err := fetchList(srv.URL, path); err != nil {
		t.Fatalf("first fetch: %v", err)
	}
	got, _ := os.ReadFile(path)
	if string(got) != body {
		t.Fatalf("cached body = %q, want %q", got, body)
	}
	if etag, _ := os.ReadFile(path + ".etag"); string(etag) != "v1" {
		t.Fatalf("etag = %q, want v1", etag)
	}

	// Second fetch sends If-None-Match and must get a 304 (not re-downloaded).
	if err := fetchList(srv.URL, path); !errors.Is(err, errNotModified) {
		t.Fatalf("second fetch err = %v, want errNotModified", err)
	}
	if hits != 2 {
		t.Fatalf("server hits = %d, want 2", hits)
	}
}

func TestFetchListBadStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	path := filepath.Join(t.TempDir(), "list.txt")
	if err := fetchList(srv.URL, path); err == nil {
		t.Fatal("expected error on 404")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("no file should be written on a failed fetch")
	}
}
