package filter

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

const (
	maxListBytes = 60 << 20 // refuse absurdly large lists
	fetchTimeout = 30 * time.Second
)

var errNotModified = errors.New("filter: list not modified")

// blocklistCacheDir returns (and creates) the on-disk cache directory, mirroring the config-dir
// pattern in internal/config. An empty string means no cache is available (remote packs then
// cannot be fetched and fall back to whatever is already loaded).
func blocklistCacheDir() string {
	base, err := os.UserConfigDir()
	if err != nil {
		return ""
	}
	dir := filepath.Join(base, "lemonet", "blocklists")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return ""
	}
	return dir
}

// fetchList downloads url to listPath using a conditional (ETag) request, writing atomically via a
// temp file + rename so a partial download never replaces a good cache. Returns errNotModified on
// HTTP 304. The caller reads listPath afterward regardless.
func fetchList(url, listPath string) error {
	return fetchListWithClient(&http.Client{Timeout: fetchTimeout}, url, listPath)
}

func fetchListWithClient(client *http.Client, url, listPath string) error {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	// Only do a conditional request when the cached body still exists; otherwise a 304 would leave
	// us with nothing to read and the pack stuck.
	if _, err := os.Stat(listPath); err == nil {
		if etag, err := os.ReadFile(listPath + ".etag"); err == nil && len(etag) > 0 {
			req.Header.Set("If-None-Match", string(etag))
		}
	}

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotModified {
		return errNotModified
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("filter: %s returned HTTP %d", url, resp.StatusCode)
	}

	tmp, err := os.CreateTemp(filepath.Dir(listPath), ".dl-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // harmless after a successful rename

	n, err := io.Copy(tmp, io.LimitReader(resp.Body, maxListBytes+1))
	closeErr := tmp.Close() // some filesystems report write errors only on Close
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if n > maxListBytes {
		return fmt.Errorf("filter: %s exceeds the %d-byte cap", url, maxListBytes)
	}
	if err := os.Rename(tmpName, listPath); err != nil {
		return err
	}
	if etag := resp.Header.Get("ETag"); etag != "" {
		_ = os.WriteFile(listPath+".etag", []byte(etag), 0o600)
	}
	return nil
}

func removeListCache(path string) {
	_ = os.Remove(path)
	_ = os.Remove(path + ".etag")
}
