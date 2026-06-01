package filter

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/yusufornek/lemonet/internal/filter/rules"
)

// Manager owns the rules engine and the blocklist catalog. Built-in packs load from embedded data
// at startup; remote packs download on demand the first time a user enables them, cache to disk,
// and refresh on request. It produces the Filter the relay consults.
type Manager struct {
	engine *rules.Engine
	filter *Filter
	dir    string // blocklist cache dir; "" if unavailable

	mu     sync.Mutex
	states map[string]*packState
}

type packState struct {
	info         PackInfo
	def          packDef
	remoteLoaded bool
}

// NewManager builds the engine, registers every pack in the catalog, loads embedded and cached
// lists, and returns a ready Manager.
func NewManager() *Manager {
	m := &Manager{
		engine: rules.NewEngine(),
		dir:    blocklistCacheDir(),
		states: make(map[string]*packState),
	}
	for _, d := range packDefs {
		pack := &rules.ListPack{
			ID: d.id, Name: d.name, Category: d.category,
			License: d.license, Attribution: d.attribution, SourceURL: d.url,
		}
		m.engine.AddPack(pack)
		st := &packState{
			def: d,
			info: PackInfo{
				ID: d.id, Name: d.name, Category: d.category,
				License: d.license, Attribution: d.attribution, SourceURL: d.url,
			},
		}
		m.states[d.id] = st

		if d.embedFile != "" {
			if f, err := packData.Open(d.embedFile); err == nil {
				pack.Domains().Set(parseList(f))
				_ = f.Close()
				st.info.Count = pack.Domains().Len()
				st.info.Loaded = st.info.Count > 0
			}
		}
		// A cached remote list (from a previous run) supersedes the embedded fallback.
		if d.url != "" && m.dir != "" {
			if f, err := os.Open(m.listPath(d.id)); err == nil {
				pack.Domains().Set(parseList(f))
				_ = f.Close()
				st.info.Count = pack.Domains().Len()
				st.info.Loaded = st.info.Count > 0
				st.remoteLoaded = st.info.Count > 0
			}
		}
	}
	m.filter = New(m.engine)
	return m
}

func (m *Manager) listPath(id string) string { return filepath.Join(m.dir, id+".txt") }

// Filter returns the FlowInspector the relay uses.
func (m *Manager) Filter() *Filter { return m.filter }

// Packs returns catalog metadata in stable order.
func (m *Manager) Packs() []PackInfo {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]PackInfo, 0, len(packDefs))
	for _, d := range packDefs {
		out = append(out, m.states[d.id].info)
	}
	return out
}

// EnsureLoaded downloads and applies a remote pack's list the first time it is needed. It is safe
// to call repeatedly and concurrently; built-in or already-loaded packs return immediately. Run it
// in a goroutine: a large list can take seconds to fetch and parse.
func (m *Manager) EnsureLoaded(id string) error {
	m.mu.Lock()
	st, ok := m.states[id]
	if !ok {
		m.mu.Unlock()
		return fmt.Errorf("filter: unknown pack %s", id)
	}
	if st.def.url == "" || st.remoteLoaded || st.info.Loading {
		m.mu.Unlock()
		return nil
	}
	st.info.Loading = true
	m.mu.Unlock()

	err := m.loadRemote(st)

	m.mu.Lock()
	st.info.Loading = false
	m.mu.Unlock()
	return err
}

// Refresh forces a re-download of a remote pack (used by a periodic refresh or a manual request).
func (m *Manager) Refresh(id string) error {
	m.mu.Lock()
	st, ok := m.states[id]
	m.mu.Unlock()
	if !ok || st.def.url == "" {
		return fmt.Errorf("filter: %s is not a refreshable pack", id)
	}
	if m.dir != "" {
		_ = os.Remove(m.listPath(id) + ".etag") // force a full GET
	}
	return m.loadRemote(st)
}

// loadRemote fetches (conditionally) and applies a remote pack's list. A failed fetch keeps any
// existing cached/embedded list rather than wiping the pack.
func (m *Manager) loadRemote(st *packState) error {
	if m.dir == "" {
		return fmt.Errorf("filter: no cache directory; cannot fetch %s", st.def.id)
	}
	path := m.listPath(st.def.id)

	err := fetchList(st.def.url, path)
	if err != nil && !errors.Is(err, errNotModified) {
		if _, statErr := os.Stat(path); statErr != nil {
			return err // network failed and nothing is cached
		}
		// otherwise fall through and (re)load the stale cache
	}

	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	pack, ok := m.engine.Pack(st.def.id)
	if !ok {
		return fmt.Errorf("filter: pack %s missing from engine", st.def.id)
	}
	pack.Domains().Set(parseList(f))

	m.mu.Lock()
	st.info.Count = pack.Domains().Len()
	st.info.Loaded = st.info.Count > 0
	st.remoteLoaded = st.info.Count > 0
	m.mu.Unlock()
	return nil
}
