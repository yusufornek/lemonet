package filter

import "testing"

func TestManagerRegistersCatalog(t *testing.T) {
	m := NewManager()
	infos := m.Packs()
	if len(infos) != len(packDefs) {
		t.Fatalf("Packs() returned %d packs, want %d", len(infos), len(packDefs))
	}
	for _, info := range infos {
		if _, ok := m.engine.Pack(info.ID); !ok {
			t.Errorf("pack %q not registered in engine", info.ID)
		}
	}
	// The embedded "social" pack must load offline with domains; remote packs may be empty until
	// the user enables them.
	social := findPack(infos, "social")
	if social == nil || social.Count == 0 || !social.Loaded {
		t.Errorf("built-in social pack should load offline with domains, got %+v", social)
	}
}

func findPack(infos []PackInfo, id string) *PackInfo {
	for i := range infos {
		if infos[i].ID == id {
			return &infos[i]
		}
	}
	return nil
}
