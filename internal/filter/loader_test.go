package filter

import "testing"

func TestDefaultEngineLoadsPacks(t *testing.T) {
	e, infos := DefaultEngine()
	if len(infos) == 0 {
		t.Fatal("expected built-in packs")
	}
	for _, info := range infos {
		if info.Count == 0 {
			t.Errorf("pack %q loaded no domains", info.ID)
		}
		if _, ok := e.Pack(info.ID); !ok {
			t.Errorf("pack %q not registered in engine", info.ID)
		}
	}
}
