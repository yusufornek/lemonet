//go:build darwin

package engine

import (
	"errors"
	"testing"
)

func TestDarwinGuardEndReturnsRestoreErrors(t *testing.T) {
	prevWrite := writeSysctlBoolFunc
	defer func() { writeSysctlBoolFunc = prevWrite }()

	errV4 := errors.New("v4 restore failed")
	errV6 := errors.New("v6 restore failed")
	writeSysctlBoolFunc = func(key string, _ bool) error {
		switch key {
		case darwinRedirectV4:
			return errV4
		case darwinRedirectV6:
			return errV6
		default:
			t.Fatalf("unexpected sysctl key %q", key)
			return nil
		}
	}

	g := &darwinGuard{prevV4: true, prevV6: false, applied: true}
	err := g.End()
	if !errors.Is(err, errV4) || !errors.Is(err, errV6) {
		t.Fatalf("End error = %v, want both restore errors", err)
	}
	if g.applied {
		t.Fatal("End should mark the guard unapplied even when restore reports an error")
	}
}

func TestDarwinGuardBeginRequiresSnapshotsBeforeWriting(t *testing.T) {
	prevRead := readSysctlBoolFunc
	prevWrite := writeSysctlBoolFunc
	defer func() {
		readSysctlBoolFunc = prevRead
		writeSysctlBoolFunc = prevWrite
	}()

	for _, failKey := range []string{darwinRedirectV4, darwinRedirectV6} {
		readErr := errors.New("snapshot failed")
		writeCalled := false
		readSysctlBoolFunc = func(key string) (bool, error) {
			if key == failKey {
				return false, readErr
			}
			return true, nil
		}
		writeSysctlBoolFunc = func(string, bool) error {
			writeCalled = true
			return nil
		}

		g := &darwinGuard{}
		err := g.Begin()
		if !errors.Is(err, readErr) {
			t.Fatalf("Begin error for %s = %v, want snapshot error", failKey, err)
		}
		if writeCalled {
			t.Fatalf("Begin wrote sysctl after %s snapshot failed", failKey)
		}
		if g.applied {
			t.Fatalf("Begin marked guard applied after %s snapshot failed", failKey)
		}
	}
}
