//go:build linux

package engine

import (
	"errors"
	"testing"
)

func TestLinuxGuardBeginRequiresSnapshotBeforeWriting(t *testing.T) {
	prevRead := readProcBoolFunc
	prevWrite := writeProcBoolFunc
	defer func() {
		readProcBoolFunc = prevRead
		writeProcBoolFunc = prevWrite
	}()

	readErr := errors.New("snapshot failed")
	writeCalled := false
	readProcBoolFunc = func(string) (bool, error) {
		return false, readErr
	}
	writeProcBoolFunc = func(string, bool) error {
		writeCalled = true
		return nil
	}

	g := &linuxGuard{}
	err := g.Begin()
	if !errors.Is(err, readErr) {
		t.Fatalf("Begin error = %v, want snapshot error", err)
	}
	if writeCalled {
		t.Fatal("Begin wrote proc value after snapshot failed")
	}
	if g.applied {
		t.Fatal("Begin marked guard applied after snapshot failed")
	}
}
