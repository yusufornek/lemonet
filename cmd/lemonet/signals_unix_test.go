//go:build !windows

package main

import (
	"syscall"
	"testing"
)

func TestShutdownSignalsIncludeUnixTerminationSignals(t *testing.T) {
	signals := shutdownSignals()
	for _, sig := range []syscall.Signal{syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT} {
		if !hasSignal(signals, sig) {
			t.Fatalf("shutdown signals must include %v", sig)
		}
	}
}
