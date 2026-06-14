package main

import (
	"errors"
	"os"
	"testing"
)

func TestPanelURLKeepsTokenInFragment(t *testing.T) {
	got := panelURL("127.0.0.1:49152", "secret")
	want := "http://127.0.0.1:49152/#token=secret"
	if got != want {
		t.Fatalf("panelURL = %q, want %q", got, want)
	}
}

func TestShutdownSignalsIncludeInterrupt(t *testing.T) {
	if !hasSignal(shutdownSignals(), os.Interrupt) {
		t.Fatal("shutdown signals must include os.Interrupt")
	}
}

func TestMergeCleanupErrorPreservesOperationAndCleanupErrors(t *testing.T) {
	operationErr := errors.New("shutdown failed")
	cleanupErr := errors.New("cleanup failed")
	got := mergeCleanupError(operationErr, func() error { return cleanupErr })
	if !errors.Is(got, operationErr) || !errors.Is(got, cleanupErr) {
		t.Fatalf("merged error = %v, want both operation and cleanup errors", got)
	}
}

func TestValidateLoopbackAddr(t *testing.T) {
	valid := []string{
		"127.0.0.1:0",
		"localhost:8080",
		"[::1]:0",
	}
	for _, addr := range valid {
		if err := validateLoopbackAddr(addr); err != nil {
			t.Errorf("validateLoopbackAddr(%q) returned %v", addr, err)
		}
	}

	invalid := []string{
		":0",
		"0.0.0.0:0",
		"[::]:0",
		"192.168.1.10:8080",
		"bad address",
	}
	for _, addr := range invalid {
		if err := validateLoopbackAddr(addr); err == nil {
			t.Errorf("validateLoopbackAddr(%q) returned nil", addr)
		}
	}
}

func hasSignal(signals []os.Signal, want os.Signal) bool {
	for _, sig := range signals {
		if sig == want {
			return true
		}
	}
	return false
}
