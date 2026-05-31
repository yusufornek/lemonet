package enforce

import (
	"net/netip"
	"testing"

	"github.com/yusufornek/lemonet/internal/engine"
)

var testIP = netip.MustParseAddr("192.168.1.50")

func TestUnknownDeviceForwards(t *testing.T) {
	u := NewUserspace()
	if drop, delay := u.Decide(testIP, engine.Upload, 1500); drop || delay != 0 {
		t.Fatalf("unknown device: drop=%v delay=%v, want forward", drop, delay)
	}
}

func TestBlockDrops(t *testing.T) {
	u := NewUserspace()
	if err := u.Block(testIP); err != nil {
		t.Fatal(err)
	}
	if drop, _ := u.Decide(testIP, engine.Upload, 1500); !drop {
		t.Fatal("blocked device should drop")
	}
	if err := u.Clear(testIP); err != nil {
		t.Fatal(err)
	}
	if drop, _ := u.Decide(testIP, engine.Upload, 1500); drop {
		t.Fatal("cleared device should forward")
	}
}

func TestPauseResume(t *testing.T) {
	u := NewUserspace()
	_ = u.Pause(testIP)
	if drop, _ := u.Decide(testIP, engine.Download, 1500); !drop {
		t.Fatal("paused device should drop")
	}
	_ = u.Resume(testIP)
	if drop, _ := u.Decide(testIP, engine.Download, 1500); drop {
		t.Fatal("resumed device should forward")
	}
}

func TestThrottleDelaysWhenBucketDrained(t *testing.T) {
	u := NewUserspace()
	if err := u.Throttle(testIP, 64, 0); err != nil {
		t.Fatal(err)
	}
	// Drain the bucket with a large send, then a second send must be delayed.
	u.Decide(testIP, engine.Upload, 64_000)
	if _, delay := u.Decide(testIP, engine.Upload, 64_000); delay <= 0 {
		t.Fatal("throttled device should be delayed once the bucket is drained")
	}
	// The unthrottled direction stays free.
	if _, delay := u.Decide(testIP, engine.Download, 64_000); delay != 0 {
		t.Fatalf("unthrottled direction delay = %v, want 0", delay)
	}
}
