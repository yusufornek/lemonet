package enforce

import (
	"net/netip"
	"runtime"
	"sync"
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
	const fullEthernetFrame = 1514
	drop, _ := u.Decide(testIP, engine.Upload, fullEthernetFrame)
	if drop {
		t.Fatal("a normal full-size frame should be shaped, not dropped")
	}
	if drop, delay := u.Decide(testIP, engine.Upload, fullEthernetFrame); drop || delay <= 0 {
		t.Fatal("throttled device should be delayed once the bucket is drained")
	}
	// The unthrottled direction stays free.
	if _, delay := u.Decide(testIP, engine.Download, 64_000); delay != 0 {
		t.Fatalf("unthrottled direction delay = %v, want 0", delay)
	}
}

func TestThrottleDropsReservationsLargerThanBurst(t *testing.T) {
	u := NewUserspace()
	if err := u.Throttle(testIP, 64, 0); err != nil {
		t.Fatal(err)
	}
	drop, delay := u.Decide(testIP, engine.Upload, 64_000)
	if !drop || delay != 0 {
		t.Fatalf("oversized throttled frame: drop=%v delay=%v, want immediate drop", drop, delay)
	}
}

func TestThrottleRejectsNegativeRates(t *testing.T) {
	u := NewUserspace()
	if err := u.Throttle(testIP, -1, 0); err == nil {
		t.Fatal("negative upload rate should be rejected")
	}
	if err := u.Throttle(testIP, 0, -1); err == nil {
		t.Fatal("negative download rate should be rejected")
	}
}

func TestDecideConcurrentPolicyMutation(t *testing.T) {
	u := NewUserspace()
	prevProcs := runtime.GOMAXPROCS(8)
	defer runtime.GOMAXPROCS(prevProcs)
	var wg sync.WaitGroup
	start := make(chan struct{})

	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for j := 0; j < 20_000; j++ {
				u.Decide(testIP, engine.Upload, 512)
				u.Decide(testIP, engine.Download, 512)
			}
		}()
	}

	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for j := 0; j < 20_000; j++ {
				_ = u.Block(testIP)
				_ = u.Throttle(testIP, 64, 128)
				_ = u.Pause(testIP)
				_ = u.Resume(testIP)
				_ = u.Clear(testIP)
			}
		}()
	}

	close(start)
	wg.Wait()
}
