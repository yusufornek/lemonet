package enforce

import (
	"fmt"
	"net/netip"
	"sync"
	"time"

	"golang.org/x/time/rate"

	"github.com/yusufornek/lemonet/internal/engine"
)

// burstFraction sizes each token bucket at this fraction of one second of throughput. A small
// burst lets TCP fill the pipe without letting the average rate drift above the configured cap.
const burstFraction = 0.1

const minBurstBytes = 2048

type policy struct {
	blocked bool
	paused  bool
	up      *rate.Limiter
	down    *rate.Limiter
}

// Userspace is the default Enforcer. It keeps a per-device policy and implements engine.Decider
// so the relay can consult it for every forwarded packet.
type Userspace struct {
	mu       sync.RWMutex
	policies map[netip.Addr]*policy
}

func NewUserspace() *Userspace {
	return &Userspace{policies: make(map[netip.Addr]*policy)}
}

func (u *Userspace) entry(ip netip.Addr) *policy {
	p, ok := u.policies[ip]
	if !ok {
		p = &policy{}
		u.policies[ip] = p
	}
	return p
}

func (u *Userspace) Block(ip netip.Addr) error {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.entry(ip).blocked = true
	return nil
}

func (u *Userspace) Throttle(ip netip.Addr, upKbps, downKbps int) error {
	if upKbps < 0 || downKbps < 0 {
		return fmt.Errorf("enforce: throttle rates must be non-negative")
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	p := u.entry(ip)
	p.up = limiterFor(p.up, upKbps)
	p.down = limiterFor(p.down, downKbps)
	return nil
}

func (u *Userspace) Pause(ip netip.Addr) error {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.entry(ip).paused = true
	return nil
}

func (u *Userspace) Resume(ip netip.Addr) error {
	u.mu.Lock()
	defer u.mu.Unlock()
	if p, ok := u.policies[ip]; ok {
		p.paused = false
	}
	return nil
}

func (u *Userspace) Clear(ip netip.Addr) error {
	u.mu.Lock()
	defer u.mu.Unlock()
	delete(u.policies, ip)
	return nil
}

func (u *Userspace) ClearAll() error {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.policies = make(map[netip.Addr]*policy)
	return nil
}

// Decide implements engine.Decider. It drops blocked or paused devices and, for throttled ones,
// returns the delay the relay should wait before forwarding so the average rate stays under cap.
func (u *Userspace) Decide(device netip.Addr, dir engine.Direction, length int) (bool, time.Duration) {
	u.mu.RLock()
	p, ok := u.policies[device]
	if !ok {
		u.mu.RUnlock()
		return false, 0
	}
	blocked, paused := p.blocked, p.paused
	up, down := p.up, p.down
	u.mu.RUnlock()
	if blocked || paused {
		return true, 0
	}

	lim := up
	if dir == engine.Download {
		lim = down
	}
	if lim == nil {
		return false, 0
	}
	res := lim.ReserveN(time.Now(), length)
	if !res.OK() {
		return true, 0
	}
	return false, res.Delay()
}

// limiterFor creates or updates a byte-rate limiter for the given kbps. 0 kbps removes the limit.
func limiterFor(existing *rate.Limiter, kbps int) *rate.Limiter {
	if kbps <= 0 {
		return nil
	}
	bytesPerSec := float64(kbps) * 1000 / 8
	burst := int(bytesPerSec * burstFraction)
	if burst < minBurstBytes {
		burst = minBurstBytes
	}
	if existing == nil {
		return rate.NewLimiter(rate.Limit(bytesPerSec), burst)
	}
	existing.SetLimit(rate.Limit(bytesPerSec))
	existing.SetBurst(burst)
	return existing
}

var _ engine.Decider = (*Userspace)(nil)
var _ Enforcer = (*Userspace)(nil)
