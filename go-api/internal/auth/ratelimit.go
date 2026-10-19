package auth

import (
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// RateLimiter is a per-key (client IP) token bucket used on the login form.
type RateLimiter struct {
	mu    sync.Mutex
	every rate.Limit
	burst int
	keys  map[string]*entry
}

type entry struct {
	lim  *rate.Limiter
	seen time.Time
}

func NewRateLimiter(perMinute, burst int) *RateLimiter {
	rl := &RateLimiter{
		every: rate.Every(time.Minute / time.Duration(perMinute)),
		burst: burst,
		keys:  map[string]*entry{},
	}
	go rl.gc()
	return rl
}

func (rl *RateLimiter) Allow(key string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	e, ok := rl.keys[key]
	if !ok {
		e = &entry{lim: rate.NewLimiter(rl.every, rl.burst)}
		rl.keys[key] = e
	}
	e.seen = time.Now()
	return e.lim.Allow()
}

func (rl *RateLimiter) gc() {
	for range time.Tick(5 * time.Minute) {
		rl.mu.Lock()
		for k, e := range rl.keys {
			if time.Since(e.seen) > 10*time.Minute {
				delete(rl.keys, k)
			}
		}
		rl.mu.Unlock()
	}
}
