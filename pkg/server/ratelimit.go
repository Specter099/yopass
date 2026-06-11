package server

import (
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// visitorTTL is how long an idle client's limiter is kept before it is
// evicted from the visitors map.
const visitorTTL = 10 * time.Minute

// rateLimiter implements per-client token bucket rate limiting keyed on the
// real client IP (X-Forwarded-For is only honoured from trusted proxies, see
// getRealClientIP). Idle entries are evicted lazily so no background
// goroutine is required.
type rateLimiter struct {
	mu        sync.Mutex
	visitors  map[string]*visitor
	rate      rate.Limit
	burst     int
	lastSweep time.Time
}

type visitor struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

// newRateLimiter creates a limiter allowing perMinute sustained requests per
// client with the given burst capacity.
func newRateLimiter(perMinute int, burst int) *rateLimiter {
	return &rateLimiter{
		visitors:  make(map[string]*visitor),
		rate:      rate.Limit(float64(perMinute) / 60.0),
		burst:     burst,
		lastSweep: time.Now(),
	}
}

// allow reports whether the client identified by ip may proceed.
func (rl *rateLimiter) allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	if now.Sub(rl.lastSweep) > visitorTTL {
		for k, v := range rl.visitors {
			if now.Sub(v.lastSeen) > visitorTTL {
				delete(rl.visitors, k)
			}
		}
		rl.lastSweep = now
	}

	v, ok := rl.visitors[ip]
	if !ok {
		v = &visitor{limiter: rate.NewLimiter(rl.rate, rl.burst)}
		rl.visitors[ip] = v
	}
	v.lastSeen = now
	return v.limiter.Allow()
}

// rateLimitedPath reports whether the request path is subject to rate
// limiting. Static assets, health probes and metrics are exempt so that
// normal page loads and orchestrator probes are never throttled; the
// limiter protects the endpoints that create, consume or authenticate.
func rateLimitedPath(path string) bool {
	for _, prefix := range []string{"/secret/", "/create/", "/file/", "/auth/"} {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}

// rateLimitMiddleware returns a middleware enforcing the server's rate limit
// on secret and authentication endpoints. A nil receiver or nil limiter is a
// no-op so the middleware can be registered unconditionally.
func (y *Server) rateLimitMiddleware(rl *rateLimiter) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if rl == nil || r.Method == http.MethodOptions || !rateLimitedPath(r.URL.Path) {
				next.ServeHTTP(w, r)
				return
			}
			if !rl.allow(y.getRealClientIP(r)) {
				w.Header().Set("Retry-After", "60")
				writeJSONError(w, `{"message": "Too many requests"}`, http.StatusTooManyRequests)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
