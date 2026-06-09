package server

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap/zaptest"
)

func TestRateLimiterAllow(t *testing.T) {
	rl := newRateLimiter(60, 2)

	if !rl.allow("10.0.0.1") {
		t.Fatal("first request should be allowed")
	}
	if !rl.allow("10.0.0.1") {
		t.Fatal("second request within burst should be allowed")
	}
	if rl.allow("10.0.0.1") {
		t.Fatal("third request should exceed burst and be denied")
	}
	// A different client has its own bucket.
	if !rl.allow("10.0.0.2") {
		t.Fatal("request from a different client should be allowed")
	}
}

func TestRateLimitedPath(t *testing.T) {
	tests := []struct {
		path    string
		limited bool
	}{
		{"/secret/f9fa5704-3ed2-4e60-b441-c426d3f9f3c1", true},
		{"/create/secret", true},
		{"/create/file", true},
		{"/file/f9fa5704-3ed2-4e60-b441-c426d3f9f3c1", true},
		{"/auth/login", true},
		{"/health", false},
		{"/ready", false},
		{"/config", false},
		{"/", false},
		{"/assets/index.js", false},
	}
	for _, tt := range tests {
		if got := rateLimitedPath(tt.path); got != tt.limited {
			t.Errorf("rateLimitedPath(%q) = %v, want %v", tt.path, got, tt.limited)
		}
	}
}

func TestRateLimitMiddleware(t *testing.T) {
	y := Server{
		DB:                 &mockDB{},
		Registry:           prometheus.NewRegistry(),
		Logger:             zaptest.NewLogger(t),
		RateLimitPerMinute: 60,
		RateLimitBurst:     2,
	}
	handler := y.HTTPHandler()

	statusFor := func(path string) int {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.RemoteAddr = "192.0.2.1:1234"
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		return rr.Code
	}

	secretPath := "/secret/f9fa5704-3ed2-4e60-b441-c426d3f9f3c1"
	for i := 0; i < 2; i++ {
		if code := statusFor(secretPath); code == http.StatusTooManyRequests {
			t.Fatalf("request %d should not be rate limited", i+1)
		}
	}
	if code := statusFor(secretPath); code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 after burst exhausted, got %d", code)
	}
	// Health endpoint is exempt.
	if code := statusFor("/health"); code == http.StatusTooManyRequests {
		t.Fatal("health endpoint should not be rate limited")
	}
}

func TestRateLimitDisabledByDefault(t *testing.T) {
	y := Server{
		DB:       &mockDB{},
		Registry: prometheus.NewRegistry(),
		Logger:   zaptest.NewLogger(t),
	}
	handler := y.HTTPHandler()

	for i := 0; i < 20; i++ {
		req := httptest.NewRequest(http.MethodGet, "/secret/f9fa5704-3ed2-4e60-b441-c426d3f9f3c1", nil)
		req.RemoteAddr = "192.0.2.1:1234"
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code == http.StatusTooManyRequests {
			t.Fatal("rate limiting should be disabled when RateLimitPerMinute is 0")
		}
	}
}

func TestValidateTrustedProxies(t *testing.T) {
	tests := []struct {
		name    string
		proxies []string
		wantErr bool
	}{
		{"empty", nil, false},
		{"valid IP", []string{"10.0.0.1"}, false},
		{"valid IPv6", []string{"::1"}, false},
		{"valid CIDR", []string{"10.0.0.0/8"}, false},
		{"mixed valid", []string{"192.168.1.1", "172.16.0.0/12"}, false},
		{"malformed CIDR", []string{"10.0.0/8"}, true},
		{"hostname", []string{"proxy.example.com"}, true},
		{"garbage", []string{"not-an-ip"}, true},
		{"valid then invalid", []string{"10.0.0.1", "bogus"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateTrustedProxies(tt.proxies)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ValidateTrustedProxies(%v) error = %v, wantErr %v", tt.proxies, err, tt.wantErr)
			}
		})
	}
}
