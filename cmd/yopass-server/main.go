package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/gorilla/securecookie"
	"github.com/jhaals/yopass/pkg/server"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/zitadel/oidc/v3/pkg/client/rp"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var logLevel zapcore.Level

// version is set at build time via ldflags.
var version string

const licenseAnnotationKey = "yopass-license-group"

var licenseOIDCFlags = []string{
	"oidc-issuer", "oidc-client-id", "oidc-client-secret", "oidc-redirect-url",
	"require-auth", "oidc-session-key", "oidc-allowed-domains", "frontend-url",
}

var licenseBrandingFlags = []string{
	"license-key", "app-name", "logo-url",
	"theme-light", "theme-dark", "theme-custom-light", "theme-custom-dark",
	"max-file-size",
}

var licenseAuditFlags = []string{
	"audit-log", "audit-log-file", "audit-redact-email", "audit-redact-key",
}

// flagSectionFiltered returns a temporary FlagSet containing only the flags
// from pflag.CommandLine that satisfy the filter predicate.
func flagSectionFiltered(filter func(*pflag.Flag) bool) *pflag.FlagSet {
	fs := pflag.NewFlagSet("", pflag.ContinueOnError)
	pflag.CommandLine.VisitAll(func(f *pflag.Flag) {
		if !f.Hidden && filter(f) {
			fs.AddFlag(f)
		}
	})
	return fs
}

func init() {
	pflag.String("address", "", "listen address (default 0.0.0.0)")
	pflag.Int("port", 1337, "listen port")
	pflag.String("database", "memcached", "database backend ('memcached' or 'redis')")
	pflag.String("asset-path", "public", "path to the assets folder")
	pflag.Int("max-length", 10000, "max length of encrypted secret")
	pflag.String("max-file-size", "512KB", "max file upload size (e.g. 10KB, 512KB, 1MB); capped at 1MB without a license key")
	pflag.String("memcached", "localhost:11211", "memcached address")
	pflag.Int("metrics-port", -1, "metrics server listen port")
	pflag.String("redis", "redis://localhost:6379/0", "Redis URL")
	pflag.String("tls-cert", "", "path to TLS certificate")
	pflag.String("tls-key", "", "path to TLS key")
	pflag.Bool("force-onetime-secrets", false, "reject non onetime secrets from being created")
	pflag.String("cors-allow-origin", "*", "Access-Control-Allow-Origin")
	pflag.Bool("disable-upload", false, "disable the /file upload endpoints")
	pflag.Bool("read-only", false, "disable all secret creation endpoints (retrieval-only mode)")
	pflag.Bool("prefetch-secret", true, "Display information that the secret might be one time use")
	pflag.Bool("disable-features", false, "disable features")
	pflag.Bool("no-language-switcher", false, "disable the language switcher in the UI")
	pflag.StringSlice("trusted-proxies", []string{}, "trusted proxy IP addresses or CIDR blocks for X-Forwarded-For header validation")
	pflag.Int("rate-limit", 0, "max sustained requests per minute per client IP on secret and auth endpoints (0 disables rate limiting)")
	pflag.Int("rate-limit-burst", 0, "burst capacity for --rate-limit (defaults to the --rate-limit value)")
	pflag.String("privacy-notice-url", "", "URL to privacy notice page")
	pflag.String("imprint-url", "", "URL to imprint/legal notice page")
	pflag.String("default-expiry", "1h", "default expiry time for secrets [1h, 1d, 1w]")
	pflag.String("theme-light", "emerald", "DaisyUI theme name for light mode")
	pflag.String("theme-dark", "dim", "DaisyUI theme name for dark mode")
	pflag.String("theme-custom-light", "", "JSON object of CSS variables for a custom light theme (e.g. '{\"--color-primary\":\"oklch(...)\"}')")
	pflag.String("theme-custom-dark", "", "JSON object of CSS variables for a custom dark theme (e.g. '{\"--color-primary\":\"oklch(...)\"}')")
	pflag.String("app-name", "", "Custom application name shown in the UI (default: Yopass)")
	pflag.String("logo-url", "", "URL to a logo image (e.g. /mylogo.svg for a file in the public directory)")
	pflag.String("license-key", "", "JWT license key for premium features (theming, custom branding)")
	pflag.String("file-store", "", "file store backend for large files ('disk' or 's3'), defaults to database storage")
	pflag.String("file-store-path", "/tmp/yopass-files", "base path for disk file store")
	pflag.String("file-store-s3-bucket", "", "S3 bucket name for file store")
	pflag.String("file-store-s3-prefix", "yopass/", "S3 key prefix for file store")
	pflag.String("file-store-s3-endpoint", "", "S3 endpoint URL (for MinIO/compatible)")
	pflag.String("file-store-s3-region", "us-east-1", "S3 region")
	pflag.Int("cleanup-interval", 60, "file cleanup interval in seconds")
	pflag.Bool("disable-file-cleanup", false, "disable the file store cleanup goroutine (use when S3 lifecycle rules handle expiration)")
	pflag.Bool("health-check", false, "Perform health check and exit")
	pflag.String("oidc-issuer", "", "OIDC issuer URL (e.g. https://accounts.google.com)")
	pflag.String("oidc-client-id", "", "OIDC OAuth2 client ID")
	pflag.String("oidc-client-secret", "", "OIDC OAuth2 client secret")
	pflag.String("oidc-redirect-url", "", "OIDC callback URL (e.g. https://yopass.example.com/auth/callback)")
	pflag.Bool("require-auth", false, "require authentication to create secrets (needs --oidc-issuer and a valid license)")
	pflag.String("oidc-session-key", "", "64-byte hex-encoded session key for multi-instance deployments (generate with: openssl rand -hex 64)")
	pflag.StringSlice("oidc-allowed-domains", []string{}, "restrict secret creation to users whose email matches one of these domains (comma-separated, e.g. corp.example.com,example.com)")
	pflag.String("frontend-url", "", "frontend base URL for post-login redirect in split deployments (e.g. http://localhost:3000)")
	pflag.Bool("audit-log", false, "enable structured audit logging to NDJSON (requires valid license)")
	pflag.String("audit-log-file", "", "file path for audit log output (default: stdout)")
	pflag.Bool("audit-redact-email", false, "pseudonymize user_email in audit logs (12-char keyed HMAC) — preserves per-user correlation without retaining the cleartext address; not reversible-proof anonymization")
	pflag.String("audit-redact-key", "", "hex key (>=64 chars / 32 bytes) for --audit-redact-email; if unset, derived from --oidc-session-key, else an ephemeral per-process key is used (no cross-restart correlation)")
	pflag.CommandLine.AddGoFlag(&flag.Flag{Name: "log-level", Usage: "Log level", Value: &logLevel})

	for _, name := range licenseOIDCFlags {
		if err := pflag.CommandLine.SetAnnotation(name, licenseAnnotationKey, []string{"oidc"}); err != nil {
			log.Fatalf("failed to annotate flag %q: %v", name, err)
		}
	}
	for _, name := range licenseBrandingFlags {
		if err := pflag.CommandLine.SetAnnotation(name, licenseAnnotationKey, []string{"branding"}); err != nil {
			log.Fatalf("failed to annotate flag %q: %v", name, err)
		}
	}
	for _, name := range licenseAuditFlags {
		if err := pflag.CommandLine.SetAnnotation(name, licenseAnnotationKey, []string{"audit"}); err != nil {
			log.Fatalf("failed to annotate flag %q: %v", name, err)
		}
	}

	pflag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: yopass-server [flags]\n\nFlags:\n")
		flagSectionFiltered(func(f *pflag.Flag) bool {
			_, ok := f.Annotations[licenseAnnotationKey]
			return !ok
		}).PrintDefaults()

		fmt.Fprintf(os.Stderr, "\nBusiness License — Authentication / OIDC (requires --license-key):\n")
		flagSectionFiltered(func(f *pflag.Flag) bool {
			vals := f.Annotations[licenseAnnotationKey]
			return len(vals) > 0 && vals[0] == "oidc"
		}).PrintDefaults()

		fmt.Fprintf(os.Stderr, "\nBusiness License — Branding & Theming (requires --license-key):\n")
		flagSectionFiltered(func(f *pflag.Flag) bool {
			vals := f.Annotations[licenseAnnotationKey]
			return len(vals) > 0 && vals[0] == "branding"
		}).PrintDefaults()

		fmt.Fprintf(os.Stderr, "\nBusiness License — Audit Logging (requires --license-key):\n")
		flagSectionFiltered(func(f *pflag.Flag) bool {
			vals := f.Annotations[licenseAnnotationKey]
			return len(vals) > 0 && vals[0] == "audit"
		}).PrintDefaults()
	}

	viper.AutomaticEnv()
	viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))
	if err := viper.BindPFlags(pflag.CommandLine); err != nil {
		log.Fatalf("Unable to bind flags: %v", err)
	}

	pflag.Parse()
}

func main() {
	logger := configureZapLogger()

	// Handle health check mode
	if viper.GetBool("health-check") {
		db, err := setupDatabase(logger)
		if err != nil {
			logger.Error("Failed to setup database", zap.Error(err))
			os.Exit(1)
		}
		if err := performHealthCheck(logger, db); err != nil {
			logger.Error("Health check failed", zap.Error(err))
			os.Exit(1)
		}
		logger.Info("Health check passed")
		os.Exit(0)
	}

	switch viper.GetString("default-expiry") {
	case "", "1h", "1d", "1w":
		// valid
	default:
		logger.Fatal("invalid --default-expiry value, expected one of: 1h, 1d, 1w",
			zap.String("value", viper.GetString("default-expiry")))
	}

	for _, flagName := range []string{"theme-light", "theme-dark"} {
		val := viper.GetString(flagName)
		if val == "custom-light" || val == "custom-dark" {
			logger.Fatal(flagName+" must not be set to a reserved name",
				zap.String("value", val),
				zap.Strings("reserved", []string{"custom-light", "custom-dark"}))
		}
	}

	for _, flagName := range []string{"theme-custom-light", "theme-custom-dark"} {
		raw := viper.GetString(flagName)
		if raw == "" {
			continue
		}
		var vars map[string]string
		if err := json.Unmarshal([]byte(raw), &vars); err != nil {
			logger.Fatal("invalid JSON for "+flagName, zap.Error(err))
		}
		for k, v := range vars {
			if !strings.HasPrefix(k, "--color-") {
				logger.Fatal(flagName+" contains invalid CSS variable key (must start with --color-)",
					zap.String("key", k))
			}
			if !isValidCSSColorValue(v) {
				logger.Fatal(flagName+" contains a value with disallowed characters; only color-value chars are permitted (letters, digits, whitespace, . , ( ) # % / -)",
					zap.String("key", k),
					zap.String("value", v))
			}
		}
	}

	// A malformed entry is silently ignored at request time (it fails closed),
	// leaving wrong client IPs in logs and audit events — refuse to start instead.
	if err := server.ValidateTrustedProxies(viper.GetStringSlice("trusted-proxies")); err != nil {
		logger.Fatal("invalid --trusted-proxies value", zap.Error(err))
	}

	registry := setupRegistry()

	licenseStatus := server.LicenseStatus{}
	if licenseKey := viper.GetString("license-key"); licenseKey != "" {
		licenseStatus = server.VerifyLicense(licenseKey, logger)
		if licenseStatus.Valid {
			logger.Info("license key verified",
				zap.String("licensee", licenseStatus.Licensee),
				zap.Time("expires_at", licenseStatus.ExpiresAt),
				zap.Float64("days_until_expiry", licenseStatus.DaysUntilExpiry()),
			)
		}
		daysGauge := prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "yopass_license_days_until_expiry",
			Help: "Number of days until the license key expires; negative if expired",
		})
		registry.MustRegister(daysGauge)
		daysGauge.Set(licenseStatus.DaysUntilExpiry())
	}

	var oidcProvider rp.RelyingParty
	if licenseStatus.Valid && viper.GetString("oidc-issuer") != "" {
		oidcCtx, oidcCancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer oidcCancel()
		var oidcErr error
		oidcProvider, oidcErr = server.NewOIDCProvider(oidcCtx, logger, viper.GetString("oidc-session-key"))
		if oidcErr != nil {
			logger.Fatal("failed to initialize OIDC provider", zap.Error(oidcErr))
		}
		logger.Info("OIDC authentication enabled",
			zap.String("issuer", viper.GetString("oidc-issuer")),
			zap.Bool("require_auth", viper.GetBool("require-auth")),
		)
	} else if viper.GetString("oidc-issuer") != "" && !licenseStatus.Valid {
		logger.Fatal("--oidc-issuer is configured but no valid license key was provided — refusing to start without authentication (provide --license-key or remove --oidc-issuer)")
	}
	if viper.GetBool("require-auth") && oidcProvider == nil {
		logger.Fatal("--require-auth is set but OIDC is not configured (check --oidc-issuer and --license-key)")
	}

	// Security posture warnings for authenticated deployments. These do not
	// block startup but flag configurations where the consume-endpoint CSRF
	// guard and Secure-cookie logic rest on weaker assumptions.
	if oidcProvider != nil {
		// M1: with no trusted proxies, X-Forwarded-Proto is honoured from any
		// peer, so an attacker reaching the server directly can influence
		// Secure/SameSite cookie attributes and HSTS emission.
		if len(viper.GetStringSlice("trusted-proxies")) == 0 {
			logger.Warn("OIDC is enabled but --trusted-proxies is not set; X-Forwarded-Proto is trusted from any client, so HTTPS detection (Secure cookies, HSTS) can be spoofed. Set --trusted-proxies to your reverse proxy's address(es).")
		}
		// H2: the X-Requested-With CSRF guard on consume endpoints only blocks
		// cross-origin fetches when CORS is restricted to a specific origin.
		// With the wildcard default the preflight succeeds for any origin.
		if viper.GetString("frontend-url") == "" && viper.GetString("cors-allow-origin") == "*" {
			logger.Warn("OIDC is enabled but cors-allow-origin is '*' and --frontend-url is unset; cross-origin fetches to consume endpoints are not blocked by the CSRF guard. Set --cors-allow-origin (or --frontend-url) to your frontend origin.")
		}
	}

	var cookieCodec *securecookie.SecureCookie
	if oidcProvider != nil {
		sessionKey := viper.GetString("oidc-session-key")
		if sessionKey != "" && len(sessionKey) != 128 {
			// A non-empty key with the wrong length would silently fall back to
			// ephemeral random keys, which breaks sessions across instances behind
			// a load balancer. There is no legitimate use for a wrong-length key,
			// so refuse to start.
			logger.Fatal("--oidc-session-key has wrong length; expected 128 hex characters (generate with: openssl rand -hex 64)",
				zap.Int("provided_length", len(sessionKey)))
		}
		if len(sessionKey) == 128 {
			if _, err := hex.DecodeString(sessionKey); err != nil {
				logger.Fatal("--oidc-session-key is 128 characters but not valid hex; generate with: openssl rand -hex 64")
			}
		}
		codec, err := server.NewCookieCodec(sessionKey)
		if err != nil {
			logger.Fatal("failed to initialize session cookie codec", zap.Error(err))
		}
		cookieCodec = codec
	}

	var auditLogger server.AuditLogger = server.NewNoopAuditLogger()
	if viper.GetBool("audit-log") {
		if !licenseStatus.Valid {
			logger.Fatal("--audit-log requires a valid license key")
		}
		redactEmail := viper.GetBool("audit-redact-email")
		var redactKey []byte
		if redactEmail {
			redactKey = resolveAuditRedactKey(logger)
		}
		al, err := server.NewAuditLogger(viper.GetString("audit-log-file"), redactEmail, redactKey)
		if err != nil {
			logger.Fatal("failed to initialize audit logger", zap.Error(err))
		}
		auditLogger = al
		output := viper.GetString("audit-log-file")
		if output == "" {
			output = "stdout"
		}
		logger.Info("audit logging enabled", zap.String("output", output))
	}

	maxFileSize, err := server.ParseSize(viper.GetString("max-file-size"))
	if err != nil {
		logger.Fatal("invalid --max-file-size value", zap.String("value", viper.GetString("max-file-size")), zap.Error(err))
	}
	const maxFileSizeCap int64 = 1 * 1024 * 1024 // 1MB
	if !licenseStatus.Valid && maxFileSize > maxFileSizeCap {
		logger.Warn("--max-file-size exceeds 1MB cap, capping to 1MB (a valid license removes this limit)",
			zap.String("requested", viper.GetString("max-file-size")))
		maxFileSize = maxFileSizeCap
	}

	db, err := setupDatabase(logger)
	if err != nil {
		logger.Fatal("failed to setup database", zap.Error(err))
	}
	var fileStore server.FileStore
	if !viper.GetBool("disable-upload") {
		fileStore, err = setupFileStore(logger, db)
		if err != nil {
			logger.Fatal("failed to setup file store", zap.Error(err))
		}

		// Warn if max-length exceeds DB backend limits without a dedicated file store
		if _, isDBStore := fileStore.(*server.DatabaseFileStore); isDBStore {
			const memcachedLimit int64 = 1 * 1024 * 1024 // 1MB default memcached item limit
			if maxFileSize > memcachedLimit {
				logger.Warn("max-file-size exceeds typical database backend limits without a file store configured",
					zap.String("max-file-size", server.FormatSize(maxFileSize)),
					zap.String("db-limit", server.FormatSize(memcachedLimit)),
					zap.String("hint", "consider using --file-store disk or --file-store s3 for large file support"),
				)
			}
		}
	}

	cert := viper.GetString("tls-cert")
	key := viper.GetString("tls-key")
	quit := make(chan os.Signal, 1)

	y := server.Server{
		DB:                  db,
		FileStore:           fileStore,
		MaxLength:           viper.GetInt("max-length"),
		MaxFileSize:         maxFileSize,
		Registry:            registry,
		ForceOneTimeSecrets: viper.GetBool("force-onetime-secrets"),
		AssetPath:           viper.GetString("asset-path"),
		Logger:              logger,
		TrustedProxies:      viper.GetStringSlice("trusted-proxies"),
		Version:             version,
		License:             licenseStatus,
		OIDCProvider:        oidcProvider,
		CookieCodec:         cookieCodec,
		Audit:               auditLogger,
		RateLimitPerMinute:  viper.GetInt("rate-limit"),
		RateLimitBurst:      viper.GetInt("rate-limit-burst"),
	}
	// Start cleanup goroutine for file store (disk or S3)
	cleanupCtx, cleanupCancel := context.WithCancel(context.Background())
	defer cleanupCancel()
	if fileStore != nil && !viper.GetBool("disable-file-cleanup") {
		if ds, ok := fileStore.(*server.DiskFileStore); ok {
			interval := time.Duration(viper.GetInt("cleanup-interval")) * time.Second
			logger.Info("Starting disk file store cleanup", zap.Duration("interval", interval))
			go server.StartDiskCleanup(cleanupCtx, ds, interval, logger)
		} else if s3s, ok := fileStore.(*server.S3FileStore); ok {
			interval := time.Duration(viper.GetInt("cleanup-interval")) * time.Second
			logger.Info("Starting S3 file store cleanup", zap.Duration("interval", interval))
			go server.StartS3Cleanup(cleanupCtx, s3s, interval, logger)
		}
	}

	yopassSrv := &http.Server{
		Addr:    fmt.Sprintf("%s:%d", viper.GetString("address"), viper.GetInt("port")),
		Handler: y.HTTPHandler(),
		// ReadHeaderTimeout bounds the headers-read phase to defeat Slowloris-style
		// attacks. Body and write phases are intentionally unbounded so large file
		// uploads/downloads on slow connections still complete. IdleTimeout caps
		// keep-alive lifetime so dormant connections don't pin server resources.
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
		TLSConfig:         &tls.Config{MinVersion: tls.VersionTLS12},
	}
	go func() {
		logger.Info("Starting yopass server", zap.String("address", yopassSrv.Addr))
		logger.Info("Loading assets from: ", zap.String("asset-path", y.AssetPath))
		err := listenAndServe(yopassSrv, cert, key)
		if !errors.Is(err, http.ErrServerClosed) {
			logger.Fatal("yopass stopped unexpectedly", zap.Error(err))
		}
	}()

	metricsServer := &http.Server{
		Addr:              fmt.Sprintf("%s:%d", viper.GetString("address"), viper.GetInt("metrics-port")),
		Handler:           metricsHandler(registry),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	if port := viper.GetInt("metrics-port"); port > 0 {
		go func() {
			logger.Info("Starting yopass metrics server", zap.String("address", metricsServer.Addr))
			err := listenAndServe(metricsServer, cert, key)
			if !errors.Is(err, http.ErrServerClosed) {
				logger.Fatal("metrics server stopped unexpectedly", zap.Error(err))
			}
		}()
	}

	signal.Notify(quit, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)
	sig := <-quit
	logger.Info("Shutting down HTTP server", zap.String("signal", sig.String()))
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := yopassSrv.Shutdown(ctx); err != nil {
		logger.Fatal("shutdown error: %s", zap.Error(err))
	}
	if port := viper.GetInt("metrics-port"); port > 0 {
		if err := metricsServer.Shutdown(ctx); err != nil {
			logger.Fatal("shutdown error: %s", zap.Error(err))
		}
	}
	if err := auditLogger.Sync(); err != nil {
		logger.Error("failed to flush audit log on shutdown", zap.Error(err))
	}
	logger.Info("Server shut down")
}

// cssColorValueRe matches the character set legitimate color values need:
// letters, digits, whitespace, and . , ( ) # % - /
//
// This is permissive enough for any modern color function — oklch(), rgb(),
// hsl(), color-mix(), hex, named colors — while rejecting the metacharacters
// (; { } : *) that allow rule-level CSS injection. The values are reflected
// verbatim into a <style> rule on the client (ThemeProvider). React's
// textContent prevents HTML injection, but without value validation a
// malicious operator config could still close the declaration with ';' and
// inject arbitrary CSS rules.
var cssColorValueRe = regexp.MustCompile(`^[a-zA-Z0-9.,()#%/ -]+$`)

func isValidCSSColorValue(s string) bool {
	if s == "" || !cssColorValueRe.MatchString(s) {
		return false
	}
	// Defense-in-depth: a color value never needs url() or a protocol-relative
	// path, and the character allowlist alone would otherwise permit e.g.
	// url(//evil/x) since ':' is not required. Reject both.
	if strings.Contains(strings.ToLower(s), "url") || strings.Contains(s, "//") {
		return false
	}
	return true
}

// resolveAuditRedactKey returns the HMAC key used to pseudonymize user_email
// in audit logs. Preference order:
//  1. --audit-redact-key (explicit, >=32 bytes of hex)
//  2. a labelled subkey derived from a 128-hex --oidc-session-key
//  3. an ephemeral random key (digests will not correlate across restarts or
//     instances; a warning is logged so this is visible)
func resolveAuditRedactKey(logger *zap.Logger) []byte {
	if raw := viper.GetString("audit-redact-key"); raw != "" {
		key, err := hex.DecodeString(raw)
		if err != nil || len(key) < 32 {
			logger.Fatal("--audit-redact-key must be at least 64 hex characters (32 bytes); generate with: openssl rand -hex 32")
		}
		return key
	}
	if sk := viper.GetString("oidc-session-key"); len(sk) == 128 {
		if _, err := hex.DecodeString(sk); err == nil {
			key, err := server.DeriveKey(sk, "audit-email-redact")
			if err != nil {
				logger.Fatal("failed to derive audit redaction key", zap.Error(err))
			}
			return key
		}
	}
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		logger.Fatal("failed to generate audit redaction key", zap.Error(err))
	}
	logger.Warn("--audit-redact-email is enabled without --audit-redact-key or a 128-hex --oidc-session-key; using an ephemeral random key. Email digests will not correlate across restarts or instances. Set --audit-redact-key (openssl rand -hex 32) for stable correlation.")
	return key
}

// listenAndServe starts a HTTP server on the given addr. It uses TLS if both
// certFile and keyFile are not empty.
func listenAndServe(srv *http.Server, certFile string, keyFile string) error {
	if certFile == "" || keyFile == "" {
		return srv.ListenAndServe()
	}
	return srv.ListenAndServeTLS(certFile, keyFile)
}

// metricsHandler builds a handler to serve Prometheus metrics
func metricsHandler(r *prometheus.Registry) http.Handler {
	mx := http.NewServeMux()
	mx.Handle("/metrics", promhttp.HandlerFor(r, promhttp.HandlerOpts{EnableOpenMetrics: true}))
	return mx
}

func setupRegistry() *prometheus.Registry {
	registry := prometheus.NewRegistry()
	registry.MustRegister(collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	registry.MustRegister(collectors.NewGoCollector())
	return registry
}

// configureZapLogger uses the `log-level` command line argument to set and replace the zap global logger.
func configureZapLogger() *zap.Logger {
	loggerCfg := zap.NewProductionConfig()
	loggerCfg.Level.SetLevel(logLevel)

	logger, err := loggerCfg.Build()
	if err != nil {
		log.Fatalf("Unable to build logger %v", err)
	}
	zap.ReplaceGlobals(logger)
	return logger
}

func setupDatabase(logger *zap.Logger) (server.Database, error) {
	var db server.Database
	switch database := viper.GetString("database"); database {
	case "memcached":
		memcached := viper.GetString("memcached")
		db = server.NewMemcached(memcached)
		logger.Debug("configured Memcached", zap.String("address", memcached))
	case "redis":
		redis := viper.GetString("redis")
		var err error
		db, err = server.NewRedis(redis)
		if err != nil {
			return nil, fmt.Errorf("invalid Redis URL: %w", err)
		}
		logger.Debug("configured Redis", zap.String("url", redis))
	default:
		return nil, fmt.Errorf("unsupported database, expected 'memcached' or 'redis' got '%s'", database)
	}
	return db, nil
}

// performHealthCheck performs a health check on the provided database
func performHealthCheck(logger *zap.Logger, db server.Database) error {
	if err := db.Health(); err != nil {
		if logger != nil {
			logger.Error("database health check failed", zap.Error(err))
		}
		return fmt.Errorf("database health check failed: %w", err)
	}
	return nil
}

func setupFileStore(logger *zap.Logger, db server.Database) (server.FileStore, error) {
	switch viper.GetString("file-store") {
	case "":
		logger.Info("no file store configured, using database for file storage")
		return server.NewDatabaseFileStore(db), nil
	case "disk":
		path := viper.GetString("file-store-path")
		logger.Info("configured disk file store", zap.String("path", path))
		return server.NewDiskFileStore(path)
	case "s3":
		bucket := viper.GetString("file-store-s3-bucket")
		if bucket == "" {
			return nil, fmt.Errorf("file-store-s3-bucket is required when file-store=s3")
		}
		logger.Info("configured S3 file store",
			zap.String("bucket", bucket),
			zap.String("prefix", viper.GetString("file-store-s3-prefix")),
			zap.String("region", viper.GetString("file-store-s3-region")),
		)
		return server.NewS3FileStore(
			bucket,
			viper.GetString("file-store-s3-prefix"),
			viper.GetString("file-store-s3-endpoint"),
			viper.GetString("file-store-s3-region"),
		)
	default:
		return nil, fmt.Errorf("unsupported file-store backend: %s (expected 'disk' or 's3')", viper.GetString("file-store"))
	}
}
