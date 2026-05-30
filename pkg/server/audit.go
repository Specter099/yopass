package server

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// AuditOutcome classifies the result of an auditable action.
type AuditOutcome string

const (
	OutcomeSuccess AuditOutcome = "success"
	OutcomeFailure AuditOutcome = "failure"
	OutcomeDenied  AuditOutcome = "denied"
)

// AuditEvent is the structured payload written for every auditable action.
// Secret message content is never included — only IDs and metadata.
type AuditEvent struct {
	Timestamp         time.Time    `json:"timestamp"`
	Event             string       `json:"event"`
	Outcome           AuditOutcome `json:"outcome"`
	ClientIP          string       `json:"client_ip"`
	SecretID          string       `json:"secret_id,omitempty"`
	UserEmail         string       `json:"user_email,omitempty"`
	UserSubject       string       `json:"user_subject,omitempty"`
	OneTime           *bool        `json:"one_time,omitempty"`
	ExpirationSeconds *int32       `json:"expiration_seconds,omitempty"`
	RequireAuth       *bool        `json:"require_auth,omitempty"`
	Error             string       `json:"error,omitempty"`
}

// AuditLogger is satisfied by both the real logger and the no-op.
type AuditLogger interface {
	Log(e AuditEvent)
	Sync() error
}

// noopAuditLogger silently discards events when audit logging is disabled.
// It is always safe to call — no nil checks needed at call sites.
type noopAuditLogger struct{}

func (noopAuditLogger) Log(AuditEvent) {}
func (noopAuditLogger) Sync() error    { return nil }

// NewNoopAuditLogger returns the no-op implementation.
func NewNoopAuditLogger() AuditLogger { return noopAuditLogger{} }

// NewAuditLogger builds a zap-backed NDJSON audit logger.
// An empty path writes to stdout; otherwise output goes to the given file path.
//
// When redactEmail is true, user_email values are written as a keyed
// HMAC-SHA256 digest (12-char prefix) using redactKey, so logs remain
// correlatable across events for the same user but the cleartext address is
// not retained. Unlike a bare hash, the HMAC key prevents recovery of the
// low-entropy address by dictionary attack. This is for deployments whose
// retention policy treats email as PII. The caller is responsible for
// supplying a stable redactKey (see cmd/yopass-server) when redactEmail is set.
func NewAuditLogger(path string, redactEmail bool, redactKey []byte) (AuditLogger, error) {
	cfg := zap.NewProductionConfig()
	cfg.Encoding = "json"
	cfg.EncoderConfig = zapcore.EncoderConfig{
		TimeKey:        "",  // suppressed — timestamp is written explicitly as a named field
		MessageKey:     "",  // suppressed — all data lives in named fields
		LevelKey:       "",  // suppressed — every audit record is informational
		LineEnding:     zapcore.DefaultLineEnding,
		EncodeDuration: zapcore.SecondsDurationEncoder,
	}
	if path != "" {
		cfg.OutputPaths = []string{path}
	} else {
		cfg.OutputPaths = []string{"stdout"}
	}
	cfg.ErrorOutputPaths = []string{"stderr"}

	l, err := cfg.Build(zap.WithCaller(false))
	if err != nil {
		return nil, err
	}
	return &zapAuditLogger{logger: l, redactEmail: redactEmail, redactKey: redactKey}, nil
}

type zapAuditLogger struct {
	logger      *zap.Logger
	redactEmail bool
	redactKey   []byte
}

func (a *zapAuditLogger) Sync() error { return a.logger.Sync() }

func (a *zapAuditLogger) Log(e AuditEvent) {
	fields := []zap.Field{
		zap.Time("timestamp", e.Timestamp.UTC()),
		zap.String("event", e.Event),
		zap.String("outcome", string(e.Outcome)),
		zap.String("client_ip", e.ClientIP),
	}
	if e.SecretID != "" {
		fields = append(fields, zap.String("secret_id", redactSecretID(e.SecretID)))
	}
	if e.UserEmail != "" {
		email := e.UserEmail
		if a.redactEmail {
			email = redactEmail(email, a.redactKey)
		}
		fields = append(fields, zap.String("user_email", email))
	}
	if e.UserSubject != "" {
		fields = append(fields, zap.String("user_subject", e.UserSubject))
	}
	if e.OneTime != nil {
		fields = append(fields, zap.Bool("one_time", *e.OneTime))
	}
	if e.ExpirationSeconds != nil {
		fields = append(fields, zap.Int32("expiration_seconds", *e.ExpirationSeconds))
	}
	if e.RequireAuth != nil {
		fields = append(fields, zap.Bool("require_auth", *e.RequireAuth))
	}
	if e.Error != "" {
		fields = append(fields, zap.String("error", e.Error))
	}
	a.logger.Info("", fields...)
}

// audit returns the server's AuditLogger, falling back to the noop if nil.
// This makes every call site nil-safe without requiring HTTPHandler to have run first.
func (y *Server) audit() AuditLogger {
	if y.Audit == nil {
		return noopAuditLogger{}
	}
	return y.Audit
}

// redactSecretID hashes the raw secret key to a short fingerprint so audit
// logs can correlate events without exposing a token that could be used to
// retrieve the secret. Secret keys are high-entropy random values, so a bare
// truncated hash is not feasibly reversible.
func redactSecretID(secretID string) string {
	if secretID == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(secretID))
	return hex.EncodeToString(sum[:])[:12]
}

// redactEmail returns a keyed HMAC-SHA256 digest (12-char prefix) of email.
// Email addresses are low-entropy, so a bare hash (like redactSecretID) could
// be reversed with a dictionary of candidate addresses; the HMAC key defeats
// that while keeping the digest stable for correlation across events.
func redactEmail(email string, key []byte) string {
	if email == "" {
		return ""
	}
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(email))
	return hex.EncodeToString(mac.Sum(nil))[:12]
}

// boolPtr returns a pointer to b for use in optional *bool AuditEvent fields.
func boolPtr(b bool) *bool { return &b }

// int32Ptr returns a pointer to v for use in optional *int32 AuditEvent fields.
func int32Ptr(v int32) *int32 { return &v }

// sessionEmail returns the email from a session or "" if session is nil.
func sessionEmail(s *sessionData) string {
	if s == nil {
		return ""
	}
	return s.Email
}

// sessionSub returns the subject from a session or "" if session is nil.
func sessionSub(s *sessionData) string {
	if s == nil {
		return ""
	}
	return s.Sub
}
