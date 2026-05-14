package server

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRedactSecretID(t *testing.T) {
	assert.Equal(t, "", redactSecretID(""))

	got := redactSecretID("abc")
	assert.Len(t, got, 12)
	assert.Regexp(t, `^[0-9a-f]{12}$`, got)

	// Deterministic.
	assert.Equal(t, got, redactSecretID("abc"))

	// Distinct inputs produce distinct outputs.
	assert.NotEqual(t, got, redactSecretID("abd"))
}

func TestNewAuditLogger_Stdout(t *testing.T) {
	l, err := NewAuditLogger("", false)
	require.NoError(t, err)
	require.NotNil(t, l)

	// Should not panic.
	l.Log(AuditEvent{
		Timestamp: time.Now().UTC(),
		Event:     "test.event",
		Outcome:   OutcomeSuccess,
		ClientIP:  "127.0.0.1",
	})
	// Sync on stdout may return a spurious error on some platforms; just ensure
	// the call does not panic.
	_ = l.Sync()
}

func TestNewAuditLogger_File(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	l, err := NewAuditLogger(path, false)
	require.NoError(t, err)

	l.Log(AuditEvent{
		Timestamp:         time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC),
		Event:             "secret.created",
		Outcome:           OutcomeSuccess,
		ClientIP:          "10.0.0.1",
		SecretID:          "raw-secret-key",
		UserEmail:         "user@example.com",
		UserSubject:       "sub-123",
		OneTime:           boolPtr(true),
		ExpirationSeconds: int32Ptr(3600),
		RequireAuth:       boolPtr(false),
	})
	_ = l.Sync()

	data, err := os.ReadFile(path)
	require.NoError(t, err)
	require.NotEmpty(t, data)

	var event map[string]any
	require.NoError(t, json.Unmarshal(data, &event))

	assert.Equal(t, "secret.created", event["event"])
	assert.Equal(t, "success", event["outcome"])
	assert.Equal(t, "10.0.0.1", event["client_ip"])
	assert.Equal(t, "user@example.com", event["user_email"])
	assert.Equal(t, "sub-123", event["user_subject"])
	assert.Equal(t, true, event["one_time"])
	assert.Equal(t, float64(3600), event["expiration_seconds"])
	assert.Equal(t, false, event["require_auth"])

	// secret_id must be redacted, not the raw value.
	secretID, _ := event["secret_id"].(string)
	assert.Len(t, secretID, 12)
	assert.NotEqual(t, "raw-secret-key", secretID)
	assert.Equal(t, redactSecretID("raw-secret-key"), secretID)
}

// TestNewAuditLogger_RedactEmail verifies that when redactEmail=true the
// user_email field is hashed (12-char SHA-256 prefix) instead of written in
// cleartext, while remaining stable so log analysis can correlate by user.
func TestNewAuditLogger_RedactEmail(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	l, err := NewAuditLogger(path, true)
	require.NoError(t, err)

	l.Log(AuditEvent{
		Timestamp: time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC),
		Event:     "secret.created",
		Outcome:   OutcomeSuccess,
		ClientIP:  "10.0.0.1",
		UserEmail: "user@example.com",
	})
	_ = l.Sync()

	data, err := os.ReadFile(path)
	require.NoError(t, err)

	var event map[string]any
	require.NoError(t, json.Unmarshal(data, &event))

	got, _ := event["user_email"].(string)
	assert.Len(t, got, 12)
	assert.NotEqual(t, "user@example.com", got)
	assert.NotContains(t, got, "@")
	// Stable hash so analysis tools can correlate events for the same user.
	assert.Equal(t, redactSecretID("user@example.com"), got)
}

func TestNewAuditLogger_OptionalFieldsSuppressed(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	l, err := NewAuditLogger(path, false)
	require.NoError(t, err)

	l.Log(AuditEvent{
		Timestamp: time.Now().UTC(),
		Event:     "minimal",
		Outcome:   OutcomeFailure,
		ClientIP:  "1.1.1.1",
	})
	_ = l.Sync()

	data, err := os.ReadFile(path)
	require.NoError(t, err)

	var event map[string]any
	require.NoError(t, json.Unmarshal(data, &event))

	for _, k := range []string{"secret_id", "user_email", "user_subject", "one_time", "expiration_seconds", "require_auth", "error"} {
		_, ok := event[k]
		assert.Falsef(t, ok, "field %q should be omitted when unset", k)
	}
}

func TestNewAuditLogger_InvalidPath(t *testing.T) {
	// A file inside a non-existent directory cannot be created by zap.
	_, err := NewAuditLogger(filepath.Join(t.TempDir(), "does", "not", "exist", "audit.log"), false)
	assert.Error(t, err)
}

func TestNoopAuditLogger(t *testing.T) {
	l := NewNoopAuditLogger()
	require.NotNil(t, l)
	assert.NotPanics(t, func() {
		l.Log(AuditEvent{Event: "whatever"})
	})
	assert.NoError(t, l.Sync())
}

func TestServerAuditFallback(t *testing.T) {
	s := &Server{}
	l := s.audit()
	require.NotNil(t, l)
	assert.NotPanics(t, func() {
		l.Log(AuditEvent{Event: "x"})
	})

	// When set, returns the configured logger.
	dir := t.TempDir()
	real, err := NewAuditLogger(filepath.Join(dir, "a.log"), false)
	require.NoError(t, err)
	s.Audit = real
	assert.Same(t, real, s.audit())
}

func TestSessionHelpers(t *testing.T) {
	assert.Equal(t, "", sessionEmail(nil))
	assert.Equal(t, "", sessionSub(nil))

	s := &sessionData{Sub: "sub-1", Email: "a@b.c"}
	assert.Equal(t, "a@b.c", sessionEmail(s))
	assert.Equal(t, "sub-1", sessionSub(s))
}

func TestPtrHelpers(t *testing.T) {
	b := boolPtr(true)
	require.NotNil(t, b)
	assert.True(t, *b)

	f := boolPtr(false)
	require.NotNil(t, f)
	assert.False(t, *f)

	i := int32Ptr(42)
	require.NotNil(t, i)
	assert.Equal(t, int32(42), *i)
}

