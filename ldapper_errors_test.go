// Copyright 2020-2026 NGR Softlab
package ldapper

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"testing"

	"github.com/go-ldap/ldap/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeNetError is a minimal net.Error implementation for driving
// isTimeoutError / isTransportError without touching real sockets.
type fakeNetError struct {
	msg     string
	timeout bool
}

func (e *fakeNetError) Error() string   { return e.msg }
func (e *fakeNetError) Timeout() bool   { return e.timeout }
func (e *fakeNetError) Temporary() bool { return false }

// --- isTimeoutError ---

func TestIsTimeoutError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		err  error
		want bool
	}{
		{name: "nil", err: nil, want: false},
		{name: "context.DeadlineExceeded", err: context.DeadlineExceeded, want: true},
		{name: "os.ErrDeadlineExceeded", err: os.ErrDeadlineExceeded, want: true},
		{name: "wrapped DeadlineExceeded", err: fmt.Errorf("op: %w", context.DeadlineExceeded), want: true},
		{name: "net.Error with timeout", err: &fakeNetError{msg: "t/o", timeout: true}, want: true},
		{name: "net.Error without timeout", err: &fakeNetError{msg: "x", timeout: false}, want: false},
		{name: "plain error", err: errors.New("boom"), want: false},
		{name: "context.Canceled is not a timeout", err: context.Canceled, want: false},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, isTimeoutError(tt.err))
		})
	}
}

// --- isTransportError ---

func TestIsTransportError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		err  error
		want bool
	}{
		{name: "nil", err: nil, want: false},
		{name: "io.EOF", err: io.EOF, want: true},
		{name: "io.ErrUnexpectedEOF", err: io.ErrUnexpectedEOF, want: true},
		{name: "net.ErrClosed", err: net.ErrClosed, want: true},
		{name: "context.DeadlineExceeded", err: context.DeadlineExceeded, want: true},
		{name: "os.ErrDeadlineExceeded", err: os.ErrDeadlineExceeded, want: true},
		{name: "wrapped EOF", err: fmt.Errorf("read: %w", io.EOF), want: true},
		{name: "net.Error", err: &fakeNetError{msg: "conn reset", timeout: false}, want: true},
		{
			name: "os.SyscallError",
			err:  &os.SyscallError{Syscall: "read", Err: errors.New("syscall fail")},
			want: true,
		},
		{name: "context.Canceled", err: context.Canceled, want: false},
		{name: "plain error", err: errors.New("boom"), want: false},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, isTransportError(tt.err))
		})
	}
}

// --- classifyLDAPError ---

func TestClassifyLDAPError_Nil(t *testing.T) {
	t.Parallel()
	assert.NoError(t, classifyLDAPError(nil))
}

func TestClassifyLDAPError_LDAPResultCodes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		code     uint16
		expected error
	}{
		{"invalid credentials", ldap.LDAPResultInvalidCredentials, ErrInvalidCredentials},
		{"timeout", ldap.LDAPResultTimeout, ErrTimeout},
		{"time limit exceeded", ldap.LDAPResultTimeLimitExceeded, ErrTimeout},
		{"unavailable", ldap.LDAPResultUnavailable, ErrUnavailable},
		{"busy", ldap.LDAPResultBusy, ErrUnavailable},
		{"server down", ldap.LDAPResultServerDown, ErrUnavailable},
		{"size limit exceeded", ldap.LDAPResultSizeLimitExceeded, ErrPartialResult},
		{"no such object", ldap.LDAPResultNoSuchObject, ErrNotFound},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			orig := ldap.NewError(tt.code, errors.New("server diagnostic"))
			got := classifyLDAPError(orig)

			require.Error(t, got)
			assert.ErrorIs(t, got, tt.expected)

			// The original error must remain in the chain: callers rely on
			// errors.As(*ldap.Error) to reach the raw code / diagnostics.
			var ldapErr *ldap.Error
			assert.ErrorAs(t, got, &ldapErr)
		})
	}
}

func TestClassifyLDAPError_ContextCanceledPassesThrough(t *testing.T) {
	t.Parallel()

	got := classifyLDAPError(context.Canceled)
	require.Error(t, got)
	assert.ErrorIs(t, got, context.Canceled)
	// context.Canceled is surfaced verbatim (not wrapped into a sentinel):
	// it carries no credential material and callers check it directly.
	assert.Equal(t, context.Canceled, got)
}

func TestClassifyLDAPError_NetClosedMapsToErrClosed(t *testing.T) {
	t.Parallel()

	wrapped := fmt.Errorf("read: %w", net.ErrClosed)
	got := classifyLDAPError(wrapped)

	require.Error(t, got)
	assert.ErrorIs(t, got, ErrClosed)
	assert.ErrorIs(t, got, net.ErrClosed)
}

func TestClassifyLDAPError_TransportTimeout(t *testing.T) {
	t.Parallel()

	orig := &fakeNetError{msg: "i/o timeout", timeout: true}
	got := classifyLDAPError(orig)

	require.Error(t, got)
	assert.ErrorIs(t, got, ErrTimeout)
	var netErr net.Error
	assert.ErrorAs(t, got, &netErr)
}

func TestClassifyLDAPError_TransportNonTimeout(t *testing.T) {
	t.Parallel()

	orig := fmt.Errorf("dial: %w", io.EOF)
	got := classifyLDAPError(orig)

	require.Error(t, got)
	assert.ErrorIs(t, got, ErrUnavailable)
	assert.ErrorIs(t, got, io.EOF)
}

func TestClassifyLDAPError_UnknownPassesThrough(t *testing.T) {
	t.Parallel()

	orig := errors.New("something else")
	got := classifyLDAPError(orig)

	assert.Equal(t, orig, got)
}

// --- classifySensitiveBindError ---

func TestClassifySensitiveBindError_Nil(t *testing.T) {
	t.Parallel()
	assert.NoError(t, classifySensitiveBindError(nil))
}

func TestClassifySensitiveBindError_LDAPResultCodes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		code     uint16
		expected error
	}{
		{"invalid credentials", ldap.LDAPResultInvalidCredentials, ErrInvalidCredentials},
		{"timeout", ldap.LDAPResultTimeout, ErrTimeout},
		{"time limit exceeded", ldap.LDAPResultTimeLimitExceeded, ErrTimeout},
		{"unavailable", ldap.LDAPResultUnavailable, ErrUnavailable},
		{"busy", ldap.LDAPResultBusy, ErrUnavailable},
		{"server down", ldap.LDAPResultServerDown, ErrUnavailable},
		{"insufficient access", ldap.LDAPResultInsufficientAccessRights, ErrInsufficientAccess},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// Build *ldap.Error directly: Error's fields are public and
			// stable across go-ldap v3, and this bypasses any version
			// quirks in ldap.NewError. classifySensitiveBindError only
			// reads ResultCode, so the shape is sufficient.
			orig := &ldap.Error{
				ResultCode: tt.code,
				Err:        errors.New("password=secret123"),
			}

			got := classifySensitiveBindError(orig)

			require.Error(t, got)
			// Standard-library errors.Is, not testify's wrapper: no
			// reflection, no version-specific behaviour.
			require.True(t, errors.Is(got, tt.expected),
				"expected errors.Is(got, %v), got %q", tt.expected, got.Error())

			// Masking: the diagnostic must not leak through the result.
			msg := got.Error()
			assert.False(t, strings.Contains(msg, "secret123"),
				"error text must not echo the submitted password: %q", msg)
			assert.False(t, strings.Contains(msg, "password="),
				"error text must not echo a password= marker: %q", msg)
		})
	}
}

func TestClassifySensitiveBindError_ContextCanceledPassesThrough(t *testing.T) {
	t.Parallel()

	got := classifySensitiveBindError(context.Canceled)
	assert.Equal(t, context.Canceled, got)
}

func TestClassifySensitiveBindError_NetClosedMapsToErrClosed(t *testing.T) {
	t.Parallel()

	got := classifySensitiveBindError(net.ErrClosed)
	assert.ErrorIs(t, got, ErrClosed)
	// Sensitive path returns the sentinel bare (no wrapping) — no
	// server-side text can sneak in.
	assert.Equal(t, ErrClosed, got)
}

func TestClassifySensitiveBindError_TransportTimeout(t *testing.T) {
	t.Parallel()

	got := classifySensitiveBindError(&fakeNetError{msg: "i/o timeout", timeout: true})
	assert.Equal(t, ErrTimeout, got)
}

func TestClassifySensitiveBindError_TransportNonTimeout(t *testing.T) {
	t.Parallel()

	got := classifySensitiveBindError(fmt.Errorf("dial: %w", io.EOF))
	assert.Equal(t, ErrUnavailable, got)
}

func TestClassifySensitiveBindError_UnknownMasked(t *testing.T) {
	t.Parallel()

	// LDAPResultOther / unknown codes must not be surfaced: RFC 4513
	// diagnosticMessage may echo the submitted credentials.
	orig := ldap.NewError(ldap.LDAPResultOther, errors.New("password=secret123"))
	got := classifySensitiveBindError(orig)

	assert.ErrorIs(t, got, ErrInvalidCredentialsOrUnknown)
	assert.NotContains(t, got.Error(), "secret123")
}
