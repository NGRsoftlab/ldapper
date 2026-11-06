// Copyright 2020-2026 NGR Softlab
package ldapper

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"testing"

	"github.com/go-ldap/ldap/v3"
)

// helper: build a *ldap.Error with a given result code and an optional
// underlying error. Keeps tests concise.
func ldapErr(code uint16, cause error) error {
	return &ldap.Error{ResultCode: code, Err: cause}
}

// TestClassifyLDAPError_Nil asserts the trivial passthrough.
func TestClassifyLDAPError_Nil(t *testing.T) {
	if got := classifyLDAPError(nil); got != nil {
		t.Fatalf("classifyLDAPError(nil) = %v, want nil", got)
	}
}

// TestClassifyLDAPError_LDAPCodes verifies the mapping of every LDAP result
// code branch. Both errors.Is on the sentinel and errors.As on the original
// *ldap.Error must succeed (thanks to the "%w: %w" wrapping).
func TestClassifyLDAPError_LDAPCodes(t *testing.T) {
	tests := []struct {
		name     string
		code     uint16
		sentinel error
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

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			raw := ldapErr(tc.code, errors.New("server said: "+tc.name))
			got := classifyLDAPError(raw)

			if !errors.Is(got, tc.sentinel) {
				t.Fatalf("errors.Is(%v, %v) = false", got, tc.sentinel)
			}

			// The original *ldap.Error must remain reachable via errors.As.
			var ldapTarget *ldap.Error
			if !errors.As(got, &ldapTarget) {
				t.Fatalf("errors.As did not recover *ldap.Error from %v", got)
			}
			if ldapTarget.ResultCode != tc.code {
				t.Fatalf("recovered result code = %d, want %d", ldapTarget.ResultCode, tc.code)
			}
		})
	}
}

// TestClassifyLDAPError_Transport covers the fallback branches after the
// LDAP-code switch: net.ErrClosed, generic transport, and timeout.
func TestClassifyLDAPError_Transport(t *testing.T) {
	t.Run("net.ErrClosed maps to ErrClosed", func(t *testing.T) {
		got := classifyLDAPError(net.ErrClosed)
		if !errors.Is(got, ErrClosed) {
			t.Fatalf("errors.Is(%v, ErrClosed) = false", got)
		}
	})

	t.Run("io.EOF maps to ErrUnavailable", func(t *testing.T) {
		got := classifyLDAPError(io.EOF)
		if !errors.Is(got, ErrUnavailable) {
			t.Fatalf("errors.Is(%v, ErrUnavailable) = false", got)
		}
	})

	t.Run("io.ErrUnexpectedEOF maps to ErrUnavailable", func(t *testing.T) {
		got := classifyLDAPError(io.ErrUnexpectedEOF)
		if !errors.Is(got, ErrUnavailable) {
			t.Fatalf("errors.Is(%v, ErrUnavailable) = false", got)
		}
	})

	t.Run("net.OpError maps to ErrUnavailable", func(t *testing.T) {
		raw := &net.OpError{Op: "dial", Net: "tcp", Err: errors.New("connection refused")}
		got := classifyLDAPError(raw)
		if !errors.Is(got, ErrUnavailable) {
			t.Fatalf("errors.Is(%v, ErrUnavailable) = false", got)
		}
	})

	t.Run("context deadline maps to ErrTimeout", func(t *testing.T) {
		got := classifyLDAPError(context.DeadlineExceeded)
		if !errors.Is(got, ErrTimeout) {
			t.Fatalf("errors.Is(%v, ErrTimeout) = false", got)
		}
	})

	t.Run("os.ErrDeadlineExceeded maps to ErrTimeout", func(t *testing.T) {
		got := classifyLDAPError(os.ErrDeadlineExceeded)
		if !errors.Is(got, ErrTimeout) {
			t.Fatalf("errors.Is(%v, ErrTimeout) = false", got)
		}
	})

	t.Run("timeout net.Error maps to ErrTimeout", func(t *testing.T) {
		raw := &net.DNSError{Err: "i/o timeout", Name: "x", IsTimeout: true}
		got := classifyLDAPError(raw)
		if !errors.Is(got, ErrTimeout) {
			t.Fatalf("errors.Is(%v, ErrTimeout) = false", got)
		}
	})
}

// TestClassifyLDAPError_UnknownPreserved asserts that an unrecognised error
// is returned as-is (not wrapped in a sentinel), so callers can still inspect
// the original via errors.Is / errors.As.
func TestClassifyLDAPError_UnknownPreserved(t *testing.T) {
	original := errors.New("some totally unexpected failure")
	got := classifyLDAPError(original)
	if got != original {
		t.Fatalf("classifyLDAPError did not preserve unknown error: got %v, want %v", got, original)
	}
}

// TestClassifySensitiveBindError_LDAPCodes verifies the sentinel mapping on
// the bind path. Every returned error is a bare sentinel — no wrapping, no
// raw text from the server.
func TestClassifySensitiveBindError_LDAPCodes(t *testing.T) {
	tests := []struct {
		name     string
		code     uint16
		sentinel error
	}{
		{"invalid credentials", ldap.LDAPResultInvalidCredentials, ErrInvalidCredentials},
		{"timeout", ldap.LDAPResultTimeout, ErrTimeout},
		{"time limit exceeded", ldap.LDAPResultTimeLimitExceeded, ErrTimeout},
		{"unavailable", ldap.LDAPResultUnavailable, ErrUnavailable},
		{"busy", ldap.LDAPResultBusy, ErrUnavailable},
		{"server down", ldap.LDAPResultServerDown, ErrUnavailable},
		{"insufficient access", ldap.LDAPResultInsufficientAccessRights, ErrInsufficientAccess},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			raw := ldapErr(tc.code, errors.New("raw server message that must not leak"))
			got := classifySensitiveBindError(raw)
			if !errors.Is(got, tc.sentinel) {
				t.Fatalf("errors.Is(%v, %v) = false", got, tc.sentinel)
			}
		})
	}
}

// TestClassifySensitiveBindError_DoesNotLeakSecret is the central security
// regression test: the raw error text may echo back the submitted password,
// so it must never appear in the classified result nor in any wrapped chain.
func TestClassifySensitiveBindError_DoesNotLeakSecret(t *testing.T) {
	const secret = "hunter2-Super-Secret!"

	tests := []struct {
		name string
		raw  error
	}{
		{
			name: "invalid credentials with echoed password",
			raw:  ldapErr(ldap.LDAPResultInvalidCredentials, errors.New("bind failed for password "+secret)),
		},
		{
			name: "unknown result code with echoed password",
			raw:  ldapErr(ldap.LDAPResultOther, errors.New("weird server response: "+secret)),
		},
		{
			name: "transport error with echoed password",
			raw:  &net.OpError{Op: "write", Net: "tcp", Err: errors.New("refused " + secret)},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := classifySensitiveBindError(tc.raw)
			if got == nil {
				t.Fatal("classifySensitiveBindError returned nil")
			}

			if strings.Contains(got.Error(), secret) {
				t.Fatalf("secret leaked in error text: %v", got)
			}

			// Walk every wrapped error to be defensive against future
			// changes that add %w wrapping to the bind path.
			for e := errors.Unwrap(got); e != nil; e = errors.Unwrap(e) {
				if strings.Contains(e.Error(), secret) {
					t.Fatalf("secret leaked in wrapped chain: %v", e)
				}
			}
		})
	}
}

// TestClassifySensitiveBindError_UnknownFallsBackToInvalidCredentials verifies
// the conservative default: an unrecognised bind failure is reported as
// ErrInvalidCredentials rather than leaking server details.
func TestClassifySensitiveBindError_UnknownFallsBackToInvalidCredentials(t *testing.T) {
	raw := ldapErr(ldap.LDAPResultOther, errors.New("nothing useful"))
	got := classifySensitiveBindError(raw)
	if !errors.Is(got, ErrInvalidCredentials) {
		t.Fatalf("errors.Is(%v, ErrInvalidCredentials) = false", got)
	}
}

// TestIsTimeoutError covers the timeout predicate directly.
func TestIsTimeoutError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"plain error", errors.New("boom"), false},
		{"context deadline", context.DeadlineExceeded, true},
		{"os deadline", os.ErrDeadlineExceeded, true},
		{"timeout net.Error", &net.DNSError{IsTimeout: true, Name: "x"}, true},
		{"non-timeout net.Error", &net.DNSError{IsTimeout: false, Name: "x"}, false},
		{"io.EOF", io.EOF, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := isTimeoutError(tc.err); got != tc.want {
				t.Fatalf("isTimeoutError(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

// TestIsTransportError covers the transport predicate: anything originating
// from the network layer, including timeouts, must report true.
func TestIsTransportError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"plain error", errors.New("boom"), false},
		{"timeout inherited", context.DeadlineExceeded, true},
		{"io.EOF", io.EOF, true},
		{"io.ErrUnexpectedEOF", io.ErrUnexpectedEOF, true},
		{"net.ErrClosed", net.ErrClosed, true},
		{"net.OpError", &net.OpError{Op: "dial", Net: "tcp", Err: errors.New("refused")}, true},
		{"syscall error", &os.SyscallError{Syscall: "read", Err: errors.New("reset")}, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := isTransportError(tc.err); got != tc.want {
				t.Fatalf("isTransportError(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}
