// Copyright 2020-2026 NGR Softlab
package ldapper

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"

	"github.com/go-ldap/ldap/v3"
)

var (
	// Input/config validation
	ErrInvalidArgument = errors.New("invalid argument")

	// Authentication & authorization
	// ErrInvalidCredentials is returned on a bind failure that was classified
	// as a credential rejection with high confidence (LDAP result code 49).
	ErrInvalidCredentials = errors.New("invalid credentials")
	// ErrInvalidCredentialsOrUnknown is returned by the bind-path classifier
	// when the server returned an LDAP result code that could not be mapped
	// to a specific sentinel. The underlying code is deliberately not exposed
	// to avoid leaking server-side details (RFC 4513 §4.2: diagnosticMessage
	// may echo the submitted credentials).
	//
	// Callers that need a boolean "credentials rejected" decision should treat
	// this error as inconclusive, not as a rejection.
	ErrInvalidCredentialsOrUnknown = errors.New("invalid credentials or unknown error")
	ErrNotAuthenticated            = errors.New("connection not authenticated")

	// Transport / availability
	ErrUnavailable = errors.New("directory unavailable")
	ErrTimeout     = errors.New("operation timed out")
	ErrClosed      = errors.New("connection closed or not initialized")

	// Result shape
	// ErrNotFound means the object is definitively absent — the LDAP server
	// returned a no-such-object result code or an equivalent definitive signal.
	ErrNotFound = errors.New("not found")

	// ErrNotFoundOrNotVisible means a search returned zero entries. The object
	// either does not exist or is hidden by access controls; LDAP does not
	// distinguish these cases at the search layer, so callers MUST treat this
	// as "cannot determine existence". Do not infer "user does not exist" from
	// this error in security-sensitive paths.
	ErrNotFoundOrNotVisible = errors.New("not found or not visible")
	ErrAmbiguousResult      = errors.New("ambiguous result")
	ErrPartialResult        = errors.New("partial result")

	// Smth strange :)
	ErrInsufficientAccess = errors.New("insufficient access rights")
)

// isTimeoutError reports whether err represents a timeout / deadline condition.
func isTimeoutError(err error) bool {
	if err == nil {
		return false
	}
	// context.DeadlineExceeded and os.ErrDeadlineExceeded are the same
	// class since Go 1.15, but check both for clarity / robustness.
	if errors.Is(err, context.DeadlineExceeded) ||
		errors.Is(err, os.ErrDeadlineExceeded) {
		return true
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}
	return false
}

// isTransportError reports whether err originates from the network layer
// (connection failure, timeout, broken pipe, EOF) rather than from an LDAP
// protocol response. Useful to distinguish "server unavailable" from
// "credentials rejected" in security-sensitive paths where raw error text
// must not be exposed.
func isTransportError(err error) bool {
	if err == nil {
		return false
	}
	switch {
	case errors.Is(err, io.EOF),
		errors.Is(err, io.ErrUnexpectedEOF),
		errors.Is(err, net.ErrClosed),
		errors.Is(err, context.DeadlineExceeded),
		errors.Is(err, os.ErrDeadlineExceeded):
		return true
	}
	// Any net.Error (including *net.OpError and timeout wrappers).
	var netErr net.Error
	if errors.As(err, &netErr) {
		return true
	}
	var syscallErr *os.SyscallError
	if errors.As(err, &syscallErr) {
		return true
	}
	return false
}

// classifyLDAPError maps transport/protocol errors to public sentinels.
// The original error is preserved in the chain so callers can still
// errors.As() it to *ldap.Error or net.Error.
func classifyLDAPError(err error) error {
	if err == nil {
		return nil
	}

	switch {
	case ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials):
		return fmt.Errorf("%w: %w", ErrInvalidCredentials, err)

	case ldap.IsErrorWithCode(err, ldap.LDAPResultTimeout),
		ldap.IsErrorWithCode(err, ldap.LDAPResultTimeLimitExceeded):
		return fmt.Errorf("%w: %w", ErrTimeout, err)

	case ldap.IsErrorWithCode(err, ldap.LDAPResultUnavailable),
		ldap.IsErrorWithCode(err, ldap.LDAPResultBusy),
		ldap.IsErrorWithCode(err, ldap.LDAPResultServerDown):
		return fmt.Errorf("%w: %w", ErrUnavailable, err)

	case ldap.IsErrorWithCode(err, ldap.LDAPResultSizeLimitExceeded):
		return fmt.Errorf("%w: %w", ErrPartialResult, err)

	case ldap.IsErrorWithCode(err, ldap.LDAPResultNoSuchObject):
		return fmt.Errorf("%w: %w", ErrNotFound, err)
	}

	// context.Canceled is safe to surface: it carries no credentials.
	if errors.Is(err, context.Canceled) {
		return err
	}

	// Handle net.ErrClosed before the general transport check so callers can
	// distinguish "connection was closed" from "connection failed".
	if errors.Is(err, net.ErrClosed) {
		return fmt.Errorf("%w: %w", ErrClosed, err)
	}

	if isTransportError(err) {
		if isTimeoutError(err) {
			return fmt.Errorf("%w: %w", ErrTimeout, err)
		}
		return fmt.Errorf("%w: %w", ErrUnavailable, err)
	}

	return err
}

// classifySensitiveBindError is the bind-path counterpart: it classifies
// based on result code but never includes the underlying error text, which
// may echo back the submitted credentials.
func classifySensitiveBindError(err error) error {
	if err == nil {
		return nil
	}

	switch {
	case ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials):
		return ErrInvalidCredentials
	case ldap.IsErrorWithCode(err, ldap.LDAPResultTimeout),
		ldap.IsErrorWithCode(err, ldap.LDAPResultTimeLimitExceeded):
		return ErrTimeout
	case ldap.IsErrorWithCode(err, ldap.LDAPResultUnavailable),
		ldap.IsErrorWithCode(err, ldap.LDAPResultBusy),
		ldap.IsErrorWithCode(err, ldap.LDAPResultServerDown):
		return ErrUnavailable
	case ldap.IsErrorWithCode(err, ldap.LDAPResultInsufficientAccessRights):
		return ErrInsufficientAccess
	}

	// context.Canceled is safe to surface: it carries no credentials.
	if errors.Is(err, context.Canceled) {
		return err
	}

	// Handle net.ErrClosed before the general transport check so callers can
	// distinguish "connection was closed" from "connection failed".
	if errors.Is(err, net.ErrClosed) {
		return ErrClosed
	}

	// Network-layer failures are safe to expose: they don't echo credentials.
	if isTransportError(err) {
		if isTimeoutError(err) {
			return ErrTimeout
		}
		return ErrUnavailable
	}

	// LDAPResultOther and unknown codes: mask as credential rejection or unknown error.
	return ErrInvalidCredentialsOrUnknown
}
