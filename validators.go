// Copyright 2020-2026 NGR Softlab
package ldapper

import (
	"fmt"
	"net"
	"strings"

	"github.com/go-ldap/ldap/v3"
)

// requireConnLocked returns ErrClosed if no live connection object exists.
// Caller must hold opMu.
func (ldapper *LDAPper) requireConnLocked() error {
	if ldapper.closed {
		return fmt.Errorf("%w: client is closed", ErrClosed)
	}
	if ldapper.connection == nil {
		return fmt.Errorf("%w: connection not initialized", ErrClosed)
	}
	return nil
}

// requireAuthLocked returns ErrNotAuthenticated if the connection has no bound user.
// Caller must hold opMu.
func (ldapper *LDAPper) requireAuthLocked() error {
	if err := ldapper.requireConnLocked(); err != nil {
		return err
	}
	if !ldapper.isAuthenticated {
		return ErrNotAuthenticated
	}
	return nil
}

// validateDN checks that dn parses as a syntactically valid distinguished
// name. It does NOT normalize or escape the value — DN escaping (RFC 4514)
// differs from filter escaping (RFC 4515), so the original string is passed
// to the server as-is once validated.
//
// The empty string is syntactically valid: per RFC 4514 it denotes the root
// DSE (the base of the directory tree). Callers that would treat an empty
// DN as a caller bug — most search methods, where an empty base means "the
// whole tree" — must use validateBaseDN, which additionally rejects "".
func validateDN(dn string) error {
	if _, err := ldap.ParseDN(dn); err != nil {
		return fmt.Errorf("%w: invalid DN %q: %v", ErrInvalidArgument, dn, err)
	}
	return nil
}

// validators.go
// validateBaseDN is the strict variant used by search methods: an empty DN
// would trigger a full-tree search, which is almost always a caller bug.
// Use validateDN directly for probes (e.g. root DSE).
func validateBaseDN(dn string) error {
	if dn == "" {
		return fmt.Errorf("%w: empty base DN", ErrInvalidArgument)
	}
	return validateDN(dn)
}

// isIPLiteral reports whether host parses as an IP address (IPv4 or IPv6,
// including scoped forms — though scoped literals are rejected later by
// validateHost's charset check; see comment there). The second return value
// is the parsed net.IP, or nil when host is a DNS name.
//
// Extracted so validateHost and formatHost share the same detection logic:
// before this, both called net.ParseIP independently and could drift apart
// (formatHost has no "reject anything" branch, so it silently falls through
// to "DNS" for garbage — which is fine for formatting, but the detection
// rule itself should be single-sourced).
func isIPLiteral(host string) (net.IP, bool) {
	ip := net.ParseIP(host)
	return ip, ip != nil
}

// formatHost renders host in the form expected by net.JoinHostPort: IPv6
// literals are bracketed (RFC 3986), IPv4 and DNS names pass through
// unchanged. It does NOT validate — validateHost is the gatekeeper.
//
// A scoped IPv6 literal (fe80::1%eth0) is not parsed by net.ParseIP and
// therefore falls through unbracketed; this never reaches production code
// because validateHost rejects scoped literals upstream.
func formatHost(host string) string {
	ip, ok := isIPLiteral(host)
	if ok && ip.To4() == nil {
		return "[" + host + "]" // IPv6 literal: brackets required by RFC 3986
	}
	return host
}

// validateHost rejects host strings containing URL-special characters.
// Accepts IPv4, IPv6 (without brackets — go-ldap handles formatting) and
// DNS names. Empty host is also rejected.
//
// The charset checks are intentionally different for IPs and DNS names:
//
//   - IP literal (net.ParseIP succeeds): '[' ']' ':' are rejected even
//     though ':' is part of every IPv6 literal — brackets must be added by
//     formatHost, not present in the input, and a port is a separate
//     parameter (uint). "/@#?" are rejected unconditionally.
//   - DNS name: all of "/@#?:[]" are rejected. ':' in a DNS name is never
//     valid; net.JoinHostPort would emit "host:389:636"-style corruption.
//
// IPv6 scoped literals (fe80::1%eth0) are NOT supported: net.ParseIP does
// not understand the "%zone" suffix, so the input falls into the DNS branch
// and is rejected on the ":" character. This is a deliberate limitation —
// scope IDs are link-local-only and never appropriate for a directory
// service URI. Use a globally routable IPv6 address instead.
func validateHost(host string) error {
	if host == "" {
		return fmt.Errorf("%w: empty host", ErrInvalidArgument)
	}

	_, isIP := isIPLiteral(host)
	forbidden := "/@#?"
	if isIP {
		// Add brackets — an IP literal in "input form" never carries them;
		// formatHost supplies brackets when building the URI.
		forbidden += "[]"
	} else {
		// DNS names additionally cannot contain ':' (port is separate) or
		// brackets (which only apply to IPv6 literals).
		forbidden += ":[]"
	}
	if strings.ContainsAny(host, forbidden) {
		return fmt.Errorf("%w: invalid host %q", ErrInvalidArgument, host)
	}
	return nil
}
