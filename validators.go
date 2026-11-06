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

// validateDN checks that dn parses as a syntactically valid distinguished name.
// It does NOT normalize or escape the value — DN escaping (RFC 4514) differs
// from filter escaping (RFC 4515), so the original string is passed to the
// server as-is once validated.
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

func formatHost(host string) string {
	if ip := net.ParseIP(host); ip != nil && ip.To4() == nil {
		return "[" + host + "]" // IPv6 literal: brackets required by RFC 3986
	}
	return host
}

// validateHost rejects host strings containing URL-special characters.
// Accepts IPv4, IPv6 (without brackets — go-ldap handles formatting) and
// DNS names. Empty host is also rejected.
func validateHost(host string) error {
	if host == "" {
		return fmt.Errorf("%w: empty host", ErrInvalidArgument)
	}

	if net.ParseIP(host) != nil {
		if strings.ContainsAny(host, "/@#?[]") {
			return fmt.Errorf("%w: invalid host %q", ErrInvalidArgument, host)
		}
	} else {
		if strings.ContainsAny(host, "/@#?:[]") {
			return fmt.Errorf("%w: invalid host %q", ErrInvalidArgument, host)
		}
	}

	return nil
}
