// Copyright 2020-2026 NGR Softlab
package ldapper

import (
	"testing"

	"github.com/go-ldap/ldap/v3"

	"github.com/NGRsoftlab/ldapper/interfaces"
	"github.com/NGRsoftlab/ldapper/mocks"
)

// ---------- helpers for tests ----------

// newDialableLDAPper builds an LDAPper suitable for tests where dialURL is
// mocked to succeed. skipTLS is required: StartTLS on the empty *ldap.Conn
// returned by the mock would block forever on a nil channel.
func newDialableLDAPper(hosts []string) *LDAPper {
	return &LDAPper{hosts: hosts, port: 389, skipTLS: true} // NB: StartTLS on the mocked empty *ldap.Conn blocks forever
}

func newTestConnection(adapter interfaces.CatalogAdapter, conn interfaces.LDAPConn) *LDAPper {
	return &LDAPper{catalogAdapter: adapter, connection: conn}
}

// newLDAPEntry is a helper to build *ldap.Entry with attributes.
func newLDAPEntry(dn string, attrs map[string][]string) *ldap.Entry {
	entry := &ldap.Entry{DN: dn}
	for name, values := range attrs {
		entry.Attributes = append(entry.Attributes, &ldap.EntryAttribute{Name: name, Values: values})
	}
	return entry
}

// withMockDialURL temporarily replaces the package-level dialURL with fn and
// restores the original value when the test finishes.
func withMockDialURL(t *testing.T, fn func(uri string, opts ...ldap.DialOpt) (*ldap.Conn, error)) {
	t.Helper()
	original := dialURL
	dialURL = fn
	t.Cleanup(func() { dialURL = original })
}

// mockOUs returns a mock connection whose SearchFunc returns the given entries
// with no paging controls. Suitable for single-page tree-building tests.
func mockOUs(entries ...*ldap.Entry) *mocks.MockLDAPConn {
	return &mocks.MockLDAPConn{
		SearchFunc: func(*ldap.SearchRequest) (*ldap.SearchResult, error) {
			return &ldap.SearchResult{Entries: entries}, nil
		},
	}
}
