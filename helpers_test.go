// Copyright 2020-2026 NGR Softlab
package ldapper

import (
	"github.com/go-ldap/ldap/v3"

	"github.com/NGRsoftlab/ldapper/adapters"
)

func newTestConnection(adapter adapters.CatalogAdapter, conn LDAPConn) *LDAPConnection {
	return &LDAPConnection{catalogAdapter: adapter, connection: conn}
}

// newLDAPEntry is a helper to build *ldap.Entry with attributes.
func newLDAPEntry(dn string, attrs map[string][]string) *ldap.Entry {
	entry := &ldap.Entry{DN: dn}
	for name, values := range attrs {
		entry.Attributes = append(entry.Attributes, &ldap.EntryAttribute{Name: name, Values: values})
	}
	return entry
}
