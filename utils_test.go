// Copyright 2020-2026 NGR Softlab
package ldapper

import (
	"github.com/go-ldap/ldap/v3"
)

// ---------- helpers for tests ----------

// newLDAPEntry is a helper to build *ldap.Entry with attributes.
// NB: deliberately returns *ldap.Entry (not ldap.Entry) — callers in this
// package pass it to CatalogAdapter.GetNormalizedUserInfo, which expects
// the pointer form.
func newLDAPEntry(dn string, attrs map[string][]string) *ldap.Entry {
	entry := &ldap.Entry{DN: dn}
	for name, values := range attrs {
		byteValues := make([][]byte, len(values))
		for i, v := range values {
			byteValues[i] = []byte(v)
		}
		entry.Attributes = append(entry.Attributes, &ldap.EntryAttribute{
			Name:       name,
			Values:     values,
			ByteValues: byteValues,
		})
	}
	return entry
}
