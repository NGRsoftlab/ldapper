// Copyright 2020-2026 NGR Softlab
package adapters

// OpenDJAdapter targets OpenDJ (ForgeRock / Open Identity Platform).
//
// OpenDJ's group model is the standard LDAP one:
//
//   - groupOfNames       → member (DN)
//   - groupOfUniqueNames → uniqueMember (DN)
//   - posixGroup         → memberUid (short uid)
//
// which is exactly what OPENLDAPAdapter already covers — so the group
// filter, GroupAttrs, and short-form bind expansion are inherited.
//
// The one OpenDJ-specific detail worth surfacing is the virtual
// isMemberOf attribute: OpenDJ generates it on user entries (and group
// entries), listing the DNs of the groups the user belongs to. It is
// not part of the schema on disk; the server computes it. Requesting it
// in UserAttrs lets callers read group membership directly from the
// user entry without a separate search.
type OpenDJAdapter struct {
	OPENLDAPAdapter
}

// UserAttrs adds the virtual isMemberOf attribute. It is harmless on
// servers that do not implement it (the attribute is simply absent),
// which keeps the adapter compatible with plain OpenLDAP too.
func (a OpenDJAdapter) UserAttrs() []string {
	return append(a.OPENLDAPAdapter.UserAttrs(), "isMemberOf")
}
