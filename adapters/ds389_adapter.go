// Copyright 2020-2026 NGR Softlab
package adapters

// DS389Adapter targets 389 Directory Server (and its upstream forks:
// Red Hat Directory Server, Oracle Directory Server Enterprise Edition,
// and other Netscape-derived servers).
//
// Schema differences from plain OpenLDAP that matter here:
//
//   - Users: alongside inetOrgPerson / posixAccount / person, 389-DS
//     entries commonly carry nsAccount / nsOrgPerson. Filtering on all
//     five classes matches every user the server would accept.
//   - Groups: the standard three models are supported — groupOfNames
//     (member, DN), groupOfUniqueNames (uniqueMember, DN) and posixGroup
//     (memberUid, short uid). This is the same shape OpenLDAP uses, so
//     the group filter is inherited.
//   - Disabled accounts: nsAccountLock: true. Unlike OpenLDAP, 389-DS
//     exposes this attribute on the user entry, so it is included in
//     UserAttrs for callers that inspect account state.
//
// Everything else (short-form bind expansion, attribute→normalized-field
// mapping, photo via jpegPhoto, address via postalAddress) is identical
// to OpenLDAP and is inherited from OPENLDAPAdapter.
type DS389Adapter struct {
	OPENLDAPAdapter
}

// UserObjectFilter extends the OpenLDAP user filter with the
// 389-DS-specific nsAccount / nsOrgPerson classes.
func (a DS389Adapter) UserObjectFilter() string {
	return "(|(objectClass=nsAccount)(objectClass=nsOrgPerson)(objectClass=posixAccount)(objectClass=inetOrgPerson)(objectClass=person))"
}

// UserAttrs adds nsAccountLock on top of the OpenLDAP list; callers that
// render "disabled" badges or filter out inactive users rely on it.
func (a DS389Adapter) UserAttrs() []string {
	return append(a.OPENLDAPAdapter.UserAttrs(), "nsAccountLock")
}
