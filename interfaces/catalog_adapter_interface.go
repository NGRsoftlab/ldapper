// Copyright 2020-2026 NGR Softlab
package interfaces

import (
	"github.com/go-ldap/ldap/v3"

	"github.com/NGRsoftlab/ldapper/types"
)

type CatalogAdapter interface {
	// cast things
	GetNormalizedUserInfo(ldapUser types.LDAPUser) *types.UserNormalizedInfo
	GetNormalizedOUInfoFromEntry(entry ldap.Entry) *types.OUNormalizedInfo

	// object type filters
	UserObjectFilter() string
	GroupObjectFilter() string
	OUObjectFilter() string

	// Search filters
	//
	// Contract: templates use fmt-style verbs (%s or %[N]s). All arguments
	// passed via SearchUserGroupsFilterTemplateArgs (or applied by LDAPper
	// methods) are escaped with ldap.EscapeFilter before substitution, so
	// implementers must return raw (unescaped) attribute values.
	SearchUserFilterTemplate() string       // NB: 1 arg
	SearchUserGroupsFilterTemplate() string // NB: N args, use with SearchUserGroupsFilterTemplateArgs unpacking
	SearchUserGroupsFilterTemplateArgs(ldapUser types.LDAPUser) []any
	SearchOUFilterTemplate() string    // NB: 1 arg
	SearchGroupFilterTemplate() string // NB: 1 arg

	// attrs
	UserAttrs() []string
	OUAttrs() []string
	GroupAttrs() []string

	// BindIdentity converts a caller-supplied login into the principal that
	// is passed verbatim to LDAPConn.Bind. The adapter decides the form:
	//
	//   - MSAD / ALDPro: accept UPN, sAMAccountName or DN → the login is
	//                    passed through; the server performs the mapping.
	//   - OpenLDAP:      requires a DN → "uid=<login>,<baseDN>" when
	//                    <login> is not already a DN.
	//   - FreeIPA:       requires a DN → "uid=<login>,cn=users,cn=accounts,
	//                    <baseDN>" when <login> is not already a DN.
	//
	// The lookup uses the ORIGINAL login (not the value returned by
	// BindIdentity), so SearchUserFilterTemplate must accept every form
	// that BindIdentity accepts — typically by unioning the schema
	// attribute with an entryDN alternative (see the shipped adapters).
	//
	// Returning an error lets the adapter reject inputs it cannot map to
	// a bind principal (e.g. a short-form login with an empty baseDN).
	BindIdentity(login, baseDN string) (string, error)
}

// PrimaryGroupResolver is implemented by adapters that need custom logic
// to resolve a user's primary group (e.g., Active Directory).
type PrimaryGroupResolver interface {
	// ResolvePrimaryGroupDN takes a user entry and returns the DN of the user's
	// primary group. The ldapConn is provided for any extra LDAP searches needed.
	ResolvePrimaryGroupDN(user types.LDAPUser, ldapConn LDAPConn) (string, error)
}
