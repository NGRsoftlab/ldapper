// Copyright 2020-2026 NGR Softlab
package ldapper

import "github.com/go-ldap/ldap/v3"

type CatalogAdapter interface {
	// cast things
	GetNormalizedUserInfo(ldapUser LDAPUser) *UserNormalizedInfo
	OUInfoFromEntry(entry ldap.Entry) *OUInfo

	// object type filters
	UserObjectFilter() string
	GroupObjectFilter() string
	OUObjectFilter() string

	// search filters
	SearchUserFilterTemplate() string       // NB: 1 arg
	SearchUserGroupsFilterTemplate() string // NB: N args, use with arglist unpacking
	SearchUserGroupsFilterTemplateArgs(ldapUser LDAPUser) []any
	SearchOUFilterTemplate() string    // NB: 1 arg
	SearchGroupFilterTemplate() string // NB: 1 arg

	// attrs
	UserAttrs() []string
	ShortUserAttrs() []string
	OUAttrs() []string
	GroupAttrs() []string
}
