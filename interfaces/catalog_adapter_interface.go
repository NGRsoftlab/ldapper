// Copyright 2020-2026 NGR Softlab
package interfaces

import (
	"github.com/go-ldap/ldap/v3"

	"github.com/NGRsoftlab/ldapper/types"
)

type CatalogAdapter interface {
	// cast things
	GetNormalizedUserInfo(ldapUser types.LDAPUser) *types.UserNormalizedInfo
	OUInfoFromEntry(entry ldap.Entry) *types.OUInfo

	// object type filters
	UserObjectFilter() string
	GroupObjectFilter() string
	OUObjectFilter() string

	// search filters
	SearchUserFilterTemplate() string       // NB: 1 arg
	SearchUserGroupsFilterTemplate() string // NB: N args, use with arglist unpacking
	SearchUserGroupsFilterTemplateArgs(ldapUser types.LDAPUser) []any
	SearchOUFilterTemplate() string    // NB: 1 arg
	SearchGroupFilterTemplate() string // NB: 1 arg

	// attrs
	UserAttrs() []string
	ShortUserAttrs() []string
	OUAttrs() []string
	GroupAttrs() []string
}
