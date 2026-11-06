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
}
