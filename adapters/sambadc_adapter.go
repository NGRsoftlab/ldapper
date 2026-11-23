// Copyright 2020-2026 NGR Softlab
package adapters

import (
	"github.com/go-ldap/ldap/v3"

	"github.com/NGRsoftlab/ldapper/types"
)

// SAMBAAdapter targets Samba 4 AD DC.
//
// Samba 4 AD DC presents an Active Directory-compatible LDAP schema: the
// user / group / OU object classes and the key attributes (sAMAccountName,
// userPrincipalName, objectSid, primaryGroupID, objectCategory, ...) are
// identical to Microsoft AD. Group expansion via
// LDAP_MATCHING_RULE_IN_CHAIN (1.2.840.113556.1.4.1941) is supported in
// Samba 4.11+; this is the same OID MSADAdapter uses.
//
// Because the schema is a strict superset of the AD one, SAMBAAdapter
// embeds MSADAdapter and inherits every method — including
// PrimaryGroupResolver.ResolvePrimaryGroupDN — without duplication.
type SAMBAAdapter struct {
	MSADAdapter
}

// Compile-time guard: Samba must expose exactly the AD contract.
var _ interface {
	GetNormalizedUserInfo(types.LDAPUser) *types.UserNormalizedInfo
	GetNormalizedOUInfoFromEntry(ldap.Entry) *types.OUNormalizedInfo
	UserObjectFilter() string
	GroupObjectFilter() string
	OUObjectFilter() string
	SearchUserFilterTemplate() string
	SearchUserGroupsFilterTemplate() string
	SearchUserGroupsFilterTemplateArgs(types.LDAPUser) []any
	SearchOUFilterTemplate() string
	SearchGroupFilterTemplate() string
	UserAttrs() []string
	OUAttrs() []string
	GroupAttrs() []string
	BindIdentity(login, baseDN string) (string, error)
} = SAMBAAdapter{}
