// Copyright 2020-2026 NGR Softlab
package adapters

import (
	"fmt"
	"strings"

	"github.com/go-ldap/ldap/v3"

	"github.com/NGRsoftlab/ldapper/interfaces"
	"github.com/NGRsoftlab/ldapper/types"
)

type MSADAdapter struct{}

// CAST

func (a MSADAdapter) GetNormalizedUserInfo(ldapUser types.LDAPUser) *types.UserNormalizedInfo {
	return &types.UserNormalizedInfo{
		DistinguishedName: ldapUser.DN,
		CommonName:        ldapUser.GetAttributeValue("cn"),
		Mobile:            ldapUser.GetAttributeValue("mobile"),
		Phone:             ldapUser.GetAttributeValue("telephoneNumber"),
		Mail:              ldapUser.GetAttributeValue("mail"),
		Department:        ldapUser.GetAttributeValue("department"),
		Title:             ldapUser.GetAttributeValue("title"),
		Manager:           ldapUser.GetAttributeValue("manager"),
		Photo:             ldapUser.GetFirstNonNullAttributeRawValue([]string{"thumbnailPhoto", "jpegPhoto"}),
		Company:           ldapUser.GetAttributeValue("company"),
		Country:           ldapUser.GetAttributeValue("co"),
		Address:           ldapUser.GetAttributeValue("streetAddress"),
		City:              ldapUser.GetAttributeValue("l"),
		Index:             ldapUser.GetAttributeValue("postalCode"),
	}
}

func (a MSADAdapter) GetNormalizedOUInfoFromEntry(entry ldap.Entry) *types.OUNormalizedInfo {
	return &types.OUNormalizedInfo{
		DN:       entry.DN,
		Name:     ouNameFromDN(entry.DN),
		OU:       entry.DN,
		Children: make([]*types.OUNormalizedInfo, 0),
	}
}

// BIND

// BindIdentity passes the login through unchanged: AD accepts UPN,
// sAMAccountName and DN as Simple Bind principals, so no transformation is
// needed. SearchUserFilterTemplate unions sAMAccountName, userPrincipalName
// and distinguishedName so that all three forms are matched during the
// post-bind lookup.
func (a MSADAdapter) BindIdentity(login, _ string) (string, error) {
	if login == "" {
		return "", fmt.Errorf("empty login")
	}
	return login, nil
}

// TYPE FILTERS

func (a MSADAdapter) OUObjectFilter() string {
	return "(&(objectClass=organizationalUnit))"
}

func (a MSADAdapter) GroupObjectFilter() string {
	return "(&(objectCategory=group))"
}

func (a MSADAdapter) UserObjectFilter() string {
	return "(&(objectClass=user)(objectCategory=person))"
}

// SEARCH

func (a MSADAdapter) SearchUserFilterTemplate() string {
	// Match by sAMAccountName OR userPrincipalName OR distinguishedName so
	// that any principal accepted by BindIdentity can be resolved back to
	// the user entry.
	return "(&(objectCategory=person)(objectClass=user)(|(sAMAccountName=%[1]s)(userPrincipalName=%[1]s)(distinguishedName=%[1]s)))"
}

func (a MSADAdapter) SearchUserGroupsFilterTemplate() string {
	return "(&(objectCategory=group)(member:1.2.840.113556.1.4.1941:=%[1]s))"
}

func (a MSADAdapter) SearchUserGroupsFilterTemplateArgs(ldapUser types.LDAPUser) []any {
	return []any{ldapUser.DN}
}

func (a MSADAdapter) SearchOUFilterTemplate() string {
	return "(&(objectClass=organizationalUnit)(ou=%[1]s))"
}

func (a MSADAdapter) SearchGroupFilterTemplate() string {
	return "(&(objectCategory=group)(cn=%[1]s))"
}

// ATTRS

func (a MSADAdapter) UserAttrs() []string {
	return []string{
		// common
		"cn",
		"distinguishedName",

		// primary group
		"primaryGroupID",

		// personal
		"name",
		"sAMAccountName",
		"userPrincipalName",
		"givenName",
		"sn",
		"initials",
		"displayName",
		"description",
		"mail",

		// title and department info
		"title",
		"department",
		"company",
		"manager",
		"employeeID",
		"roomNumber",

		// address
		"street",
		"streetAddress",
		"l",
		"st",
		"co",
		"postalCode",

		// additional
		"userAccountControl",
		"memberOf",
		"objectGUID",
		"objectSid",

		// phone
		"telephoneNumber",
		"mobile",
		"ipPhone",

		// photo
		"thumbnailPhoto",
		"jpegPhoto",
	}
}

func (a MSADAdapter) OUAttrs() []string {
	return []string{
		"distinguishedName",
		"name",
		"objectClass",
		"objectGUID",
		"description",
		"managedBy",
	}
}

func (a MSADAdapter) GroupAttrs() []string {
	return []string{
		"cn",
		"distinguishedName",
		"sAMAccountName",
		"groupType",
		"member",
		"memberOf",
		"description",
		"objectGUID",
	}
}

// ------ PrimaryGroupResolver behavior implementation ------- //

// ResolvePrimaryGroupDN resolves the DN of the primary group for an AD user.
// It reads the domain objectSid, combines it with the user's primaryGroupID,
// and searches for a group with the resulting objectSid.
func (a MSADAdapter) ResolvePrimaryGroupDN(user types.LDAPUser, conn interfaces.LDAPConn) (string, error) {
	pgidStr := user.GetAttributeValue("primaryGroupID")
	if pgidStr == "" {
		return "", nil // No primary group set, nothing to do.
	}

	// 1. Extract the domain DN from the user's DN.
	userDN, err := ldap.ParseDN(user.DN)
	if err != nil {
		return "", err
	}

	if len(userDN.RDNs) < 2 {
		return "", fmt.Errorf("invalid user DN (need at least 2 RDNs for domain extraction): %s", user.DN)
	}

	// Find the deepest ancestor entry with objectClass=domainDNS.
	// The user's actual domain is the nearest domain ancestor.
	var domainDNStr string
	var domainSidBytes []byte

	for i := len(userDN.RDNs) - 1; i >= 0; i-- {
		candidate := &ldap.DN{RDNs: userDN.RDNs[i:]}
		req := ldap.NewSearchRequest(
			candidate.String(),
			ldap.ScopeBaseObject,
			ldap.NeverDerefAliases,
			1, 0, false,
			"(objectClass=domainDNS)",
			[]string{"objectSid"},
			nil,
		)
		res, err := conn.Search(req)
		if err != nil {
			// Network/server error — propagate immediately; the connection
			// is likely broken, and retrying other candidates would fail
			// the same way while hiding the real cause.
			return "", fmt.Errorf("search domainDNS ancestor %s: %w",
				candidate.String(), err)
		}
		if len(res.Entries) > 0 {
			domainDNStr = candidate.String()
			domainSidBytes = res.Entries[0].GetRawAttributeValue("objectSid")
			if domainSidBytes == nil {
				return "", fmt.Errorf("domain %s has no objectSid", domainDNStr)
			}
			break
		}
	}

	if domainDNStr == "" {
		return "", fmt.Errorf("no domainDNS ancestor found for user %s", user.DN)
	}

	// 2. Convert the binary domain SID to its string representation.
	domainSidStr, err := binarySidToString(domainSidBytes)
	if err != nil {
		return "", fmt.Errorf("convert the binary domain SID to its string representation for %s: %w", domainDNStr, err)
	}

	// 3. Construct the primary group's SID string.
	groupSidStr := fmt.Sprintf("%s-%s", domainSidStr, pgidStr)

	// 4. Search for the group by objectSid.
	groupReq := ldap.NewSearchRequest(
		domainDNStr, // Search the whole domain
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		1, 0, false,
		fmt.Sprintf("(&(objectCategory=group)(objectSid=%s))", ldap.EscapeFilter(groupSidStr)),
		[]string{"distinguishedName"},
		nil,
	)
	groupRes, err := conn.Search(groupReq)
	if err != nil {
		return "", fmt.Errorf("failed to resolve primary group for user %s: %w", user.DN, err)
	}
	if len(groupRes.Entries) == 0 {
		return "", fmt.Errorf("primary group with SID %s not found for user %s", groupSidStr, user.DN)
	}

	return groupRes.Entries[0].DN, nil
}

// binarySidToString converts a binary SID to its string representation (e.g., "S-1-5-21-...").
// This is a standard algorithm; see references.
func binarySidToString(b []byte) (string, error) {
	if len(b) < 8 {
		return "", fmt.Errorf("SID too short: %d bytes", len(b))
	}
	revision := b[0]
	subAuthorityCount := int(b[1])
	if len(b) < 8+subAuthorityCount*4 {
		return "", fmt.Errorf("SID truncated: have %d, need %d",
			len(b), 8+subAuthorityCount*4)
	}

	identifierAuthority := uint64(0)
	for i := 0; i < 6; i++ {
		identifierAuthority = (identifierAuthority << 8) | uint64(b[2+i])
	}

	subAuthorities := make([]string, subAuthorityCount)
	for i := 0; i < subAuthorityCount; i++ {
		offset := 8 + i*4
		subAuthority := uint32(b[offset]) | uint32(b[offset+1])<<8 |
			uint32(b[offset+2])<<16 | uint32(b[offset+3])<<24
		subAuthorities[i] = fmt.Sprintf("%d", subAuthority)
	}

	if subAuthorityCount == 0 {
		return fmt.Sprintf("S-%d-%d", revision, identifierAuthority), nil
	}
	return fmt.Sprintf("S-%d-%d-%s", revision, identifierAuthority,
		strings.Join(subAuthorities, "-")), nil
}
