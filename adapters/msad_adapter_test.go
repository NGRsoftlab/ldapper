// Copyright 2020-2026 NGR Softlab
package adapters

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/go-ldap/ldap/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/NGRsoftlab/ldapper/mocks"
)

// entryPtr converts the value-returning newLDAPEntry into the pointer form
// expected by ldap.SearchResult.Entries.
func entryPtr(dn string, attrs map[string][]string) *ldap.Entry {
	e := newLDAPEntry(dn, attrs)
	return &e
}

// ================== GetNormalizedUserInfo ==================

func TestMSADAdapter_GetNormalizedUserInfo_AllFields(t *testing.T) {
	t.Parallel()

	user := newLDAPUser("cn=alice,dc=x", attrMap(map[string]string{
		"cn":              "Alice Smith",
		"mobile":          "+1-555-0100",
		"telephoneNumber": "+1-555-0101",
		"mail":            "alice@example.com",
		"department":      "Engineering",
		"title":           "Senior Engineer",
		"manager":         "cn=bob,dc=x",
		"company":         "Acme Corp",
		"co":              "US",
		"streetAddress":   "123 Main St",
		"l":               "Springfield",
		"postalCode":      "12345",
	}))

	info := MSADAdapter{}.GetNormalizedUserInfo(user)
	require.NotNil(t, info)

	assert.Equal(t, "cn=alice,dc=x", info.DistinguishedName)
	assert.Equal(t, "Alice Smith", info.CommonName)
	assert.Equal(t, "+1-555-0100", info.Mobile)
	assert.Equal(t, "+1-555-0101", info.Phone)
	assert.Equal(t, "alice@example.com", info.Mail)
	assert.Equal(t, "Engineering", info.Department)
	assert.Equal(t, "Senior Engineer", info.Title)
	assert.Equal(t, "cn=bob,dc=x", info.Manager)
	assert.Equal(t, "Acme Corp", info.Company)
	assert.Equal(t, "US", info.Country)
	assert.Equal(t, "123 Main St", info.Address)
	assert.Equal(t, "Springfield", info.City)
	assert.Equal(t, "12345", info.Index)
}

func TestMSADAdapter_GetNormalizedUserInfo_PhotoFallback(t *testing.T) {
	t.Parallel()

	thumb := []byte{0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10} // JPEG magic + version
	jpeg := []byte{0xFF, 0xD8, 0xFF, 0xE1, 0x00, 0x42}

	tests := []struct {
		name  string
		attrs map[string][]string
		want  []byte
	}{
		{
			name: "only thumbnailPhoto",
			attrs: map[string][]string{
				"thumbnailPhoto": {string(thumb)},
			},
			want: thumb,
		},
		{
			name: "only jpegPhoto",
			attrs: map[string][]string{
				"jpegPhoto": {string(jpeg)},
			},
			want: jpeg,
		},
		{
			name: "thumbnailPhoto wins when both present",
			attrs: map[string][]string{
				"thumbnailPhoto": {string(thumb)},
				"jpegPhoto":      {string(jpeg)},
			},
			want: thumb,
		},
		{
			name:  "neither",
			attrs: nil,
			want:  nil,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			user := newLDAPUser("cn=alice,dc=x", tt.attrs)
			info := MSADAdapter{}.GetNormalizedUserInfo(user)
			require.NotNil(t, info)

			if tt.want == nil {
				assert.Nil(t, info.Photo)
				return
			}
			assert.Equal(t, tt.want, info.Photo,
				"binary photo bytes must survive the []string round-trip unchanged")
		})
	}
}

func TestMSADAdapter_GetNormalizedUserInfo_EmptyAttributes(t *testing.T) {
	t.Parallel()

	info := MSADAdapter{}.GetNormalizedUserInfo(newLDAPUser("cn=alice,dc=x", nil))
	require.NotNil(t, info)
	assert.Equal(t, "cn=alice,dc=x", info.DistinguishedName)
	assert.Empty(t, info.CommonName)
	assert.Nil(t, info.Photo)
}

// ================== GetNormalizedOUInfoFromEntry ==================

func TestMSADAdapter_GetNormalizedOUInfoFromEntry(t *testing.T) {
	t.Parallel()

	entry := newLDAPEntry("ou=sales,dc=example,dc=com", map[string][]string{
		"name": {"Sales"},
	})

	info := MSADAdapter{}.GetNormalizedOUInfoFromEntry(entry)
	require.NotNil(t, info)

	assert.Equal(t, "ou=sales,dc=example,dc=com", info.DN)
	assert.Equal(t, "sales", info.Name)
	// NB: MSAD adapter sets OU to the full DN (not the ou attribute value).
	// Different from OPENLDAP/FREEIPA/ALDPRO; the distinction matters for
	// callers that use OU as a unique identifier.
	assert.Equal(t, "ou=sales,dc=example,dc=com", info.OU,
		"MSAD adapter uses the DN as the OU identifier")
	assert.NotNil(t, info.Children)
	assert.Empty(t, info.Children)
}

// ================== BindIdentity ==================

func TestMSADAdapter_BindIdentity(t *testing.T) {
	t.Parallel()

	t.Run("empty login", func(t *testing.T) {
		t.Parallel()
		_, err := MSADAdapter{}.BindIdentity("", "dc=x")
		require.Error(t, err)
	})

	t.Run("passes login through unchanged", func(t *testing.T) {
		t.Parallel()

		// AD accepts UPN, sAMAccountName and DN as Simple Bind principals.
		// The adapter must not transform any of them.
		cases := []string{
			"alice",
			"alice@example.com",
			"DOMAIN\\alice",
			"cn=Alice Smith,ou=sales,dc=example",
			"uid=alice,ou=people,dc=example",
		}
		for _, login := range cases {
			login := login
			t.Run(login, func(t *testing.T) {
				t.Parallel()
				got, err := MSADAdapter{}.BindIdentity(login, "dc=irrelevant")
				require.NoError(t, err)
				assert.Equal(t, login, got)
			})
		}
	})

	t.Run("baseDN is ignored", func(t *testing.T) {
		t.Parallel()
		// Unlike OPENLDAP/FREEIPA, MSAD does not use baseDN to build the
		// principal. Verify the parameter is truly a no-op.
		got1, _ := MSADAdapter{}.BindIdentity("alice", "dc=a")
		got2, _ := MSADAdapter{}.BindIdentity("alice", "dc=b")
		assert.Equal(t, got1, got2)
	})
}

// ================== Filter templates ==================

func TestMSADAdapter_SearchUserFilterTemplate(t *testing.T) {
	t.Parallel()

	tmpl := MSADAdapter{}.SearchUserFilterTemplate()

	t.Run("valid with plain arg", func(t *testing.T) {
		t.Parallel()
		f := fmt.Sprintf(tmpl, ldap.EscapeFilter("alice"))
		requireValidFilter(t, f)
		assert.Contains(t, f, "sAMAccountName=alice")
		assert.Contains(t, f, "userPrincipalName=alice")
		assert.Contains(t, f, "distinguishedName=alice")
	})

	t.Run("escapes special chars", func(t *testing.T) {
		t.Parallel()
		f := fmt.Sprintf(tmpl, ldap.EscapeFilter("a*b(c)"))
		requireValidFilter(t, f)
		assert.Contains(t, f, `a\2ab\28c\29`)
		assert.NotContains(t, f, "a*b")
	})
}

func TestMSADAdapter_SearchUserGroupsFilterTemplate(t *testing.T) {
	t.Parallel()

	tmpl := MSADAdapter{}.SearchUserGroupsFilterTemplate()
	f := fmt.Sprintf(tmpl, ldap.EscapeFilter("cn=alice,dc=x"))

	requireValidFilter(t, f)
	assert.Contains(t, f, "member:1.2.840.113556.1.4.1941:=",
		"MSAD group membership must use the LDAP_MATCHING_RULE_IN_CHAIN OID")
	assert.Contains(t, f, "objectCategory=group")
}

func TestMSADAdapter_SearchOUFilterTemplate(t *testing.T) {
	t.Parallel()

	f := fmt.Sprintf(MSADAdapter{}.SearchOUFilterTemplate(), ldap.EscapeFilter("sales"))
	requireValidFilter(t, f)
	assert.Contains(t, f, "objectClass=organizationalUnit")
}

func TestMSADAdapter_SearchGroupFilterTemplate(t *testing.T) {
	t.Parallel()

	f := fmt.Sprintf(MSADAdapter{}.SearchGroupFilterTemplate(), ldap.EscapeFilter("admins"))
	requireValidFilter(t, f)
	assert.Contains(t, f, "objectCategory=group")
}

func TestMSADAdapter_ObjectFilters(t *testing.T) {
	t.Parallel()

	a := MSADAdapter{}
	for name, f := range map[string]string{
		"UserObjectFilter":  a.UserObjectFilter(),
		"GroupObjectFilter": a.GroupObjectFilter(),
		"OUObjectFilter":    a.OUObjectFilter(),
	} {
		f := f
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			requireValidFilter(t, f)
		})
	}
}

// ================== Attrs ==================

func TestMSADAdapter_Attrs_RequiredForResolver(t *testing.T) {
	t.Parallel()

	// primaryGroupID must be fetched on every user lookup — otherwise
	// ResolvePrimaryGroupDN would silently return ("", nil) for every user,
	// making GetUserGroups return an incomplete group list.
	attrs := MSADAdapter{}.UserAttrs()
	assert.Contains(t, attrs, "primaryGroupID")

	// distinguishedName is required by SearchUserFilterTemplate.
	assert.Contains(t, attrs, "distinguishedName")
}

func TestMSADAdapter_Attrs_NonEmpty(t *testing.T) {
	t.Parallel()

	a := MSADAdapter{}
	assert.NotEmpty(t, a.UserAttrs())
	assert.NotEmpty(t, a.OUAttrs())
	assert.NotEmpty(t, a.GroupAttrs())
}

// ================== ResolvePrimaryGroupDN ==================

// SID byte fixtures. Format: revision(1) | count(1) | authority(6, BE) |
// sub-authorities(count × 4, LE each).
var (
	// S-1-5-21-111-222-333
	msadChildDomainSID = []byte{
		0x01, 0x04,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x05, // authority = 5
		0x15, 0x00, 0x00, 0x00, // 21
		0x6F, 0x00, 0x00, 0x00, // 111
		0xDE, 0x00, 0x00, 0x00, // 222
		0x4D, 0x01, 0x00, 0x00, // 333
	}

	// S-1-5-21-999-888-777 — deliberately different from the child SID so
	// a regression that picks the parent domain produces a distinctly
	// wrong group SID.
	msadParentDomainSID = []byte{
		0x01, 0x04,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x05,
		0x15, 0x00, 0x00, 0x00, // 21
		0xE7, 0x03, 0x00, 0x00, // 999
		0x78, 0x03, 0x00, 0x00, // 888
		0x09, 0x03, 0x00, 0x00, // 777
	}
)

// THE regression test.
//
// In a multi-domain forest the user's primaryGroupID is a RID in the
// user's own domain, not in the forest root. The resolver must therefore
// probe domainDNS ancestors from NEAREST to FARTHEST (leaf → root), pick
// the child domain first, and use its SID prefix.
//
// With the old (root → leaf) walk, the parent domain's SID was chosen,
// the group filter carried "S-1-5-21-999-888-777-513", the group lookup
// returned zero entries, and GetUserGroups failed for every user in a
// child domain. This test fails on that implementation and passes on the
// fixed one.
func TestMSADAdapter_ResolvePrimaryGroupDN_ChildDomainRegression(t *testing.T) {
	t.Parallel()

	var domainLookups []string
	var groupFilter string

	conn := &mocks.MockLDAPConn{
		SearchFunc: func(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
			switch {
			case strings.Contains(req.Filter, "objectClass=domainDNS"):
				domainLookups = append(domainLookups, req.BaseDN)
				// Case-insensitive: DN.String() normalises attribute
				// types to lowercase; EqualFold also survives versions
				// that preserve the caller's case.
				switch {
				case strings.EqualFold(req.BaseDN, "DC=child,DC=example,DC=com"):
					return &ldap.SearchResult{Entries: []*ldap.Entry{
						entryPtr(req.BaseDN, map[string][]string{
							"objectSid": {string(msadChildDomainSID)},
						}),
					}}, nil
				case strings.EqualFold(req.BaseDN, "DC=example,DC=com"):
					return &ldap.SearchResult{Entries: []*ldap.Entry{
						entryPtr(req.BaseDN, map[string][]string{
							"objectSid": {string(msadParentDomainSID)},
						}),
					}}, nil
				}
				// Not a domainDNS — the resolver must continue up the
				// tree. This is the "miss" the walk produces on every
				// non-domain ancestor (OU=Sales, DC=com, ...).
				return &ldap.SearchResult{}, nil

			case strings.Contains(req.Filter, "objectCategory=group"):
				groupFilter = req.Filter
				// The mock only knows the child-domain primary group.
				// A resolver that picked the parent SID hits "not found"
				// — but the ordering assertion below would already have
				// failed first, so this stays as a fallback signal.
				if strings.Contains(req.Filter, "S-1-5-21-111-222-333-513") {
					return &ldap.SearchResult{Entries: []*ldap.Entry{
						entryPtr("CN=Domain Users,DC=child,DC=example,DC=com", nil),
					}}, nil
				}
				return &ldap.SearchResult{}, nil
			}
			t.Fatalf("unexpected filter: %q", req.Filter)
			return nil, nil
		},
	}

	user := newLDAPUser("CN=Alice,OU=Sales,DC=child,DC=example,DC=com",
		attrMap(map[string]string{"primaryGroupID": "513"}))

	dn, err := MSADAdapter{}.ResolvePrimaryGroupDN(context.Background(), user, conn)
	require.NoError(t, err)
	assert.Equal(t, "CN=Domain Users,DC=child,DC=example,DC=com", dn)

	// Nearest-to-farthest walk: the child domain must be probed and, if
	// both are probed, the child must appear before the parent in the log.
	childIdx, parentIdx := -1, -1
	for i, d := range domainLookups {
		switch {
		case strings.EqualFold(d, "DC=child,DC=example,DC=com"):
			childIdx = i
		case strings.EqualFold(d, "DC=example,DC=com"):
			parentIdx = i
		}
	}
	require.NotEqual(t, -1, childIdx,
		"child domain must be probed; with a root-first walk it is never reached")
	if parentIdx != -1 {
		assert.Less(t, childIdx, parentIdx,
			"child domain must be probed before parent domain")
	}

	assert.Contains(t, groupFilter, "S-1-5-21-111-222-333-513",
		"group SID must be built from the CHILD domain, not the forest root")
	assert.NotContains(t, groupFilter, "S-1-5-21-999-888-777",
		"parent-domain SID must never appear in the group search")
}

func TestMSADAdapter_ResolvePrimaryGroupDN_SingleDomainForest(t *testing.T) {
	t.Parallel()

	conn := &mocks.MockLDAPConn{
		SearchFunc: func(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
			switch {
			case strings.Contains(req.Filter, "objectClass=domainDNS"):
				if strings.EqualFold(req.BaseDN, "DC=example,DC=com") {
					return &ldap.SearchResult{Entries: []*ldap.Entry{
						entryPtr(req.BaseDN, map[string][]string{
							"objectSid": {string(msadChildDomainSID)},
						}),
					}}, nil
				}
				return &ldap.SearchResult{}, nil
			case strings.Contains(req.Filter, "objectCategory=group"):
				return &ldap.SearchResult{Entries: []*ldap.Entry{
					entryPtr("CN=Domain Users,DC=example,DC=com", nil),
				}}, nil
			}
			t.Fatalf("unexpected filter: %q", req.Filter)
			return nil, nil
		},
	}

	user := newLDAPUser("CN=Alice,DC=example,DC=com",
		attrMap(map[string]string{"primaryGroupID": "513"}))

	dn, err := MSADAdapter{}.ResolvePrimaryGroupDN(context.Background(), user, conn)
	require.NoError(t, err)
	assert.Equal(t, "CN=Domain Users,DC=example,DC=com", dn)
}

func TestMSADAdapter_ResolvePrimaryGroupDN_NoPrimaryGroupID(t *testing.T) {
	t.Parallel()

	// No primaryGroupID -> ("", nil) with NO LDAP round-trip.
	calls := 0
	conn := &mocks.MockLDAPConn{
		SearchFunc: func(*ldap.SearchRequest) (*ldap.SearchResult, error) {
			calls++
			return nil, errors.New("should not be called")
		},
	}

	user := newLDAPUser("CN=Alice,DC=example,DC=com", nil)

	dn, err := MSADAdapter{}.ResolvePrimaryGroupDN(context.Background(), user, conn)
	require.NoError(t, err)
	assert.Empty(t, dn)
	assert.Zero(t, calls, "no primaryGroupID -> no LDAP search")
}

func TestMSADAdapter_ResolvePrimaryGroupDN_InvalidUserDN(t *testing.T) {
	t.Parallel()

	user := newLDAPUser("not-a-dn",
		attrMap(map[string]string{"primaryGroupID": "513"}))

	_, err := MSADAdapter{}.ResolvePrimaryGroupDN(context.Background(), user, &mocks.MockLDAPConn{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid DN")
}

func TestMSADAdapter_ResolvePrimaryGroupDN_SingleRDNUser(t *testing.T) {
	t.Parallel()

	// A DN with fewer than 2 RDNs has no ancestor to probe.
	user := newLDAPUser("CN=Alice",
		attrMap(map[string]string{"primaryGroupID": "513"}))

	_, err := MSADAdapter{}.ResolvePrimaryGroupDN(context.Background(), user, &mocks.MockLDAPConn{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "need at least 2 RDNs")
}

func TestMSADAdapter_ResolvePrimaryGroupDN_ContextAlreadyCancelled(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	user := newLDAPUser("CN=Alice,DC=example,DC=com",
		attrMap(map[string]string{"primaryGroupID": "513"}))

	_, err := MSADAdapter{}.ResolvePrimaryGroupDN(ctx, user, &mocks.MockLDAPConn{})
	require.Error(t, err)
	assert.ErrorIs(t, err, context.Canceled)
}

func TestMSADAdapter_ResolvePrimaryGroupDN_ContextCancelledMidLoop(t *testing.T) {
	t.Parallel()

	// Cancel after the first (successful) ancestor probe so the loop's
	// next ctx.Err() check fires before the second search.
	ctx, cancel := context.WithCancel(context.Background())
	calls := 0
	conn := &mocks.MockLDAPConn{
		SearchFunc: func(*ldap.SearchRequest) (*ldap.SearchResult, error) {
			calls++
			if calls == 1 {
				cancel()
			}
			return &ldap.SearchResult{}, nil // not a domainDNS — forces another iteration
		},
	}

	user := newLDAPUser("CN=Alice,OU=Sales,DC=child,DC=example,DC=com",
		attrMap(map[string]string{"primaryGroupID": "513"}))

	_, err := MSADAdapter{}.ResolvePrimaryGroupDN(ctx, user, conn)
	require.Error(t, err)
	assert.ErrorIs(t, err, context.Canceled)
}

func TestMSADAdapter_ResolvePrimaryGroupDN_NoDomainDNSFound(t *testing.T) {
	t.Parallel()

	conn := &mocks.MockLDAPConn{
		SearchFunc: func(*ldap.SearchRequest) (*ldap.SearchResult, error) {
			return &ldap.SearchResult{}, nil
		},
	}

	user := newLDAPUser("CN=Alice,DC=example,DC=com",
		attrMap(map[string]string{"primaryGroupID": "513"}))

	_, err := MSADAdapter{}.ResolvePrimaryGroupDN(context.Background(), user, conn)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no domainDNS ancestor")
}

func TestMSADAdapter_ResolvePrimaryGroupDN_DomainWithoutObjectSid(t *testing.T) {
	t.Parallel()

	conn := &mocks.MockLDAPConn{
		SearchFunc: func(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
			if strings.Contains(req.Filter, "objectClass=domainDNS") {
				// Domain entry present but no objectSid attribute.
				return &ldap.SearchResult{Entries: []*ldap.Entry{
					entryPtr(req.BaseDN, nil),
				}}, nil
			}
			t.Fatalf("must not search for a group when the domain has no SID")
			return nil, nil
		},
	}

	user := newLDAPUser("CN=Alice,DC=example,DC=com",
		attrMap(map[string]string{"primaryGroupID": "513"}))

	_, err := MSADAdapter{}.ResolvePrimaryGroupDN(context.Background(), user, conn)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "has no objectSid")
}

func TestMSADAdapter_ResolvePrimaryGroupDN_AncestorSearchError(t *testing.T) {
	t.Parallel()

	wantErr := errors.New("network unreachable")
	conn := &mocks.MockLDAPConn{
		SearchFunc: func(*ldap.SearchRequest) (*ldap.SearchResult, error) {
			return nil, wantErr
		},
	}

	user := newLDAPUser("CN=Alice,DC=example,DC=com",
		attrMap(map[string]string{"primaryGroupID": "513"}))

	_, err := MSADAdapter{}.ResolvePrimaryGroupDN(context.Background(), user, conn)
	require.Error(t, err)
	assert.ErrorIs(t, err, wantErr)
	assert.Contains(t, err.Error(), "search domainDNS ancestor")
}

func TestMSADAdapter_ResolvePrimaryGroupDN_GroupSearchError(t *testing.T) {
	t.Parallel()

	wantErr := errors.New("group search failed")
	conn := &mocks.MockLDAPConn{
		SearchFunc: func(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
			if strings.Contains(req.Filter, "objectClass=domainDNS") {
				return &ldap.SearchResult{Entries: []*ldap.Entry{
					entryPtr(req.BaseDN, map[string][]string{
						"objectSid": {string(msadChildDomainSID)},
					}),
				}}, nil
			}
			return nil, wantErr
		},
	}

	user := newLDAPUser("CN=Alice,DC=example,DC=com",
		attrMap(map[string]string{"primaryGroupID": "513"}))

	_, err := MSADAdapter{}.ResolvePrimaryGroupDN(context.Background(), user, conn)
	require.Error(t, err)
	assert.ErrorIs(t, err, wantErr)
	assert.Contains(t, err.Error(), "failed to resolve primary group")
}

func TestMSADAdapter_ResolvePrimaryGroupDN_GroupNotFound(t *testing.T) {
	t.Parallel()

	conn := &mocks.MockLDAPConn{
		SearchFunc: func(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
			if strings.Contains(req.Filter, "objectClass=domainDNS") {
				return &ldap.SearchResult{Entries: []*ldap.Entry{
					entryPtr(req.BaseDN, map[string][]string{
						"objectSid": {string(msadChildDomainSID)},
					}),
				}}, nil
			}
			return &ldap.SearchResult{}, nil // group not found
		},
	}

	user := newLDAPUser("CN=Alice,DC=example,DC=com",
		attrMap(map[string]string{"primaryGroupID": "513"}))

	_, err := MSADAdapter{}.ResolvePrimaryGroupDN(context.Background(), user, conn)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
	assert.Contains(t, err.Error(), "S-1-5-21-111-222-333-513",
		"error message must include the SID that was searched for")
}

func TestMSADAdapter_ResolvePrimaryGroupDN_DoesNotMutateUser(t *testing.T) {
	t.Parallel()

	// The resolver must be a pure function of its input user. Test that
	// a second call with the same user sees the same attributes.
	user := newLDAPUser("CN=Alice,DC=example,DC=com",
		attrMap(map[string]string{"primaryGroupID": "513"}))
	before := user.GetAttributeValue("primaryGroupID")

	conn := &mocks.MockLDAPConn{
		SearchFunc: func(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
			if strings.Contains(req.Filter, "objectClass=domainDNS") {
				return &ldap.SearchResult{Entries: []*ldap.Entry{
					entryPtr(req.BaseDN, map[string][]string{
						"objectSid": {string(msadChildDomainSID)},
					}),
				}}, nil
			}
			return &ldap.SearchResult{}, nil
		},
	}

	_, _ = MSADAdapter{}.ResolvePrimaryGroupDN(context.Background(), user, conn)

	assert.Equal(t, before, user.GetAttributeValue("primaryGroupID"))
}

// ================== binarySidToString ==================

func TestBinarySidToString(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		in      []byte
		want    string
		wantErr bool
	}{
		{
			name: "S-1-5-32-544 (Administrators)",
			in: []byte{
				0x01, 0x02,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x05,
				0x20, 0x00, 0x00, 0x00, // 32
				0x20, 0x02, 0x00, 0x00, // 544
			},
			want: "S-1-5-32-544",
		},
		{
			name: "S-1-5-21-111-222-333",
			in:   msadChildDomainSID,
			want: "S-1-5-21-111-222-333",
		},
		{
			name: "S-1-5 (no sub-authorities)",
			in: []byte{
				0x01, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x05,
			},
			want: "S-1-5",
		},
		{
			name:    "nil",
			in:      nil,
			wantErr: true,
		},
		{
			name:    "shorter than the 8-byte header",
			in:      []byte{0x01, 0x00, 0x00},
			wantErr: true,
		},
		{
			name: "declared count exceeds provided sub-authorities",
			in: []byte{
				0x01, 0x04,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x05,
				0x15, 0x00, 0x00, 0x00, // only 1 of 4 declared
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := binarySidToString(tt.in)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestBinarySidToString_RoundTrip(t *testing.T) {
	t.Parallel()

	// Sanity check: encoding known SIDs and decoding them back yields the
	// same string. Verifies the whole byte layout, not just one field.
	sids := []string{
		"S-1-5-18",
		"S-1-5-19",
		"S-1-5-20",
		"S-1-5-21-111-222-333",
		"S-1-5-21-999-888-777",
	}

	for _, sid := range sids {
		sid := sid
		t.Run(sid, func(t *testing.T) {
			t.Parallel()

			// Build the binary form from the string form via the same
			// decomposition binarySidToString uses in reverse.
			encoded := encodeSID(t, sid)
			got, err := binarySidToString(encoded)
			require.NoError(t, err)
			assert.Equal(t, sid, got)
		})
	}
}

// encodeSID builds the binary form of a SID from its string form. Used
// only by the round-trip test; the production code never needs the reverse.
func encodeSID(t *testing.T, sid string) []byte {
	t.Helper()

	parts := strings.Split(sid, "-")
	require.GreaterOrEqual(t, len(parts), 3, "bad SID fixture: %q", sid)
	require.Equal(t, "S", parts[0])

	var revision, count int
	_, err := fmt.Sscanf(parts[1], "%d", &revision)
	require.NoError(t, err)
	_, err = fmt.Sscanf(parts[2], "%d", &count) // unused; authority parsed below
	_ = count
	require.NoError(t, err)

	// parts[2] is the identifier authority, parts[3:] are sub-authorities.
	var authority uint64
	_, err = fmt.Sscanf(parts[2], "%d", &authority)
	require.NoError(t, err)

	subs := parts[3:]
	out := []byte{byte(revision), byte(len(subs))}

	// 6-byte big-endian authority.
	for i := 5; i >= 0; i-- {
		out = append(out, byte(authority>>(uint(i)*8)))
	}

	// 4-byte little-endian sub-authorities.
	for _, s := range subs {
		var v uint32
		_, err := fmt.Sscanf(s, "%d", &v)
		require.NoError(t, err)
		out = append(out,
			byte(v),
			byte(v>>8),
			byte(v>>16),
			byte(v>>24),
		)
	}
	return out
}
