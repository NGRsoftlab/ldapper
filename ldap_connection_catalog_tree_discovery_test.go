// Copyright 2020-2026 NGR Softlab
package ldapper

import (
	"errors"
	"testing"

	"github.com/go-ldap/ldap/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/NGRsoftlab/ldapper/constants"
	"github.com/NGRsoftlab/ldapper/mocks"
	"github.com/NGRsoftlab/ldapper/types"
)

// ---------- GetCatalogTree ----------

func TestGetCatalogTree_Success(t *testing.T) {
	adapter := new(mocks.MockCatalogAdapter)
	adapter.On("OUObjectFilter").Return("(objectClass=organizationalUnit)")
	adapter.On("OUAttrs").Return([]string{"ou"})

	// OUInfoFromEntry is called once per entry: first for the root OU,
	// then for the sub OU returned by GetSubOUs.
	adapter.On("OUInfoFromEntry", mock.Anything).Return(&types.OUInfo{
		DN: "ou=root,dc=example,dc=com", Name: "root", Children: make([]*types.OUInfo, 0),
	}).Once()
	adapter.On("OUInfoFromEntry", mock.Anything).Return(&types.OUInfo{
		DN: "ou=sub,ou=root,dc=example,dc=com", Name: "sub", Children: make([]*types.OUInfo, 0),
	}).Once()

	connMock := new(mocks.MockLDAPConn)
	// 1st Search: GetRootOUs — single level under baseDn.
	connMock.On("Search", mock.MatchedBy(func(req *ldap.SearchRequest) bool {
		return req.BaseDN == "dc=example,dc=com" && req.Scope == ldap.ScopeSingleLevel
	})).Return(&ldap.SearchResult{Entries: []*ldap.Entry{
		newLDAPEntry("ou=root,dc=example,dc=com", nil),
	}}, nil).Once()
	// 2nd Search: GetSubOUs for "ou=root".
	connMock.On("Search", mock.MatchedBy(func(req *ldap.SearchRequest) bool {
		return req.BaseDN == "ou=root,dc=example,dc=com" && req.Scope == ldap.ScopeSingleLevel
	})).Return(&ldap.SearchResult{Entries: []*ldap.Entry{
		newLDAPEntry("ou=sub,ou=root,dc=example,dc=com", nil),
	}}, nil).Once()
	// Further recursion for "ou=sub" depends on defaultSearchDepth (=5).
	// level starts at 2, then 3, 4, 5 — recursion continues while level < 5.
	connMock.On("Search", mock.MatchedBy(func(req *ldap.SearchRequest) bool {
		return req.BaseDN == "ou=sub,ou=root,dc=example,dc=com" && req.Scope == ldap.ScopeSingleLevel
	})).Return(&ldap.SearchResult{Entries: []*ldap.Entry{}}, nil).Maybe()

	conn := newTestConnection(adapter, connMock)
	tree, err := conn.GetCatalogTree("dc=example,dc=com")

	assert.NoError(t, err)
	assert.Len(t, tree.Tree, 1)
	assert.Equal(t, "ou=root,dc=example,dc=com", tree.Tree[0].DN)
}

func TestGetCatalogTree_RootSearchError(t *testing.T) {
	adapter := new(mocks.MockCatalogAdapter)
	adapter.On("OUObjectFilter").Return("(objectClass=organizationalUnit)")
	adapter.On("OUAttrs").Return([]string{"ou"})

	connMock := new(mocks.MockLDAPConn)
	connMock.On("Search", mock.Anything).
		Return(nil, errors.New("root search failed")).Once()

	conn := newTestConnection(adapter, connMock)
	tree, err := conn.GetCatalogTree("dc=example,dc=com")

	assert.ErrorContains(t, err, "unsuccessful ou search")
	assert.NotNil(t, tree.Tree)
	assert.Empty(t, tree.Tree)
}

func TestGetCatalogTree_EmptyRoot(t *testing.T) {
	adapter := new(mocks.MockCatalogAdapter)
	adapter.On("OUObjectFilter").Return("(objectClass=organizationalUnit)")
	adapter.On("OUAttrs").Return([]string{"ou"})

	connMock := new(mocks.MockLDAPConn)
	connMock.On("Search", mock.Anything).
		Return(&ldap.SearchResult{Entries: []*ldap.Entry{}}, nil).Once()

	conn := newTestConnection(adapter, connMock)
	tree, err := conn.GetCatalogTree("dc=example,dc=com")

	assert.NoError(t, err)
	assert.NotNil(t, tree.Tree)
	assert.Empty(t, tree.Tree)
}

// ---------- GetRootOUs ----------

func TestGetRootOUs_Success(t *testing.T) {
	adapter := new(mocks.MockCatalogAdapter)
	adapter.On("OUObjectFilter").Return("(objectClass=organizationalUnit)")
	adapter.On("OUAttrs").Return([]string{"ou"})

	adapter.On("OUInfoFromEntry", mock.Anything).Return(&types.OUInfo{
		DN: "ou=root,dc=example,dc=com", Name: "root", Children: make([]*types.OUInfo, 0),
	}).Once()

	connMock := new(mocks.MockLDAPConn)
	connMock.On("Search", mock.MatchedBy(func(req *ldap.SearchRequest) bool {
		return req.BaseDN == "dc=example,dc=com" &&
			req.Scope == ldap.ScopeSingleLevel &&
			req.Filter == "(objectClass=organizationalUnit)" &&
			req.TimeLimit == constants.DefaultSearchTimeLimit
	})).Return(&ldap.SearchResult{Entries: []*ldap.Entry{
		newLDAPEntry("ou=root,dc=example,dc=com", nil),
	}}, nil).Once()

	conn := newTestConnection(adapter, connMock)
	ous, err := conn.GetRootOUs("dc=example,dc=com")

	assert.NoError(t, err)
	assert.Len(t, ous, 1)
	assert.Equal(t, "ou=root,dc=example,dc=com", ous[0].DN)
}

func TestGetRootOUs_SearchError(t *testing.T) {
	adapter := new(mocks.MockCatalogAdapter)
	adapter.On("OUObjectFilter").Return("(objectClass=organizationalUnit)")
	adapter.On("OUAttrs").Return([]string{"ou"})

	connMock := new(mocks.MockLDAPConn)
	connMock.On("Search", mock.Anything).
		Return(nil, errors.New("search failed")).Once()

	conn := newTestConnection(adapter, connMock)
	ous, err := conn.GetRootOUs("dc=example,dc=com")

	assert.NotNil(t, ous)
	assert.Empty(t, ous)
	assert.EqualError(t, err, "unsuccessful ou search: search failed")
}

// ---------- GetSubOUs ----------

func TestGetSubOUs_Success(t *testing.T) {
	adapter := new(mocks.MockCatalogAdapter)
	adapter.On("OUObjectFilter").Return("(objectClass=organizationalUnit)")
	adapter.On("OUAttrs").Return([]string{"ou"})

	adapter.On("OUInfoFromEntry", mock.Anything).Return(&types.OUInfo{
		DN: "ou=sub,ou=root,dc=example,dc=com", Name: "sub", Children: make([]*types.OUInfo, 0),
	}).Once()

	connMock := new(mocks.MockLDAPConn)
	connMock.On("Search", mock.Anything).Return(&ldap.SearchResult{Entries: []*ldap.Entry{
		newLDAPEntry("ou=sub,ou=root,dc=example,dc=com", nil),
	}}, nil).Once()

	conn := newTestConnection(adapter, connMock)
	subs, err := conn.GetSubOUs("ou=root,dc=example,dc=com", ldap.ScopeSingleLevel)

	assert.NoError(t, err)
	assert.Len(t, subs, 1)
	assert.Equal(t, "ou=sub,ou=root,dc=example,dc=com", subs[0].DN)
}

func TestGetSubOUs_FiltersOutSelf(t *testing.T) {
	// The method drops entries whose DN equals the search base.
	adapter := new(mocks.MockCatalogAdapter)
	adapter.On("OUObjectFilter").Return("(objectClass=organizationalUnit)")
	adapter.On("OUAttrs").Return([]string{"ou"})

	adapter.On("OUInfoFromEntry", mock.Anything).Return(&types.OUInfo{
		DN: "ou=root,dc=example,dc=com", Children: make([]*types.OUInfo, 0),
	}).Once()

	connMock := new(mocks.MockLDAPConn)
	connMock.On("Search", mock.Anything).Return(&ldap.SearchResult{Entries: []*ldap.Entry{
		newLDAPEntry("ou=root,dc=example,dc=com", nil),
	}}, nil).Once()

	conn := newTestConnection(adapter, connMock)
	subs, err := conn.GetSubOUs("ou=root,dc=example,dc=com", ldap.ScopeSingleLevel)

	assert.NoError(t, err)
	assert.Empty(t, subs, "entry with DN equal to the search base must be filtered out")
}

func TestGetSubOUs_FiltersOutUnrelated(t *testing.T) {
	// The method drops entries whose DN does not end with ","+group.
	adapter := new(mocks.MockCatalogAdapter)
	adapter.On("OUObjectFilter").Return("(objectClass=organizationalUnit)")
	adapter.On("OUAttrs").Return([]string{"ou"})

	adapter.On("OUInfoFromEntry", mock.Anything).Return(&types.OUInfo{
		DN: "ou=other,dc=another,dc=com", Children: make([]*types.OUInfo, 0),
	}).Once()

	connMock := new(mocks.MockLDAPConn)
	connMock.On("Search", mock.Anything).Return(&ldap.SearchResult{Entries: []*ldap.Entry{
		newLDAPEntry("ou=other,dc=another,dc=com", nil),
	}}, nil).Once()

	conn := newTestConnection(adapter, connMock)
	subs, err := conn.GetSubOUs("ou=root,dc=example,dc=com", ldap.ScopeSingleLevel)

	assert.NoError(t, err)
	assert.Empty(t, subs, "entry whose DN does not end with \",\"+group must be filtered out")
}

func TestGetSubOUs_DoesNotMatchPrefixSubstring(t *testing.T) {
	// Regression guard: the old implementation used strings.Contains, which
	// would incorrectly match "ou=root2,dc=example,dc=com" against "ou=root".
	// The current implementation uses strings.HasSuffix(dn, ","+group), so
	// such an entry must be filtered out.
	adapter := new(mocks.MockCatalogAdapter)
	adapter.On("OUObjectFilter").Return("(objectClass=organizationalUnit)")
	adapter.On("OUAttrs").Return([]string{"ou"})

	adapter.On("OUInfoFromEntry", mock.Anything).Return(&types.OUInfo{
		DN: "ou=root2,dc=example,dc=com", Children: make([]*types.OUInfo, 0),
	}).Once()

	connMock := new(mocks.MockLDAPConn)
	connMock.On("Search", mock.Anything).Return(&ldap.SearchResult{Entries: []*ldap.Entry{
		newLDAPEntry("ou=root2,dc=example,dc=com", nil),
	}}, nil).Once()

	conn := newTestConnection(adapter, connMock)
	subs, err := conn.GetSubOUs("ou=root,dc=example,dc=com", ldap.ScopeSingleLevel)

	assert.NoError(t, err)
	assert.Empty(t, subs,
		"\"ou=root2,...\" must not be treated as a child of \"ou=root,...\"")
}

func TestGetSubOUs_SearchError(t *testing.T) {
	adapter := new(mocks.MockCatalogAdapter)
	adapter.On("OUObjectFilter").Return("(objectClass=organizationalUnit)")
	adapter.On("OUAttrs").Return([]string{"ou"})

	connMock := new(mocks.MockLDAPConn)
	connMock.On("Search", mock.Anything).
		Return(nil, errors.New("sub search failed")).Once()

	conn := newTestConnection(adapter, connMock)
	subs, err := conn.GetSubOUs("ou=root,dc=example,dc=com", ldap.ScopeSingleLevel)

	assert.NotNil(t, subs)
	assert.Empty(t, subs)
	assert.EqualError(t, err, "unsuccessful sub ou search: sub search failed")
}

func TestGetSubOUs_VerifiesSearchRequest(t *testing.T) {
	adapter := new(mocks.MockCatalogAdapter)
	adapter.On("OUObjectFilter").Return("(objectClass=organizationalUnit)")
	adapter.On("OUAttrs").Return([]string{"ou"})

	connMock := new(mocks.MockLDAPConn)
	connMock.On("Search", mock.MatchedBy(func(req *ldap.SearchRequest) bool {
		return req.BaseDN == "ou=root,dc=example,dc=com" &&
			req.Scope == ldap.ScopeSingleLevel &&
			req.Filter == "(objectClass=organizationalUnit)" &&
			req.TimeLimit == constants.DefaultSearchTimeLimit
	})).Return(&ldap.SearchResult{Entries: []*ldap.Entry{}}, nil).Once()

	conn := newTestConnection(adapter, connMock)
	_, err := conn.GetSubOUs("ou=root,dc=example,dc=com", ldap.ScopeSingleLevel)
	assert.NoError(t, err)
	connMock.AssertExpectations(t)
}

// ---------- GetRecursiveOUSearchResult ----------

func TestGetRecursiveOUSearchResult_AtMaxDepth(t *testing.T) {
	// When level == defaultSearchDepth, the recursion condition
	// (level < defaultSearchDepth) is false, so a single GetSubOUs call
	// is made and its results are attached as Children without further recursion.
	adapter := new(mocks.MockCatalogAdapter)
	adapter.On("OUObjectFilter").Return("(objectClass=organizationalUnit)")
	adapter.On("OUAttrs").Return([]string{"ou"})

	adapter.On("OUInfoFromEntry", mock.Anything).Return(&types.OUInfo{
		DN: "ou=child,ou=root,dc=example,dc=com", Children: make([]*types.OUInfo, 0),
	}).Once()

	connMock := new(mocks.MockLDAPConn)
	connMock.On("Search", mock.Anything).Return(&ldap.SearchResult{Entries: []*ldap.Entry{
		newLDAPEntry("ou=child,ou=root,dc=example,dc=com", nil),
	}}, nil).Once()

	conn := newTestConnection(adapter, connMock)
	root := []*types.OUInfo{{DN: "ou=root,dc=example,dc=com", Children: make([]*types.OUInfo, 0)}}

	conn.GetRecursiveOUSearchResult(&root, constants.DefaultSearchDepth)

	assert.Len(t, root[0].Children, 1)
	assert.Equal(t, "ou=child,ou=root,dc=example,dc=com", root[0].Children[0].DN)
	// Exactly one search — no deeper recursion at max depth.
	connMock.AssertNumberOfCalls(t, "Search", 1)
}

func TestGetRecursiveOUSearchResult_EmptyPrevLevel(t *testing.T) {
	// An empty previous level must not cause any LDAP calls.
	adapter := new(mocks.MockCatalogAdapter)
	connMock := new(mocks.MockLDAPConn)

	conn := newTestConnection(adapter, connMock)
	level := make([]*types.OUInfo, 0)

	conn.GetRecursiveOUSearchResult(&level, 1)

	connMock.AssertNotCalled(t, "Search", mock.Anything)
}

func TestGetRecursiveOUSearchResult_RecursesBelowMaxDepth(t *testing.T) {
	// level (1) < defaultSearchDepth (5) → GetSubOUs runs, and the result
	// is recursively processed (a second search follows for the child).
	adapter := new(mocks.MockCatalogAdapter)
	adapter.On("OUObjectFilter").Return("(objectClass=organizationalUnit)")
	adapter.On("OUAttrs").Return([]string{"ou"})

	// First call: child of root.
	adapter.On("OUInfoFromEntry", mock.Anything).Return(&types.OUInfo{
		DN: "ou=child,ou=root,dc=example,dc=com", Children: make([]*types.OUInfo, 0),
	}).Once()
	// Second call (from the recursive call): grandchild of root.
	adapter.On("OUInfoFromEntry", mock.Anything).Return(&types.OUInfo{
		DN: "ou=grand,ou=child,ou=root,dc=example,dc=com", Children: make([]*types.OUInfo, 0),
	}).Maybe()

	connMock := new(mocks.MockLDAPConn)
	// Search for the child under root.
	connMock.On("Search", mock.MatchedBy(func(req *ldap.SearchRequest) bool {
		return req.BaseDN == "ou=root,dc=example,dc=com"
	})).Return(&ldap.SearchResult{Entries: []*ldap.Entry{
		newLDAPEntry("ou=child,ou=root,dc=example,dc=com", nil),
	}}, nil).Once()
	// Search for the grandchild under the child (recursive call).
	connMock.On("Search", mock.MatchedBy(func(req *ldap.SearchRequest) bool {
		return req.BaseDN == "ou=child,ou=root,dc=example,dc=com"
	})).Return(&ldap.SearchResult{Entries: []*ldap.Entry{}}, nil).Maybe()

	conn := newTestConnection(adapter, connMock)
	root := []*types.OUInfo{{DN: "ou=root,dc=example,dc=com", Children: make([]*types.OUInfo, 0)}}

	conn.GetRecursiveOUSearchResult(&root, 1)

	assert.Len(t, root[0].Children, 1)
	assert.Equal(t, "ou=child,ou=root,dc=example,dc=com", root[0].Children[0].DN)
	connMock.AssertCalled(t, "Search", mock.MatchedBy(func(req *ldap.SearchRequest) bool {
		return req.BaseDN == "ou=root,dc=example,dc=com"
	}))
}
