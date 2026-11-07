// Copyright 2020-2026 NGR Softlab
package ldapper

import (
	"context"
	"errors"
	"testing"

	"github.com/go-ldap/ldap/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/NGRsoftlab/ldapper/mocks"
	"github.com/NGRsoftlab/ldapper/types"
)

// treeAdapter is a CatalogAdapter specialised for tree-discovery tests:
// it returns the minimal filter/attrs and a simple GetNormalizedOUInfoFromEntry
// that reads "ou" as the human-readable name.
type treeAdapter struct {
	fakeAdapter
}

func (treeAdapter) OUObjectFilter() string { return "(objectClass=organizationalUnit)" }
func (treeAdapter) OUAttrs() []string      { return []string{"ou"} }
func (treeAdapter) GetNormalizedOUInfoFromEntry(entry ldap.Entry) *types.OUNormalizedInfo {
	name := entry.GetAttributeValue("ou")
	if name == "" {
		name = entry.DN
	}
	return &types.OUNormalizedInfo{
		DN:       entry.DN,
		Name:     name,
		OU:       name,
		Children: make([]*types.OUNormalizedInfo, 0),
	}
}

func newTreeLDAPper(conn *mocks.MockLDAPConn) *LDAPper {
	l := &LDAPper{
		catalogAdapter: treeAdapter{},
		searchLimits:   DefaultSearchLimits(),
	}
	if conn != nil {
		l.connection = conn
	}
	return l
}

// treeServer emulates an LDAP server for the OU-tree tests:
//   - ScopeSingleLevel  → only direct children of req.BaseDN
//   - ScopeWholeSubtree → every entry under req.BaseDN
//
// allEntries must be ordered so that DFS in walkCatalogTreeLocked produces
// the order the test expects. This is deterministic: the walk iterates over
// the server-returned order slice, not over a map.
type treeServer struct {
	allEntries []*ldap.Entry
	lastScope  int
	lastBaseDN string
}

func (s *treeServer) search(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
	s.lastScope = req.Scope
	s.lastBaseDN = req.BaseDN

	baseDN, err := ldap.ParseDN(req.BaseDN)
	if err != nil {
		return nil, err
	}

	var filtered []*ldap.Entry
	for _, e := range s.allEntries {
		parsed, err := ldap.ParseDN(e.DN)
		if err != nil {
			continue
		}
		if !baseDN.AncestorOfFold(parsed) {
			continue
		}
		if req.Scope == ldap.ScopeSingleLevel && parentDNOf(e.DN) != req.BaseDN {
			continue
		}
		filtered = append(filtered, e)
	}
	return pagedResponse(filtered, nil), nil
}

// standardTree is the canonical hierarchy used by most tests below:
//
//	dc=x
//	├── ou=sales
//	│   ├── ou=east
//	│   │   └── ou=a            (depth 2 from base)
//	│   └── ou=west
//	└── ou=engineering
//
// Order matters for DFS expectations.
func standardTree() []*ldap.Entry {
	return []*ldap.Entry{
		newLDAPEntry("ou=sales,dc=x", map[string][]string{"ou": {"sales"}}),
		newLDAPEntry("ou=east,ou=sales,dc=x", map[string][]string{"ou": {"east"}}),
		newLDAPEntry("ou=west,ou=sales,dc=x", map[string][]string{"ou": {"west"}}),
		newLDAPEntry("ou=engineering,dc=x", map[string][]string{"ou": {"engineering"}}),
		newLDAPEntry("ou=a,ou=east,ou=sales,dc=x", map[string][]string{"ou": {"a"}}),
	}
}

// walkEvent captures one callback invocation.
type walkEvent struct {
	depth int
	name  string
}

// ================== WalkCatalogTree ==================

func TestWalkCatalogTree_NilCallback(t *testing.T) {
	t.Parallel()

	l := newTreeLDAPper(&mocks.MockLDAPConn{})
	err := l.WalkCatalogTree(context.Background(), "dc=x", 0, nil)

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidArgument)
}

func TestWalkCatalogTree_NoConnection(t *testing.T) {
	t.Parallel()

	l := newTreeLDAPper(nil)
	err := l.WalkCatalogTree(context.Background(), "dc=x", 0,
		func(context.Context, int, *types.OUNormalizedInfo) error { return nil })

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrClosed)
}

func TestWalkCatalogTree_InvalidBaseDN(t *testing.T) {
	t.Parallel()

	l := newTreeLDAPper(&mocks.MockLDAPConn{})
	err := l.WalkCatalogTree(context.Background(), "not-a-dn", 0,
		func(context.Context, int, *types.OUNormalizedInfo) error { return nil })

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidArgument)
}

func TestWalkCatalogTree_EmptyResult(t *testing.T) {
	t.Parallel()

	conn := &mocks.MockLDAPConn{
		SearchFunc: func(*ldap.SearchRequest) (*ldap.SearchResult, error) {
			return pagedResponse(nil, nil), nil
		},
	}
	l := newTreeLDAPper(conn)

	var events []walkEvent
	err := l.WalkCatalogTree(context.Background(), "dc=x", 0,
		func(_ context.Context, depth int, node *types.OUNormalizedInfo) error {
			events = append(events, walkEvent{depth, node.Name})
			return nil
		})

	require.NoError(t, err)
	assert.Empty(t, events)
}

func TestWalkCatalogTree_MaxDepth1_UsesSingleLevelScope(t *testing.T) {
	t.Parallel()

	server := &treeServer{allEntries: standardTree()}
	conn := &mocks.MockLDAPConn{SearchFunc: server.search}
	l := newTreeLDAPper(conn)

	var events []walkEvent
	err := l.WalkCatalogTree(context.Background(), "dc=x", 1,
		func(_ context.Context, depth int, node *types.OUNormalizedInfo) error {
			events = append(events, walkEvent{depth, node.Name})
			return nil
		})

	require.NoError(t, err)
	assert.Equal(t, ldap.ScopeSingleLevel, server.lastScope,
		"maxDepth=1 must take the fast path via ScopeSingleLevel")
	assert.Equal(t, []walkEvent{
		{0, "sales"},
		{0, "engineering"},
	}, events, "maxDepth=1 returns only direct children at depth 0")
}

func TestWalkCatalogTree_MaxDepthGreaterThan1_UsesWholeSubtree(t *testing.T) {
	t.Parallel()

	server := &treeServer{allEntries: standardTree()}
	conn := &mocks.MockLDAPConn{SearchFunc: server.search}
	l := newTreeLDAPper(conn)

	err := l.WalkCatalogTree(context.Background(), "dc=x", 2,
		func(context.Context, int, *types.OUNormalizedInfo) error { return nil })

	require.NoError(t, err)
	assert.Equal(t, ldap.ScopeWholeSubtree, server.lastScope)
}

func TestWalkCatalogTree_MaxDepth0_UsesWholeSubtree(t *testing.T) {
	t.Parallel()

	server := &treeServer{allEntries: standardTree()}
	conn := &mocks.MockLDAPConn{SearchFunc: server.search}
	l := newTreeLDAPper(conn)

	err := l.WalkCatalogTree(context.Background(), "dc=x", 0,
		func(context.Context, int, *types.OUNormalizedInfo) error { return nil })

	require.NoError(t, err)
	assert.Equal(t, ldap.ScopeWholeSubtree, server.lastScope)
}

func TestWalkCatalogTree_DFSOrder_NoDepthLimit(t *testing.T) {
	t.Parallel()

	server := &treeServer{allEntries: standardTree()}
	conn := &mocks.MockLDAPConn{SearchFunc: server.search}
	l := newTreeLDAPper(conn)

	var events []walkEvent
	err := l.WalkCatalogTree(context.Background(), "dc=x", 0,
		func(_ context.Context, depth int, node *types.OUNormalizedInfo) error {
			events = append(events, walkEvent{depth, node.Name})
			return nil
		})

	require.NoError(t, err)
	assert.Equal(t, []walkEvent{
		{0, "sales"},
		{1, "east"},
		{2, "a"},
		{1, "west"},
		{0, "engineering"},
	}, events, "DFS order and depth values must match the hierarchy")
}

func TestWalkCatalogTree_MaxDepth2_TruncatesBelowLevel1(t *testing.T) {
	t.Parallel()

	server := &treeServer{allEntries: standardTree()}
	conn := &mocks.MockLDAPConn{SearchFunc: server.search}
	l := newTreeLDAPper(conn)

	var events []walkEvent
	err := l.WalkCatalogTree(context.Background(), "dc=x", 2,
		func(_ context.Context, depth int, node *types.OUNormalizedInfo) error {
			events = append(events, walkEvent{depth, node.Name})
			return nil
		})

	require.NoError(t, err)
	assert.Equal(t, []walkEvent{
		{0, "sales"},
		{1, "east"},
		{1, "west"},
		{0, "engineering"},
	}, events, "depth=2 entries must be truncated; east/west still visited")
}

func TestWalkCatalogTree_FiltersEntriesOutsideBaseDN(t *testing.T) {
	t.Parallel()

	// Server returns an entry from a different subtree; AncestorOfFold
	// must drop it before the callback.
	entries := []*ldap.Entry{
		newLDAPEntry("ou=sales,dc=x", map[string][]string{"ou": {"sales"}}),
		newLDAPEntry("ou=other,dc=elsewhere", map[string][]string{"ou": {"other"}}),
	}
	server := &treeServer{allEntries: entries}
	conn := &mocks.MockLDAPConn{SearchFunc: server.search}
	l := newTreeLDAPper(conn)

	var names []string
	err := l.WalkCatalogTree(context.Background(), "dc=x", 0,
		func(_ context.Context, _ int, node *types.OUNormalizedInfo) error {
			names = append(names, node.Name)
			return nil
		})

	require.NoError(t, err)
	assert.Equal(t, []string{"sales"}, names,
		"entries outside the baseDN must be silently skipped")
}

func TestWalkCatalogTree_DeduplicatesByCanonicalDN(t *testing.T) {
	t.Parallel()

	// Same DN in different case — canonicalDN collapses them.
	entries := []*ldap.Entry{
		newLDAPEntry("ou=sales,dc=x", map[string][]string{"ou": {"sales"}}),
		newLDAPEntry("OU=Sales,DC=x", map[string][]string{"ou": {"Sales"}}),
	}
	server := &treeServer{allEntries: entries}
	conn := &mocks.MockLDAPConn{SearchFunc: server.search}
	l := newTreeLDAPper(conn)

	callCount := 0
	err := l.WalkCatalogTree(context.Background(), "DC=x", 0,
		func(context.Context, int, *types.OUNormalizedInfo) error {
			callCount++
			return nil
		})

	require.NoError(t, err)
	assert.Equal(t, 1, callCount, "case-different duplicates must collapse")
}

func TestWalkCatalogTree_CallbackErrorStopsWalk(t *testing.T) {
	t.Parallel()

	server := &treeServer{allEntries: standardTree()}
	conn := &mocks.MockLDAPConn{SearchFunc: server.search}
	l := newTreeLDAPper(conn)

	wantErr := errors.New("stop")
	calls := 0
	err := l.WalkCatalogTree(context.Background(), "dc=x", 0,
		func(_ context.Context, _ int, node *types.OUNormalizedInfo) error {
			calls++
			if node.Name == "east" {
				return wantErr
			}
			return nil
		})

	require.Error(t, err)
	assert.ErrorIs(t, err, wantErr)
	assert.Equal(t, 2, calls, "walk must stop after the callback returns an error")
}

func TestWalkCatalogTree_CtxCancelledBeforeStart(t *testing.T) {
	t.Parallel()

	server := &treeServer{allEntries: standardTree()}
	conn := &mocks.MockLDAPConn{SearchFunc: server.search}
	l := newTreeLDAPper(conn)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	calls := 0
	err := l.WalkCatalogTree(ctx, "dc=x", 0,
		func(context.Context, int, *types.OUNormalizedInfo) error {
			calls++
			return nil
		})

	require.Error(t, err)
	assert.ErrorIs(t, err, context.Canceled)
	assert.Zero(t, calls)
}

// ================== GetCatalogTree ==================

func TestGetCatalogTree_SingleLevel(t *testing.T) {
	t.Parallel()

	server := &treeServer{allEntries: standardTree()}
	conn := &mocks.MockLDAPConn{SearchFunc: server.search}
	l := newTreeLDAPper(conn)

	tree, err := l.GetCatalogTree(context.Background(), "dc=x", 1)

	require.NoError(t, err)
	require.Len(t, tree.Tree, 2)
	assert.Equal(t, "sales", tree.Tree[0].Name)
	assert.Empty(t, tree.Tree[0].Children, "maxDepth=1 leaves children empty")
	assert.Equal(t, "engineering", tree.Tree[1].Name)
}

func TestGetCatalogTree_Nested(t *testing.T) {
	t.Parallel()

	server := &treeServer{allEntries: standardTree()}
	conn := &mocks.MockLDAPConn{SearchFunc: server.search}
	l := newTreeLDAPper(conn)

	tree, err := l.GetCatalogTree(context.Background(), "dc=x", 0)

	require.NoError(t, err)
	require.Len(t, tree.Tree, 2)

	sales := tree.Tree[0]
	require.Equal(t, "sales", sales.Name)
	require.Len(t, sales.Children, 2)
	assert.Equal(t, "east", sales.Children[0].Name)
	assert.Equal(t, "west", sales.Children[1].Name)

	require.Len(t, sales.Children[0].Children, 1,
		"east must carry its own child 'a'")
	assert.Equal(t, "a", sales.Children[0].Children[0].Name)

	eng := tree.Tree[1]
	require.Equal(t, "engineering", eng.Name)
	assert.Empty(t, eng.Children)
}

func TestGetCatalogTree_OrphanPromotedToRoot(t *testing.T) {
	t.Parallel()

	// 'sales' is absent from the fetched set (ACL-filtered on the server);
	// 'east' is returned without its parent. It must be promoted to root
	// rather than silently dropped — that's the documented contract.
	entries := []*ldap.Entry{
		newLDAPEntry("ou=east,ou=sales,dc=x", map[string][]string{"ou": {"east"}}),
		newLDAPEntry("ou=engineering,dc=x", map[string][]string{"ou": {"engineering"}}),
	}
	server := &treeServer{allEntries: entries}
	conn := &mocks.MockLDAPConn{SearchFunc: server.search}
	l := newTreeLDAPper(conn)

	tree, err := l.GetCatalogTree(context.Background(), "dc=x", 0)

	require.NoError(t, err)
	names := make([]string, 0, len(tree.Tree))
	for _, n := range tree.Tree {
		names = append(names, n.Name)
	}
	assert.ElementsMatch(t, []string{"east", "engineering"}, names,
		"orphans become roots of the resulting tree")
}

func TestGetCatalogTree_EmptyResultReturnsNonNilTree(t *testing.T) {
	t.Parallel()

	conn := &mocks.MockLDAPConn{
		SearchFunc: func(*ldap.SearchRequest) (*ldap.SearchResult, error) {
			return pagedResponse(nil, nil), nil
		},
	}
	l := newTreeLDAPper(conn)

	tree, err := l.GetCatalogTree(context.Background(), "dc=x", 0)

	require.NoError(t, err)
	assert.NotNil(t, tree.Tree,
		"empty result must be a non-nil slice for JSON serialisation consistency")
	assert.Empty(t, tree.Tree)
}

func TestGetCatalogTree_WalkErrorReturnsEmptyTree(t *testing.T) {
	t.Parallel()

	conn := &mocks.MockLDAPConn{
		SearchFunc: func(*ldap.SearchRequest) (*ldap.SearchResult, error) {
			return nil, errors.New("server down")
		},
	}
	l := newTreeLDAPper(conn)

	tree, err := l.GetCatalogTree(context.Background(), "dc=x", 0)

	require.Error(t, err)
	assert.NotNil(t, tree.Tree,
		"a failed walk must discard partial state, not leave a half-built tree")
	assert.Empty(t, tree.Tree)
}

func TestGetCatalogTree_ResetsChildrenFromAdapter(t *testing.T) {
	t.Parallel()

	// Defensive: a custom adapter that pre-populates Children must not
	// leave stale entries in the result — the tree builder owns the field.
	customAdapter := func(entry ldap.Entry) *types.OUNormalizedInfo {
		return &types.OUNormalizedInfo{
			DN:   entry.DN,
			Name: entry.GetAttributeValue("ou"),
			Children: []*types.OUNormalizedInfo{
				{DN: "stale", Name: "stale"},
			},
		}
	}

	conn := &mocks.MockLDAPConn{
		SearchFunc: func(*ldap.SearchRequest) (*ldap.SearchResult, error) {
			return pagedResponse([]*ldap.Entry{
				newLDAPEntry("ou=sales,dc=x", map[string][]string{"ou": {"sales"}}),
			}, nil), nil
		},
	}
	l := newTreeLDAPper(conn)
	l.catalogAdapter = childrenPopulatingAdapter{treeAdapter{}, customAdapter}

	tree, err := l.GetCatalogTree(context.Background(), "dc=x", 0)

	require.NoError(t, err)
	require.Len(t, tree.Tree, 1)
	assert.Empty(t, tree.Tree[0].Children,
		"stale Children from the adapter must be cleared")
}

// childrenPopulatingAdapter delegates everything to the embedded adapter
// but overrides GetNormalizedOUInfoFromEntry with the caller-supplied fn.
type childrenPopulatingAdapter struct {
	treeAdapter
	fn func(ldap.Entry) *types.OUNormalizedInfo
}

func (a childrenPopulatingAdapter) GetNormalizedOUInfoFromEntry(e ldap.Entry) *types.OUNormalizedInfo {
	return a.fn(e)
}

// ================== ListSingleLevelOUs ==================

func TestListSingleLevelOUs_UsesSingleLevelScope(t *testing.T) {
	t.Parallel()

	server := &treeServer{allEntries: standardTree()}
	conn := &mocks.MockLDAPConn{SearchFunc: server.search}
	l := newTreeLDAPper(conn)

	ous, err := l.ListSingleLevelOUs(context.Background(), "dc=x")

	require.NoError(t, err)
	assert.Equal(t, ldap.ScopeSingleLevel, server.lastScope)
	names := make([]string, 0, len(ous))
	for _, ou := range ous {
		names = append(names, ou.Name)
	}
	assert.ElementsMatch(t, []string{"sales", "engineering"}, names)
}

// ================== GetSubOUs ==================

func TestGetSubOUs_NoConnection(t *testing.T) {
	t.Parallel()

	l := newTreeLDAPper(nil)
	_, err := l.GetSubOUs(context.Background(), "dc=x", ldap.ScopeSingleLevel)

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrClosed)
}

func TestGetSubOUs_InvalidScope(t *testing.T) {
	t.Parallel()

	l := newTreeLDAPper(&mocks.MockLDAPConn{})

	t.Run("base object rejected", func(t *testing.T) {
		t.Parallel()
		_, err := l.GetSubOUs(context.Background(), "dc=x", ldap.ScopeBaseObject)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidArgument)
		assert.Contains(t, err.Error(), "ScopeBaseObject")
	})

	t.Run("arbitrary scope rejected", func(t *testing.T) {
		t.Parallel()
		_, err := l.GetSubOUs(context.Background(), "dc=x", 999)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidArgument)
	})
}

func TestGetSubOUs_InvalidParentDN(t *testing.T) {
	t.Parallel()

	l := newTreeLDAPper(&mocks.MockLDAPConn{})
	_, err := l.GetSubOUs(context.Background(), "not-a-dn", ldap.ScopeSingleLevel)

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidArgument)
}

func TestGetSubOUs_SingleLevel(t *testing.T) {
	t.Parallel()

	server := &treeServer{allEntries: standardTree()}
	conn := &mocks.MockLDAPConn{SearchFunc: server.search}
	l := newTreeLDAPper(conn)

	ous, err := l.GetSubOUs(context.Background(), "dc=x", ldap.ScopeSingleLevel)

	require.NoError(t, err)
	names := make([]string, 0, len(ous))
	for _, ou := range ous {
		names = append(names, ou.Name)
	}
	assert.ElementsMatch(t, []string{"sales", "engineering"}, names)
}

func TestGetSubOUs_WholeSubtree(t *testing.T) {
	t.Parallel()

	server := &treeServer{allEntries: standardTree()}
	conn := &mocks.MockLDAPConn{SearchFunc: server.search}
	l := newTreeLDAPper(conn)

	ous, err := l.GetSubOUs(context.Background(), "dc=x", ldap.ScopeWholeSubtree)

	require.NoError(t, err)
	names := make([]string, 0, len(ous))
	for _, ou := range ous {
		names = append(names, ou.Name)
	}
	assert.ElementsMatch(t,
		[]string{"sales", "east", "west", "engineering", "a"},
		names)
}

func TestGetSubOUs_ExcludesParentItself(t *testing.T) {
	t.Parallel()

	// Server returns the parentDN in the result set; GetSubOUs must drop it.
	// This happens when the server treats the base as part of the subtree.
	entries := []*ldap.Entry{
		newLDAPEntry("ou=sales,dc=x", map[string][]string{"ou": {"sales"}}),
		newLDAPEntry("ou=east,ou=sales,dc=x", map[string][]string{"ou": {"east"}}),
	}
	server := &treeServer{allEntries: entries}
	conn := &mocks.MockLDAPConn{SearchFunc: server.search}
	l := newTreeLDAPper(conn)

	ous, err := l.GetSubOUs(context.Background(), "ou=sales,dc=x", ldap.ScopeWholeSubtree)

	require.NoError(t, err)
	names := make([]string, 0, len(ous))
	for _, ou := range ous {
		names = append(names, ou.Name)
	}
	assert.Equal(t, []string{"east"}, names,
		"parentDN itself must be excluded; only descendants remain")
}

func TestGetSubOUs_DeduplicatesByCanonicalDN(t *testing.T) {
	t.Parallel()

	entries := []*ldap.Entry{
		newLDAPEntry("ou=sales,dc=x", map[string][]string{"ou": {"sales"}}),
		newLDAPEntry("OU=Sales,DC=x", map[string][]string{"ou": {"Sales"}}),
		newLDAPEntry("ou=east,ou=sales,dc=x", map[string][]string{"ou": {"east"}}),
	}
	server := &treeServer{allEntries: entries}
	conn := &mocks.MockLDAPConn{SearchFunc: server.search}
	l := newTreeLDAPper(conn)

	ous, err := l.GetSubOUs(context.Background(), "dc=x", ldap.ScopeWholeSubtree)

	require.NoError(t, err)
	assert.Len(t, ous, 2, "case-different duplicates must collapse")
}

func TestGetSubOUs_EmptyResultIsNonNil(t *testing.T) {
	t.Parallel()

	conn := &mocks.MockLDAPConn{
		SearchFunc: func(*ldap.SearchRequest) (*ldap.SearchResult, error) {
			return pagedResponse(nil, nil), nil
		},
	}
	l := newTreeLDAPper(conn)

	ous, err := l.GetSubOUs(context.Background(), "dc=x", ldap.ScopeSingleLevel)

	require.NoError(t, err)
	assert.NotNil(t, ous)
	assert.Empty(t, ous)
}

func TestGetSubOUs_SearchErrorClassified(t *testing.T) {
	t.Parallel()

	conn := &mocks.MockLDAPConn{
		SearchFunc: func(*ldap.SearchRequest) (*ldap.SearchResult, error) {
			return nil, ldap.NewError(ldap.LDAPResultUnavailable, errors.New("down"))
		},
	}
	l := newTreeLDAPper(conn)

	_, err := l.GetSubOUs(context.Background(), "dc=x", ldap.ScopeWholeSubtree)

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrUnavailable)
}
