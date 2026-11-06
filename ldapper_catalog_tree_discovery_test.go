// Copyright 2020-2026 NGR Softlab
package ldapper

import (
	"errors"
	"testing"

	"github.com/go-ldap/ldap/v3"

	"github.com/NGRsoftlab/ldapper/mocks"
	"github.com/NGRsoftlab/ldapper/types"
)

// ouTreeAdapter returns a fake adapter that projects every entry into an
// OUNormalizedInfo with an empty (non-nil) Children slice. This matches
// the behaviour of the built-in adapters and keeps DeepEqual comparisons
// deterministic.
func ouTreeAdapter() *fakeAdapter {
	return &fakeAdapter{
		ouObjFilter: "(&(objectClass=organizationalUnit))",
		ouAttrs:     []string{"ou"},
		normalizedOU: func(e ldap.Entry) *types.OUNormalizedInfo {
			return &types.OUNormalizedInfo{
				DN:       e.DN,
				Name:     e.DN,
				OU:       e.GetAttributeValue("ou"),
				Children: make([]*types.OUNormalizedInfo, 0),
			}
		},
	}
}

// collectDNs flattens a tree to the set of DNs reachable from its roots,
// ignoring structure. Sufficient for "is every node present once" checks.
func collectDNs(nodes []*types.OUNormalizedInfo) []string {
	var out []string
	for _, n := range nodes {
		out = append(out, n.DN)
		out = append(out, collectDNs(n.Children)...)
	}
	return out
}

// findNode locates a node by DN in a tree (recursive).
func findNode(nodes []*types.OUNormalizedInfo, dn string) *types.OUNormalizedInfo {
	for _, n := range nodes {
		if n.DN == dn {
			return n
		}
		if got := findNode(n.Children, dn); got != nil {
			return got
		}
	}
	return nil
}

// ---------- GetCatalogTree ----------

// TestGetCatalogTree covers tree building from a single paged search:
// filtering, orphan promotion, case-insensitive DN matching, malformed
// entries and depth trimming.
func TestGetCatalogTree(t *testing.T) {
	const baseDN = "dc=example,dc=com"

	t.Run("nil connection", func(t *testing.T) {
		l := &LDAPper{catalogAdapter: ouTreeAdapter()}
		_, err := l.GetCatalogTree(baseDN, 0)
		if !errors.Is(err, ErrClosed) {
			t.Fatalf("errors.Is(%v, ErrClosed) = false", err)
		}
	})

	t.Run("invalid base DN", func(t *testing.T) {
		l := &LDAPper{connection: mockOUs(), catalogAdapter: ouTreeAdapter()}
		_, err := l.GetCatalogTree("not a dn", 0)
		if !errors.Is(err, ErrInvalidArgument) {
			t.Fatalf("errors.Is(%v, ErrInvalidArgument) = false", err)
		}
	})

	t.Run("empty base DN rejected by searchPaged", func(t *testing.T) {
		l := &LDAPper{connection: mockOUs(), catalogAdapter: ouTreeAdapter()}
		_, err := l.GetCatalogTree("", 0)
		if !errors.Is(err, ErrInvalidArgument) {
			t.Fatalf("errors.Is(%v, ErrInvalidArgument) = false", err)
		}
	})

	t.Run("empty result yields empty tree", func(t *testing.T) {
		l := &LDAPper{connection: mockOUs(), catalogAdapter: ouTreeAdapter()}
		tree, err := l.GetCatalogTree(baseDN, 0)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(tree.Tree) != 0 {
			t.Fatalf("tree.Tree = %v, want empty", tree.Tree)
		}
	})

	t.Run("single root node", func(t *testing.T) {
		entry := newLDAPEntry("ou=Sales,dc=example,dc=com", map[string][]string{"ou": {"Sales"}})
		l := &LDAPper{connection: mockOUs(entry), catalogAdapter: ouTreeAdapter()}
		tree, err := l.GetCatalogTree(baseDN, 0)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(tree.Tree) != 1 || tree.Tree[0].DN != entry.DN {
			t.Fatalf("tree.Tree = %v", tree.Tree)
		}
		if len(tree.Tree[0].Children) != 0 {
			t.Fatalf("leaf has children: %v", tree.Tree[0].Children)
		}
	})

	t.Run("two siblings at root", func(t *testing.T) {
		e1 := newLDAPEntry("ou=People,dc=example,dc=com", nil)
		e2 := newLDAPEntry("ou=Sales,dc=example,dc=com", nil)
		l := &LDAPper{connection: mockOUs(e1, e2), catalogAdapter: ouTreeAdapter()}
		tree, err := l.GetCatalogTree(baseDN, 0)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(tree.Tree) != 2 {
			t.Fatalf("len = %d, want 2", len(tree.Tree))
		}
		dns := collectDNs(tree.Tree)
		if len(dns) != 2 {
			t.Fatalf("dns = %v", dns)
		}
	})

	t.Run("parent-child hierarchy", func(t *testing.T) {
		parent := newLDAPEntry("ou=Sales,dc=example,dc=com", nil)
		child := newLDAPEntry("ou=EMEA,ou=Sales,dc=example,dc=com", nil)
		l := &LDAPper{connection: mockOUs(parent, child), catalogAdapter: ouTreeAdapter()}
		tree, err := l.GetCatalogTree(baseDN, 0)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(tree.Tree) != 1 || tree.Tree[0].DN != parent.DN {
			t.Fatalf("root = %v", tree.Tree)
		}
		if len(tree.Tree[0].Children) != 1 || tree.Tree[0].Children[0].DN != child.DN {
			t.Fatalf("children = %v", tree.Tree[0].Children)
		}
	})

	t.Run("case-insensitive parent match", func(t *testing.T) {
		parent := newLDAPEntry("OU=Sales,DC=example,DC=com", nil)
		child := newLDAPEntry("ou=EMEA,ou=sales,dc=example,dc=com", nil)
		l := &LDAPper{connection: mockOUs(parent, child), catalogAdapter: ouTreeAdapter()}
		tree, err := l.GetCatalogTree(baseDN, 0)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		// Despite differing case, the child must attach to the parent.
		if len(tree.Tree) != 1 || len(tree.Tree[0].Children) != 1 {
			t.Fatalf("hierarchy lost on case difference: %+v", tree.Tree)
		}
	})

	t.Run("base DN itself is excluded", func(t *testing.T) {
		base := newLDAPEntry(baseDN, nil)
		child := newLDAPEntry("ou=Sales,dc=example,dc=com", nil)
		l := &LDAPper{connection: mockOUs(base, child), catalogAdapter: ouTreeAdapter()}
		tree, err := l.GetCatalogTree(baseDN, 0)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if findNode(tree.Tree, baseDN) != nil {
			t.Fatalf("base DN must be excluded, tree = %v", tree.Tree)
		}
		if findNode(tree.Tree, child.DN) == nil {
			t.Fatalf("child missing")
		}
	})

	t.Run("entry outside base DN is excluded", func(t *testing.T) {
		inside := newLDAPEntry("ou=Sales,dc=example,dc=com", nil)
		outside := newLDAPEntry("ou=Sales,dc=other,dc=com", nil)
		l := &LDAPper{connection: mockOUs(inside, outside), catalogAdapter: ouTreeAdapter()}
		tree, err := l.GetCatalogTree(baseDN, 0)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if findNode(tree.Tree, outside.DN) != nil {
			t.Fatalf("out-of-tree DN leaked: %v", tree.Tree)
		}
		if findNode(tree.Tree, inside.DN) == nil {
			t.Fatalf("in-tree DN missing")
		}
	})

	t.Run("orphan promoted to root", func(t *testing.T) {
		// Child without its parent present (e.g. server filtered the parent).
		orphan := newLDAPEntry("ou=EMEA,ou=Sales,dc=example,dc=com", nil)
		l := &LDAPper{connection: mockOUs(orphan), catalogAdapter: ouTreeAdapter()}
		tree, err := l.GetCatalogTree(baseDN, 0)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(tree.Tree) != 1 || tree.Tree[0].DN != orphan.DN {
			t.Fatalf("orphan not promoted: %v", tree.Tree)
		}
	})

	t.Run("malformed entry DN is skipped", func(t *testing.T) {
		good := newLDAPEntry("ou=Sales,dc=example,dc=com", nil)
		bad := newLDAPEntry("not-a-valid-dn", nil)
		l := &LDAPper{connection: mockOUs(good, bad), catalogAdapter: ouTreeAdapter()}
		tree, err := l.GetCatalogTree(baseDN, 0)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if findNode(tree.Tree, "not-a-valid-dn") != nil {
			t.Fatalf("malformed DN not skipped: %v", tree.Tree)
		}
		if findNode(tree.Tree, good.DN) == nil {
			t.Fatalf("good entry missing")
		}
	})

	t.Run("empty DN from adapter is skipped", func(t *testing.T) {
		good := newLDAPEntry("ou=Sales,dc=example,dc=com", nil)
		bad := newLDAPEntry("", nil) // adapter returns info with DN=""
		l := &LDAPper{connection: mockOUs(good, bad), catalogAdapter: ouTreeAdapter()}
		tree, err := l.GetCatalogTree(baseDN, 0)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(tree.Tree) != 1 {
			t.Fatalf("tree = %v", tree.Tree)
		}
	})

	t.Run("maxDepth=1 keeps only roots", func(t *testing.T) {
		parent := newLDAPEntry("ou=Sales,dc=example,dc=com", nil)
		child := newLDAPEntry("ou=EMEA,ou=Sales,dc=example,dc=com", nil)
		l := &LDAPper{connection: mockOUs(parent, child), catalogAdapter: ouTreeAdapter()}
		tree, err := l.GetCatalogTree(baseDN, 1)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(tree.Tree) != 1 {
			t.Fatalf("tree = %v", tree.Tree)
		}
		if len(tree.Tree[0].Children) != 0 {
			t.Fatalf("maxDepth=1 should clear children, got %v", tree.Tree[0].Children)
		}
	})

	t.Run("search error propagates as ErrInvalidArgument via searchPaged", func(t *testing.T) {
		raw := &ldap.Error{ResultCode: ldap.LDAPResultUnavailable, Err: errors.New("down")}
		mock := &mocks.MockLDAPConn{
			SearchFunc: func(*ldap.SearchRequest) (*ldap.SearchResult, error) { return nil, raw },
		}
		l := &LDAPper{connection: mock, catalogAdapter: ouTreeAdapter()}
		_, err := l.GetCatalogTree(baseDN, 0)
		if !errors.Is(err, ErrUnavailable) {
			t.Fatalf("errors.Is(%v, ErrUnavailable) = false", err)
		}
	})
}

// ---------- GetSubOUs / ListSingleLevelOUs ----------

// TestGetSubOUs covers the descendants-only contract, scope validation and
// base DN exclusion.
func TestGetSubOUs(t *testing.T) {
	const baseDN = "dc=example,dc=com"

	t.Run("nil connection", func(t *testing.T) {
		l := &LDAPper{catalogAdapter: ouTreeAdapter()}
		_, err := l.GetSubOUs(baseDN, ldap.ScopeSingleLevel)
		if !errors.Is(err, ErrClosed) {
			t.Fatalf("errors.Is(%v, ErrClosed) = false", err)
		}
	})

	t.Run("ScopeBaseObject rejected", func(t *testing.T) {
		l := &LDAPper{connection: mockOUs(), catalogAdapter: ouTreeAdapter()}
		_, err := l.GetSubOUs(baseDN, ldap.ScopeBaseObject)
		if !errors.Is(err, ErrInvalidArgument) {
			t.Fatalf("errors.Is(%v, ErrInvalidArgument) = false", err)
		}
	})

	t.Run("invalid scope rejected", func(t *testing.T) {
		l := &LDAPper{connection: mockOUs(), catalogAdapter: ouTreeAdapter()}
		_, err := l.GetSubOUs(baseDN, 99)
		if !errors.Is(err, ErrInvalidArgument) {
			t.Fatalf("errors.Is(%v, ErrInvalidArgument) = false", err)
		}
	})

	t.Run("malformed parent DN rejected", func(t *testing.T) {
		l := &LDAPper{connection: mockOUs(), catalogAdapter: ouTreeAdapter()}
		_, err := l.GetSubOUs("not a dn", ldap.ScopeSingleLevel)
		if !errors.Is(err, ErrInvalidArgument) {
			t.Fatalf("errors.Is(%v, ErrInvalidArgument) = false", err)
		}
	})

	t.Run("single-level returns direct children", func(t *testing.T) {
		// Server for ScopeSingleLevel returns only direct children.
		e1 := newLDAPEntry("ou=Sales,dc=example,dc=com", nil)
		e2 := newLDAPEntry("ou=People,dc=example,dc=com", nil)
		l := &LDAPper{connection: mockOUs(e1, e2), catalogAdapter: ouTreeAdapter()}
		ous, err := l.GetSubOUs(baseDN, ldap.ScopeSingleLevel)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(ous) != 2 {
			t.Fatalf("len = %d, want 2", len(ous))
		}
	})

	t.Run("subtree excludes base DN itself", func(t *testing.T) {
		base := newLDAPEntry(baseDN, nil)
		child := newLDAPEntry("ou=Sales,dc=example,dc=com", nil)
		l := &LDAPper{connection: mockOUs(base, child), catalogAdapter: ouTreeAdapter()}
		ous, err := l.GetSubOUs(baseDN, ldap.ScopeWholeSubtree)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(ous) != 1 || ous[0].DN != child.DN {
			t.Fatalf("ous = %v (base must be excluded)", ous)
		}
	})

	t.Run("empty result", func(t *testing.T) {
		l := &LDAPper{connection: mockOUs(), catalogAdapter: ouTreeAdapter()}
		ous, err := l.GetSubOUs(baseDN, ldap.ScopeSingleLevel)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(ous) != 0 {
			t.Fatalf("ous = %v, want empty", ous)
		}
	})

	t.Run("search error classified", func(t *testing.T) {
		raw := &ldap.Error{ResultCode: ldap.LDAPResultUnavailable, Err: errors.New("down")}
		mock := &mocks.MockLDAPConn{
			SearchFunc: func(*ldap.SearchRequest) (*ldap.SearchResult, error) { return nil, raw },
		}
		l := &LDAPper{connection: mock, catalogAdapter: ouTreeAdapter()}
		_, err := l.GetSubOUs(baseDN, ldap.ScopeSingleLevel)
		if !errors.Is(err, ErrUnavailable) {
			t.Fatalf("errors.Is(%v, ErrUnavailable) = false", err)
		}
	})
}

// TestListSingleLevelOUs verifies the thin delegate wrapper.
func TestListSingleLevelOUs(t *testing.T) {
	const baseDN = "dc=example,dc=com"
	e1 := newLDAPEntry("ou=Sales,dc=example,dc=com", nil)

	var observedScope int
	mock := &mocks.MockLDAPConn{
		SearchFunc: func(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
			observedScope = req.Scope
			return &ldap.SearchResult{Entries: []*ldap.Entry{e1}}, nil
		},
	}
	l := &LDAPper{connection: mock, catalogAdapter: ouTreeAdapter()}

	ous, err := l.ListSingleLevelOUs(baseDN)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if observedScope != ldap.ScopeSingleLevel {
		t.Fatalf("scope = %d, want ScopeSingleLevel", observedScope)
	}
	if len(ous) != 1 || ous[0].DN != e1.DN {
		t.Fatalf("ous = %v", ous)
	}
}
