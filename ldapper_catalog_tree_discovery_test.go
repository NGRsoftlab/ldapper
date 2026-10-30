// Copyright 2020-2026 NGR Softlab
package ldapper

import (
	"errors"
	"strings"
	"testing"

	"github.com/go-ldap/ldap/v3"

	"github.com/NGRsoftlab/ldapper/constants"
	"github.com/NGRsoftlab/ldapper/mocks"
	"github.com/NGRsoftlab/ldapper/types"
)

// ---------- parentDNOf ----------

func TestParentDNOf(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"top_level", "dc=x", ""},
		{"two_level", "ou=users,dc=x", "dc=x"},
		{"deep", "ou=a,ou=b,dc=x", "ou=b,dc=x"},
		{"escaped_comma", `cn=Doe\, John,ou=users,dc=x`, "ou=users,dc=x"},
		{"empty", "", ""},
		{"invalid", "ou=x,,dc=y", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := parentDNOf(tc.in); got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}

// ---------- trimDepth ----------

func TestTrimDepth(t *testing.T) {
	// Fixture (3 levels):
	//   A -> A1 -> A11
	//     -> A2
	//   B
	newTree := func() []*types.OUInfo {
		return []*types.OUInfo{
			{DN: "A", Children: []*types.OUInfo{
				{DN: "A1", Children: []*types.OUInfo{
					{DN: "A11", Children: []*types.OUInfo{}},
				}},
				{DN: "A2", Children: []*types.OUInfo{}},
			}},
			{DN: "B", Children: []*types.OUInfo{}},
		}
	}

	t.Run("depth_1_roots_only", func(t *testing.T) {
		orig := newTree()
		got := trimDepth(orig, 1)
		if len(got) != 2 || got[0].DN != "A" || got[1].DN != "B" {
			t.Fatalf("unexpected roots: %+v", got)
		}
		for _, n := range got {
			if len(n.Children) != 0 {
				t.Errorf("expected no children at depth 1, got: %+v", n.Children)
			}
		}
		// trimDepth must return copies, not mutate the input.
		if len(orig[0].Children) != 2 {
			t.Error("trimDepth must not mutate the original tree")
		}
	})

	t.Run("depth_2", func(t *testing.T) {
		got := trimDepth(newTree(), 2)
		if len(got[0].Children) != 2 {
			t.Fatalf("expected 2 children of A, got %d", len(got[0].Children))
		}
		for _, c := range got[0].Children {
			if len(c.Children) != 0 {
				t.Errorf("expected no grandchildren at depth 2, got: %+v", c.Children)
			}
		}
	})

	t.Run("depth_above_height_keeps_full_tree", func(t *testing.T) {
		got := trimDepth(newTree(), 10)
		if len(got[0].Children[0].Children) != 1 || got[0].Children[0].Children[0].DN != "A11" {
			t.Fatalf("expected A11 preserved, got: %+v", got[0].Children[0].Children)
		}
	})

	t.Run("empty_input", func(t *testing.T) {
		got := trimDepth(nil, 5)
		if got == nil || len(got) != 0 {
			t.Fatalf("expected non-nil empty slice, got: %+v", got)
		}
	})
}

// ---------- GetCatalogTree ----------

func TestGetCatalogTree_SearchError(t *testing.T) {
	conn := newTestConnection(&testCatalogAdapter{}, &mocks.MockLDAPConn{
		SearchFunc: func(*ldap.SearchRequest) (*ldap.SearchResult, error) {
			return nil, errors.New("boom")
		},
	})
	tree, err := conn.GetCatalogTree("dc=x", 0)
	if err == nil || !strings.Contains(err.Error(), "unsuccessful ou search") {
		t.Fatalf("unexpected error: %v", err)
	}
	if tree.Tree == nil || len(tree.Tree) != 0 {
		t.Errorf("tree must be non-nil and empty on error, got: %+v", tree.Tree)
	}
}

func TestGetCatalogTree_InvalidBaseDN(t *testing.T) {
	conn := newTestConnection(&testCatalogAdapter{}, mockOUs())
	_, err := conn.GetCatalogTree("ou=x,,dc=y", 0)
	if err == nil || !strings.Contains(err.Error(), "invalid base DN") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestGetCatalogTree_EmptyResult(t *testing.T) {
	conn := newTestConnection(&testCatalogAdapter{}, mockOUs())
	tree, err := conn.GetCatalogTree("dc=x", 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tree.Tree == nil || len(tree.Tree) != 0 {
		t.Fatalf("expected non-nil empty tree, got: %+v", tree.Tree)
	}
}

// TestGetCatalogTree_DropsBaseDN: the base DN itself must be filtered out.
func TestGetCatalogTree_DropsBaseDN(t *testing.T) {
	conn := newTestConnection(&testCatalogAdapter{}, mockOUs(
		newLDAPEntry("dc=x", nil),
		newLDAPEntry("ou=a,dc=x", nil),
	))
	tree, err := conn.GetCatalogTree("dc=x", 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(tree.Tree) != 1 || tree.Tree[0].DN != "ou=a,dc=x" {
		t.Fatalf("base DN must be dropped, got: %+v", tree.Tree)
	}
}

// TestGetCatalogTree_FiltersForeignDNs: entries outside baseDn must be dropped
// even if the server returns them.
func TestGetCatalogTree_FiltersForeignDNs(t *testing.T) {
	conn := newTestConnection(&testCatalogAdapter{}, mockOUs(
		newLDAPEntry("ou=a,dc=x", nil), // kept
		newLDAPEntry("ou=b,dc=y", nil), // foreign: drop
		newLDAPEntry("ou=c,dc=x", nil), // kept
	))
	tree, err := conn.GetCatalogTree("dc=x", 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(tree.Tree) != 2 {
		t.Fatalf("expected 2 roots, got %d: %+v", len(tree.Tree), tree.Tree)
	}
	for _, r := range tree.Tree {
		if !strings.HasSuffix(r.DN, ",dc=x") {
			t.Errorf("foreign DN leaked: %s", r.DN)
		}
	}
}

// TestGetCatalogTree_SkipsMalformedDN: a malformed entry DN must not abort
// the whole call, only that entry is skipped.
func TestGetCatalogTree_SkipsMalformedDN(t *testing.T) {
	conn := newTestConnection(&testCatalogAdapter{}, mockOUs(
		newLDAPEntry("ou=x,,dc=y", nil), // malformed: skip
		newLDAPEntry("ou=ok,dc=x", nil), // keep
	))
	tree, err := conn.GetCatalogTree("dc=x", 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(tree.Tree) != 1 || tree.Tree[0].DN != "ou=ok,dc=x" {
		t.Fatalf("unexpected roots: %+v", tree.Tree)
	}
}

// TestGetCatalogTree_BuildsHierarchy verifies parent-child links are built
// from DN structure regardless of the order entries arrive in.
func TestGetCatalogTree_BuildsHierarchy(t *testing.T) {
	conn := newTestConnection(&testCatalogAdapter{}, mockOUs(
		newLDAPEntry("ou=grand,ou=a1,ou=a,dc=x", nil), // appears before parent
		newLDAPEntry("ou=a1,ou=a,dc=x", nil),
		newLDAPEntry("ou=a,dc=x", nil),
		newLDAPEntry("ou=a2,ou=a,dc=x", nil),
		newLDAPEntry("ou=b,dc=x", nil),
	))
	tree, err := conn.GetCatalogTree("dc=x", 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(tree.Tree) != 2 {
		t.Fatalf("expected 2 roots, got %d: %+v", len(tree.Tree), tree.Tree)
	}

	// Index all nodes by DN for assertions independent of child order.
	idx := map[string]*types.OUInfo{}
	var walk func(nodes []*types.OUInfo)
	walk = func(nodes []*types.OUInfo) {
		for _, n := range nodes {
			idx[n.DN] = n
			walk(n.Children)
		}
	}
	walk(tree.Tree)

	a := idx["ou=a,dc=x"]
	if a == nil || len(a.Children) != 2 {
		t.Fatalf("unexpected A: %+v", a)
	}
	a1 := idx["ou=a1,ou=a,dc=x"]
	if a1 == nil || len(a1.Children) != 1 || a1.Children[0].DN != "ou=grand,ou=a1,ou=a,dc=x" {
		t.Fatalf("unexpected A1: %+v", a1)
	}
	if b := idx["ou=b,dc=x"]; b == nil || len(b.Children) != 0 {
		t.Errorf("unexpected B: %+v", b)
	}
}

func TestGetCatalogTree_MaxDepth(t *testing.T) {
	entries := []*ldap.Entry{
		newLDAPEntry("ou=a,dc=x", nil),
		newLDAPEntry("ou=a1,ou=a,dc=x", nil),
		newLDAPEntry("ou=grand,ou=a1,ou=a,dc=x", nil),
	}

	t.Run("depth_1", func(t *testing.T) {
		tree, err := newTestConnection(&testCatalogAdapter{}, mockOUs(entries...)).
			GetCatalogTree("dc=x", 1)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(tree.Tree) != 1 || len(tree.Tree[0].Children) != 0 {
			t.Fatalf("expected roots only, got: %+v", tree.Tree)
		}
	})

	t.Run("depth_2", func(t *testing.T) {
		tree, err := newTestConnection(&testCatalogAdapter{}, mockOUs(entries...)).
			GetCatalogTree("dc=x", 2)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(tree.Tree[0].Children) != 1 || len(tree.Tree[0].Children[0].Children) != 0 {
			t.Fatalf("expected one level of children, got: %+v", tree.Tree)
		}
	})

	t.Run("depth_0_no_trim", func(t *testing.T) {
		tree, err := newTestConnection(&testCatalogAdapter{}, mockOUs(entries...)).
			GetCatalogTree("dc=x", 0)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(tree.Tree[0].Children[0].Children) != 1 {
			t.Fatalf("expected full tree, got: %+v", tree.Tree)
		}
	})
}

// TestGetCatalogTree_Paging: server echoes a paging control with a non-empty
// cookie, forcing a second request; both pages are aggregated into one tree.
func TestGetCatalogTree_Paging(t *testing.T) {
	searchCalls := 0
	conn := newTestConnection(&testCatalogAdapter{}, &mocks.MockLDAPConn{
		SearchFunc: func(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
			searchCalls++
			var cookie []byte
			if len(req.Controls) > 0 {
				if pc, ok := req.Controls[0].(*ldap.ControlPaging); ok {
					cookie = pc.Cookie
				}
			}
			next := ldap.NewControlPaging(constants.DefaultCatalogTreePageSize)
			switch string(cookie) {
			case "":
				next.SetCookie([]byte("page2"))
				return &ldap.SearchResult{
					Entries:  []*ldap.Entry{newLDAPEntry("ou=a,dc=x", nil)},
					Controls: []ldap.Control{next},
				}, nil
			case "page2":
				// Empty cookie = last page.
				return &ldap.SearchResult{
					Entries:  []*ldap.Entry{newLDAPEntry("ou=b,dc=x", nil)},
					Controls: []ldap.Control{next},
				}, nil
			}
			t.Fatalf("unexpected cookie: %q", cookie)
			return nil, nil
		},
	})

	tree, err := conn.GetCatalogTree("dc=x", 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if searchCalls != 2 {
		t.Fatalf("expected 2 searches, got %d", searchCalls)
	}
	if len(tree.Tree) != 2 {
		t.Fatalf("expected 2 roots, got %d: %+v", len(tree.Tree), tree.Tree)
	}
}

// TestGetCatalogTree_ServerIgnoresPaging: if the server does not echo a
// paging control, the loop must stop after the first request.
func TestGetCatalogTree_ServerIgnoresPaging(t *testing.T) {
	searchCalls := 0
	conn := newTestConnection(&testCatalogAdapter{}, &mocks.MockLDAPConn{
		SearchFunc: func(*ldap.SearchRequest) (*ldap.SearchResult, error) {
			searchCalls++
			return &ldap.SearchResult{
				Entries: []*ldap.Entry{newLDAPEntry("ou=a,dc=x", nil)},
			}, nil
		},
	})
	if _, err := conn.GetCatalogTree("dc=x", 0); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if searchCalls != 1 {
		t.Errorf("expected 1 search when server ignores paging, got %d", searchCalls)
	}
}

// TestGetCatalogTree_RequestShape verifies the first search request carries
// the expected base, scope, filter, attributes, paging control and limits.
func TestGetCatalogTree_RequestShape(t *testing.T) {
	var captured *ldap.SearchRequest
	adapter := &testCatalogAdapter{
		ouObjectFilter: "(objectClass=organizationalUnit)",
		ouAttrs:        []string{"ou"},
	}
	conn := newTestConnection(adapter, &mocks.MockLDAPConn{
		SearchFunc: func(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
			if captured == nil {
				captured = req
			}
			return &ldap.SearchResult{}, nil
		},
	})
	conn.SetSearchLimits(50, 15)

	if _, err := conn.GetCatalogTree("dc=x", 0); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if captured == nil {
		t.Fatal("search request not captured")
	}
	if captured.BaseDN != "dc=x" {
		t.Errorf("BaseDN: %s", captured.BaseDN)
	}
	if captured.Scope != ldap.ScopeWholeSubtree {
		t.Errorf("Scope: %d", captured.Scope)
	}
	if captured.Filter != "(objectClass=organizationalUnit)" {
		t.Errorf("Filter: %s", captured.Filter)
	}
	if len(captured.Attributes) != 1 || captured.Attributes[0] != "ou" {
		t.Errorf("Attributes: %v", captured.Attributes)
	}
	if captured.SizeLimit != 50 || captured.TimeLimit != 15 {
		t.Errorf("limits: size=%d time=%d", captured.SizeLimit, captured.TimeLimit)
	}
	if len(captured.Controls) != 1 {
		t.Fatalf("expected 1 paging control, got %d", len(captured.Controls))
	}
	pc, ok := captured.Controls[0].(*ldap.ControlPaging)
	if !ok {
		t.Fatalf("expected *ControlPaging, got %T", captured.Controls[0])
	}
	if len(pc.Cookie) != 0 {
		t.Errorf("first request must start with empty cookie, got %q", pc.Cookie)
	}
	if pc.PagingSize != constants.DefaultCatalogTreePageSize {
		t.Errorf("PagingSize: %d", pc.PagingSize)
	}
}

// ---------- GetRootOUs ----------

func TestGetRootOUs(t *testing.T) {
	t.Run("search_error", func(t *testing.T) {
		conn := newTestConnection(&testCatalogAdapter{
			ouObjectFilter: "(objectClass=organizationalUnit)",
		}, &mocks.MockLDAPConn{
			SearchFunc: func(*ldap.SearchRequest) (*ldap.SearchResult, error) {
				return nil, errors.New("boom")
			},
		})
		if _, err := conn.GetRootOUs("dc=x"); err == nil ||
			!strings.Contains(err.Error(), "unsuccessful ou search") {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("success", func(t *testing.T) {
		var captured *ldap.SearchRequest
		conn := newTestConnection(&testCatalogAdapter{
			ouObjectFilter: "(objectClass=organizationalUnit)",
			ouAttrs:        []string{"ou"},
		}, &mocks.MockLDAPConn{
			SearchFunc: func(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
				captured = req
				return &ldap.SearchResult{Entries: []*ldap.Entry{
					newLDAPEntry("ou=a,dc=x", nil),
					newLDAPEntry("ou=b,dc=x", nil),
				}}, nil
			},
		})
		ous, err := conn.GetRootOUs("dc=x")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(ous) != 2 || ous[0].DN != "ou=a,dc=x" || ous[1].DN != "ou=b,dc=x" {
			t.Fatalf("unexpected OUs: %+v", ous)
		}
		if captured.Scope != ldap.ScopeSingleLevel {
			t.Errorf("expected ScopeSingleLevel, got %d", captured.Scope)
		}
		if captured.BaseDN != "dc=x" {
			t.Errorf("unexpected BaseDN: %s", captured.BaseDN)
		}
	})
}

// ---------- GetSubOUs ----------

func TestGetSubOUs(t *testing.T) {
	t.Run("search_error", func(t *testing.T) {
		conn := newTestConnection(&testCatalogAdapter{
			ouObjectFilter: "(objectClass=organizationalUnit)",
		}, &mocks.MockLDAPConn{
			SearchFunc: func(*ldap.SearchRequest) (*ldap.SearchResult, error) {
				return nil, errors.New("boom")
			},
		})
		if _, err := conn.GetSubOUs("ou=p,dc=x", ldap.ScopeSingleLevel); err == nil ||
			!strings.Contains(err.Error(), "unsuccessful sub ou search") {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("filters_non_children", func(t *testing.T) {
		conn := newTestConnection(&testCatalogAdapter{
			ouObjectFilter: "(objectClass=organizationalUnit)",
		}, &mocks.MockLDAPConn{
			SearchFunc: func(*ldap.SearchRequest) (*ldap.SearchResult, error) {
				return &ldap.SearchResult{Entries: []*ldap.Entry{
					newLDAPEntry("ou=child,ou=parent,dc=x", nil), // kept
					newLDAPEntry("ou=other,dc=y", nil),           // unrelated
					newLDAPEntry("ou=parent,dc=x", nil),          // group itself
				}}, nil
			},
		})
		res, err := conn.GetSubOUs("ou=parent,dc=x", ldap.ScopeSingleLevel)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(res) != 1 || res[0].DN != "ou=child,ou=parent,dc=x" {
			t.Fatalf("unexpected result: %+v", res)
		}
		if res[0].Children == nil {
			t.Error("Children must be initialized to a non-nil slice")
		}
	})
}
