// Copyright 2020-2026 NGR Softlab
package ldapper

import (
	"errors"
	"strings"
	"testing"

	"github.com/go-ldap/ldap/v3"

	"github.com/NGRsoftlab/ldapper/mocks"
	"github.com/NGRsoftlab/ldapper/types"
)

// ---------- CustomSearch ----------

func TestCustomSearch_NilConnection(t *testing.T) {
	_, err := (&LDAPper{}).CustomSearch(&ldap.SearchRequest{})
	if err == nil || !strings.Contains(err.Error(), "connection not initialized") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCustomSearch_DelegatesRequest(t *testing.T) {
	var captured *ldap.SearchRequest
	conn := newTestConnection(&testCatalogAdapter{}, &mocks.MockLDAPConn{
		SearchFunc: func(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
			captured = req
			return &ldap.SearchResult{}, nil
		},
	})

	req := &ldap.SearchRequest{BaseDN: "dc=x"}
	if _, err := conn.CustomSearch(req); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if captured != req {
		t.Error("the exact request must be forwarded to the underlying connection")
	}
}

// ---------- GetUser ----------

func TestGetUser_NilConnection(t *testing.T) {
	_, err := (&LDAPper{}).GetUser("u", "dc=x")
	if err == nil || !strings.Contains(err.Error(), "connection not initialized") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestGetUser_SearchError(t *testing.T) {
	conn := newTestConnection(
		&testCatalogAdapter{searchUserFilterTemplate: "(uid=%s)", userAttrs: []string{"cn"}},
		&mocks.MockLDAPConn{SearchFunc: func(*ldap.SearchRequest) (*ldap.SearchResult, error) {
			return nil, errors.New("boom")
		}},
	)
	_, err := conn.GetUser("u", "dc=x")
	if err == nil || !strings.Contains(err.Error(), "unsuccessful user search") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestGetUser_NoEntries(t *testing.T) {
	conn := newTestConnection(
		&testCatalogAdapter{searchUserFilterTemplate: "(uid=%s)"},
		&mocks.MockLDAPConn{SearchFunc: func(*ldap.SearchRequest) (*ldap.SearchResult, error) {
			return &ldap.SearchResult{}, nil
		}},
	)
	_, err := conn.GetUser("u", "dc=x")
	if err == nil || !strings.Contains(err.Error(), "user does not exist") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestGetUser_TooManyEntries(t *testing.T) {
	conn := newTestConnection(
		&testCatalogAdapter{searchUserFilterTemplate: "(uid=%s)"},
		&mocks.MockLDAPConn{SearchFunc: func(*ldap.SearchRequest) (*ldap.SearchResult, error) {
			return &ldap.SearchResult{Entries: []*ldap.Entry{
				newLDAPEntry("cn=u1,dc=x", nil),
				newLDAPEntry("cn=u2,dc=x", nil),
			}}, nil
		}},
	)
	_, err := conn.GetUser("u", "dc=x")
	if err == nil || !strings.Contains(err.Error(), "too many entries returned") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestGetUser_Success(t *testing.T) {
	var captured *ldap.SearchRequest
	conn := newTestConnection(
		&testCatalogAdapter{searchUserFilterTemplate: "(uid=%s)", userAttrs: []string{"cn", "mail"}},
		&mocks.MockLDAPConn{SearchFunc: func(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
			captured = req
			return &ldap.SearchResult{Entries: []*ldap.Entry{
				newLDAPEntry("cn=John,dc=x", map[string][]string{
					"cn":   {"John"},
					"mail": {"john@example.com"},
				}),
			}}, nil
		}},
	)
	conn.SetSearchLimits(50, 15)

	user, err := conn.GetUser("john", "dc=x")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if user.DN != "cn=John,dc=x" {
		t.Errorf("unexpected DN: %s", user.DN)
	}
	if got := user.Attributes["mail"]; len(got) != 1 || got[0] != "john@example.com" {
		t.Errorf("unexpected mail: %v", got)
	}
	// Contract: GetUser builds its request with connection-level limits.
	if captured == nil || captured.SizeLimit != 50 || captured.TimeLimit != 15 {
		t.Errorf("limits not applied: %+v", captured)
	}
	if captured.Scope != ldap.ScopeWholeSubtree {
		t.Errorf("expected ScopeWholeSubtree, got %d", captured.Scope)
	}
	if captured.Filter != "(uid=john)" {
		t.Errorf("unexpected filter: %s", captured.Filter)
	}
}

// ---------- GetUserGroups ----------

func TestGetUserGroups_NilConnection(t *testing.T) {
	_, err := (&LDAPper{}).GetUserGroups("u", "dc=x")
	if err == nil || !strings.Contains(err.Error(), "connection not initialized") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestGetUserGroups_PropagatesGetUserError(t *testing.T) {
	conn := newTestConnection(
		&testCatalogAdapter{searchUserFilterTemplate: "(uid=%s)"},
		&mocks.MockLDAPConn{SearchFunc: func(*ldap.SearchRequest) (*ldap.SearchResult, error) {
			return &ldap.SearchResult{}, nil
		}},
	)
	_, err := conn.GetUserGroups("u", "dc=x")
	if err == nil || !strings.Contains(err.Error(), "user does not exist") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestGetUserGroups_SearchError(t *testing.T) {
	conn := newTestConnection(
		&testCatalogAdapter{
			searchUserFilterTemplate:       "(uid=%s)",
			userAttrs:                      []string{"cn"},
			searchUserGroupsFilterTemplate: "(member=%s)",
			searchUserGroupsFilterArgsFunc: func(u types.LDAPUser) []any { return []any{u.DN} },
		},
		&mocks.MockLDAPConn{SearchFunc: func(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
			if strings.HasPrefix(req.Filter, "(uid=") {
				return &ldap.SearchResult{Entries: []*ldap.Entry{
					newLDAPEntry("cn=user,dc=x", nil),
				}}, nil
			}
			return nil, errors.New("groups search fail")
		}},
	)
	_, err := conn.GetUserGroups("user", "dc=x")
	if err == nil || !strings.Contains(err.Error(), "unsuccessful user groups search") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestGetUserGroups_Success(t *testing.T) {
	conn := newTestConnection(
		&testCatalogAdapter{
			searchUserFilterTemplate:       "(uid=%s)",
			userAttrs:                      []string{"cn"},
			searchUserGroupsFilterTemplate: "(member=%s)",
			searchUserGroupsFilterArgsFunc: func(u types.LDAPUser) []any { return []any{u.DN} },
		},
		&mocks.MockLDAPConn{SearchFunc: func(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
			switch {
			case strings.HasPrefix(req.Filter, "(uid="):
				return &ldap.SearchResult{Entries: []*ldap.Entry{
					newLDAPEntry("cn=user,dc=x", nil),
				}}, nil
			case req.Filter == "(member=cn=user,dc=x)":
				return &ldap.SearchResult{Entries: []*ldap.Entry{
					newLDAPEntry("cn=admins,dc=x", map[string][]string{"cn": {"admins"}}),
					newLDAPEntry("cn=users,dc=x", map[string][]string{"cn": {"users"}}),
				}}, nil
			}
			t.Errorf("unexpected filter: %s", req.Filter)
			return &ldap.SearchResult{}, nil
		}},
	)

	groups, err := conn.GetUserGroups("user", "dc=x")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(groups) != 2 || groups[0] != "admins" || groups[1] != "users" {
		t.Fatalf("unexpected groups: %v", groups)
	}
}

// ---------- GetOUUsers ----------

func TestGetOUUsers_NilConnection(t *testing.T) {
	_, err := (&LDAPper{}).GetOUUsers("ou=users,dc=x")
	if err == nil || !strings.Contains(err.Error(), "connection not initialized") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestGetOUUsers_SearchError(t *testing.T) {
	conn := newTestConnection(
		&testCatalogAdapter{userObjectFilter: "(objectClass=person)", userAttrs: []string{"cn"}},
		&mocks.MockLDAPConn{SearchFunc: func(*ldap.SearchRequest) (*ldap.SearchResult, error) {
			return nil, errors.New("boom")
		}},
	)
	_, err := conn.GetOUUsers("ou=users,dc=x")
	if err == nil || !strings.Contains(err.Error(), "unsuccessful ou users search") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestGetOUUsers_Success(t *testing.T) {
	var captured *ldap.SearchRequest
	conn := newTestConnection(
		&testCatalogAdapter{userObjectFilter: "(objectClass=person)", userAttrs: []string{"cn"}},
		&mocks.MockLDAPConn{SearchFunc: func(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
			captured = req
			return &ldap.SearchResult{Entries: []*ldap.Entry{
				newLDAPEntry("cn=u1,ou=users,dc=x", map[string][]string{"cn": {"u1"}}),
				newLDAPEntry("cn=u2,ou=users,dc=x", map[string][]string{"cn": {"u2"}}),
			}}, nil
		}},
	)

	users, err := conn.GetOUUsers("ou=users,dc=x")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(users) != 2 {
		t.Fatalf("expected 2 users, got %d", len(users))
	}
	if users[0].DN != "cn=u1,ou=users,dc=x" || users[1].DN != "cn=u2,ou=users,dc=x" {
		t.Errorf("unexpected DNs: %s, %s", users[0].DN, users[1].DN)
	}
	if got := users[0].Attributes["cn"]; len(got) != 1 || got[0] != "u1" {
		t.Errorf("unexpected first user cn: %v", got)
	}
	// Contract: request shape for OU users search.
	if captured == nil || captured.BaseDN != "ou=users,dc=x" || captured.Scope != ldap.ScopeWholeSubtree {
		t.Errorf("unexpected request: %+v", captured)
	}
}
