// Copyright 2020-2026 NGR Softlab
package ldapper

import (
	"errors"
	"strings"
	"testing"

	"github.com/go-ldap/ldap/v3"

	"github.com/NGRsoftlab/ldapper/types"
)

// ---------- GetUser / getUserLocked ----------

// TestGetUser covers the single-user lookup. Focus:
//   - input validation is delegated to searchSingleEntryLocked,
//   - the adapter's SearchUserFilterTemplate is used with a properly
//     escaped username,
//   - the result attributes come from the adapter's UserAttrs(),
//   - DN and attribute values are faithfully transferred into types.LDAPUser.
func TestGetUser(t *testing.T) {
	const (
		userTemplate = "(&(objectClass=user)(uid=%s))"
		baseDN       = "dc=example,dc=com"
	)

	userEntry := newLDAPEntry(
		"cn=Alice,ou=Users,dc=example,dc=com",
		map[string][]string{
			"uid":  {"alice"},
			"cn":   {"Alice"},
			"mail": {"alice@example.com", "a@example.org"},
		},
	)

	t.Run("nil connection", func(t *testing.T) {
		l := &LDAPper{catalogAdapter: &fakeAdapter{userFilterTemplate: userTemplate}}
		_, err := l.GetUser("alice", baseDN)
		if !errors.Is(err, ErrClosed) {
			t.Fatalf("errors.Is(%v, ErrClosed) = false", err)
		}
	})

	t.Run("empty username", func(t *testing.T) {
		cm := newCaptureMock(t)
		l := newLDAPperWithCapture(cm)
		l.catalogAdapter = &fakeAdapter{userFilterTemplate: userTemplate}
		_, err := l.GetUser("", baseDN)
		if !errors.Is(err, ErrInvalidArgument) {
			t.Fatalf("errors.Is(%v, ErrInvalidArgument) = false", err)
		}
		if len(cm.calls) != 0 {
			t.Fatalf("no search expected, got %d", len(cm.calls))
		}
	})

	t.Run("user not found", func(t *testing.T) {
		cm := newCaptureMock(t, pagedPage{})
		l := newLDAPperWithCapture(cm)
		l.catalogAdapter = &fakeAdapter{
			userFilterTemplate: userTemplate,
			userAttrs:          []string{"uid", "cn"},
		}
		_, err := l.GetUser("ghost", baseDN)
		if !errors.Is(err, ErrNotFound) {
			t.Fatalf("errors.Is(%v, ErrNotFound) = false", err)
		}
	})

	t.Run("ambiguous result", func(t *testing.T) {
		e1 := newLDAPEntry("cn=A1,dc=x", map[string][]string{"uid": {"alice"}})
		e2 := newLDAPEntry("cn=A2,dc=x", map[string][]string{"uid": {"alice"}})
		cm := newCaptureMock(t, pagedPage{entries: []*ldap.Entry{e1, e2}})
		l := newLDAPperWithCapture(cm)
		l.catalogAdapter = &fakeAdapter{userFilterTemplate: userTemplate, userAttrs: []string{"uid"}}
		_, err := l.GetUser("alice", baseDN)
		if !errors.Is(err, ErrAmbiguousResult) {
			t.Fatalf("errors.Is(%v, ErrAmbiguousResult) = false", err)
		}
	})

	t.Run("success: filter, attributes, mapping", func(t *testing.T) {
		cm := newCaptureMock(t, pagedPage{entries: []*ldap.Entry{userEntry}})
		l := newLDAPperWithCapture(cm)
		l.catalogAdapter = &fakeAdapter{
			userFilterTemplate: userTemplate,
			userAttrs:          []string{"uid", "cn", "mail"},
		}

		user, err := l.GetUser("alice", baseDN)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if user.DN != userEntry.DN {
			t.Fatalf("DN = %q, want %q", user.DN, userEntry.DN)
		}
		if user.GetAttributeValue("uid") != "alice" {
			t.Fatalf("uid = %q", user.GetAttributeValue("uid"))
		}
		if user.GetAttributeValue("cn") != "Alice" {
			t.Fatalf("cn = %q", user.GetAttributeValue("cn"))
		}
		if got := user.Attributes["mail"]; len(got) != 2 || got[1] != "a@example.org" {
			t.Fatalf("mail values not preserved: %v", got)
		}

		// Wire-level assertions.
		if len(cm.calls) != 1 {
			t.Fatalf("got %d calls, want 1", len(cm.calls))
		}
		call := cm.calls[0]
		if call.baseDN != baseDN {
			t.Fatalf("BaseDN = %q", call.baseDN)
		}
		if !strings.Contains(call.filter, "uid=alice") {
			t.Fatalf("filter missing username: %q", call.filter)
		}
		if call.sizeLimit != 2 {
			t.Fatalf("size limit = %d, want 2 (ambiguity probe)", call.sizeLimit)
		}
		// The adapter's attribute list must be forwarded verbatim.
		if len(call.attributes) != 3 || call.attributes[0] != "uid" {
			t.Fatalf("attributes = %v", call.attributes)
		}
	})

	t.Run("username is filter-escaped", func(t *testing.T) {
		cm := newCaptureMock(t, pagedPage{})
		l := newLDAPperWithCapture(cm)
		l.catalogAdapter = &fakeAdapter{userFilterTemplate: userTemplate, userAttrs: []string{"uid"}}

		_, _ = l.GetUser("a(b*c)", baseDN)
		if len(cm.calls) != 1 {
			t.Fatalf("expected one call, got %d", len(cm.calls))
		}
		if !strings.Contains(cm.calls[0].filter, `a\28b\2ac\29`) {
			t.Fatalf("filter not escaped: %q", cm.calls[0].filter)
		}
	})

	t.Run("search error classified", func(t *testing.T) {
		raw := &ldap.Error{ResultCode: ldap.LDAPResultUnavailable, Err: errors.New("down")}
		cm := newCaptureMock(t, pagedPage{err: raw})
		l := newLDAPperWithCapture(cm)
		l.catalogAdapter = &fakeAdapter{userFilterTemplate: userTemplate}
		_, err := l.GetUser("alice", baseDN)
		if !errors.Is(err, ErrUnavailable) {
			t.Fatalf("errors.Is(%v, ErrUnavailable) = false", err)
		}
	})
}

// ---------- GetUserGroups / getUserGroupsLocked ----------

// TestGetUserGroups covers the two-step user → groups lookup. Focus:
//   - missing user is reported as ErrNotFound (never as ErrInvalidCredentials
//     — that masquerade lives only in CheckUserCredentials),
//   - the second request uses the adapter's group template populated with
//     the user's DN and uid via SearchUserGroupsFilterTemplateArgs,
//   - only the "1.1" (no attributes) attribute list is requested for the
//     groups search to avoid over-fetching,
//   - the returned slice contains group DNs in server order.
func TestGetUserGroups(t *testing.T) {
	const baseDN = "dc=example,dc=com"

	userEntry := newLDAPEntry(
		"cn=Alice,ou=Users,dc=example,dc=com",
		map[string][]string{"uid": {"alice"}, "cn": {"Alice"}},
	)
	group1 := newLDAPEntry("cn=admins,ou=Groups,dc=example,dc=com", nil)
	group2 := newLDAPEntry("cn=staff,ou=Groups,dc=example,dc=com", nil)

	// adapterForGroups builds a fake adapter whose groups search is a two-arg
	// template matching the ALDPRO/OpenLDAP pattern.
	adapterForGroups := func() *fakeAdapter {
		return &fakeAdapter{
			userFilterTemplate: "(&(objectClass=user)(uid=%s))",
			userAttrs:          []string{"uid", "cn"},
			userGroupsTemplate: "(|(member=%s)(memberUid=%s))",
			userGroupsArgs: func(u types.LDAPUser) []any {
				return []any{u.DN, u.GetAttributeValue("uid")}
			},
		}
	}

	t.Run("nil connection", func(t *testing.T) {
		l := &LDAPper{catalogAdapter: adapterForGroups()}
		_, err := l.GetUserGroups("alice", baseDN)
		if !errors.Is(err, ErrClosed) {
			t.Fatalf("errors.Is(%v, ErrClosed) = false", err)
		}
	})

	t.Run("user not found propagates as ErrNotFound", func(t *testing.T) {
		cm := newCaptureMock(t, pagedPage{}) // empty user lookup
		l := newLDAPperWithCapture(cm)
		l.catalogAdapter = adapterForGroups()

		_, err := l.GetUserGroups("ghost", baseDN)
		if !errors.Is(err, ErrNotFound) {
			t.Fatalf("errors.Is(%v, ErrNotFound) = false", err)
		}
		if errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("ErrNotFound must not be masked as ErrInvalidCredentials here")
		}
		// Groups search must never have been issued.
		if len(cm.calls) != 1 {
			t.Fatalf("expected only the user lookup call, got %d", len(cm.calls))
		}
	})

	t.Run("success returns group DNs in order", func(t *testing.T) {
		cm := newCaptureMock(t,
			pagedPage{entries: []*ldap.Entry{userEntry}},                            // user lookup
			pagedPage{entries: []*ldap.Entry{group1, group2}, nextCookie: []byte{}}, // groups lookup
		)
		l := newLDAPperWithCapture(cm)
		l.catalogAdapter = adapterForGroups()

		groups, err := l.GetUserGroups("alice", baseDN)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(groups) != 2 {
			t.Fatalf("got %d groups, want 2", len(groups))
		}
		if groups[0] != group1.DN || groups[1] != group2.DN {
			t.Fatalf("group DNs = %v", groups)
		}

		if len(cm.calls) != 2 {
			t.Fatalf("got %d calls, want 2", len(cm.calls))
		}
		groupsCall := cm.calls[1]

		// "1.1" optimisation: only the DN is requested.
		if len(groupsCall.attributes) != 1 || groupsCall.attributes[0] != "1.1" {
			t.Fatalf("attributes = %v, want [\"1.1\"]", groupsCall.attributes)
		}
		// Template was populated with both DN and uid, escaped.
		if !strings.Contains(groupsCall.filter, "cn=Alice,ou=Users,dc=example,dc=com") {
			t.Fatalf("filter missing user DN: %q", groupsCall.filter)
		}
		if !strings.Contains(groupsCall.filter, "alice") {
			t.Fatalf("filter missing uid: %q", groupsCall.filter)
		}
	})

	t.Run("groups search error classified", func(t *testing.T) {
		raw := &ldap.Error{ResultCode: ldap.LDAPResultBusy, Err: errors.New("busy")}
		cm := newCaptureMock(t,
			pagedPage{entries: []*ldap.Entry{userEntry}},
			pagedPage{err: raw},
		)
		l := newLDAPperWithCapture(cm)
		l.catalogAdapter = adapterForGroups()

		_, err := l.GetUserGroups("alice", baseDN)
		if !errors.Is(err, ErrUnavailable) {
			t.Fatalf("errors.Is(%v, ErrUnavailable) = false", err)
		}
	})
}

// ---------- GetOUUsers / getOUUsersLocked ----------

// TestGetOUUsers covers the bulk user listing under a subtree. Focus:
//   - base DN is validated before any request is issued,
//   - the search uses the adapter's UserObjectFilter and UserAttrs,
//   - every returned entry is mapped into *types.LDAPUser with the same
//     attribute projection as GetUser.
func TestGetOUUsers(t *testing.T) {
	const ouDN = "ou=Users,dc=example,dc=com"

	e1 := newLDAPEntry("cn=A,ou=Users,dc=example,dc=com", map[string][]string{
		"uid": {"alice"}, "cn": {"Alice"},
	})
	e2 := newLDAPEntry("cn=B,ou=Users,dc=example,dc=com", map[string][]string{
		"uid": {"bob"}, "cn": {"Bob"},
	})

	adapter := func() *fakeAdapter {
		return &fakeAdapter{
			userObjFilter: "(objectClass=user)",
			userAttrs:     []string{"uid", "cn"},
		}
	}

	t.Run("nil connection", func(t *testing.T) {
		l := &LDAPper{catalogAdapter: adapter()}
		_, err := l.GetOUUsers(ouDN)
		if !errors.Is(err, ErrClosed) {
			t.Fatalf("errors.Is(%v, ErrClosed) = false", err)
		}
	})

	t.Run("empty ou DN rejected before any search", func(t *testing.T) {
		cm := newCaptureMock(t)
		l := newLDAPperWithCapture(cm)
		l.catalogAdapter = adapter()

		_, err := l.GetOUUsers("")
		if !errors.Is(err, ErrInvalidArgument) {
			t.Fatalf("errors.Is(%v, ErrInvalidArgument) = false", err)
		}
		if len(cm.calls) != 0 {
			t.Fatalf("no search should have been issued, got %d", len(cm.calls))
		}
	})

	t.Run("success: filter, attrs, projection", func(t *testing.T) {
		cm := newCaptureMock(t, pagedPage{
			entries:    []*ldap.Entry{e1, e2},
			nextCookie: []byte{},
		})
		l := newLDAPperWithCapture(cm)
		l.catalogAdapter = adapter()

		users, err := l.GetOUUsers(ouDN)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(users) != 2 {
			t.Fatalf("got %d users, want 2", len(users))
		}
		if users[0].DN != e1.DN || users[1].DN != e2.DN {
			t.Fatalf("user DNs = %q, %q", users[0].DN, users[1].DN)
		}
		if users[0].GetAttributeValue("uid") != "alice" || users[1].GetAttributeValue("uid") != "bob" {
			t.Fatalf("attributes not projected: %+v / %+v", users[0].Attributes, users[1].Attributes)
		}

		if len(cm.calls) != 1 {
			t.Fatalf("got %d calls, want 1", len(cm.calls))
		}
		if cm.calls[0].filter != "(objectClass=user)" {
			t.Fatalf("filter = %q", cm.calls[0].filter)
		}
		if len(cm.calls[0].attributes) != 2 || cm.calls[0].attributes[0] != "uid" {
			t.Fatalf("attributes = %v", cm.calls[0].attributes)
		}
	})

	t.Run("empty subtree returns empty slice", func(t *testing.T) {
		cm := newCaptureMock(t, pagedPage{nextCookie: []byte{}})
		l := newLDAPperWithCapture(cm)
		l.catalogAdapter = adapter()

		users, err := l.GetOUUsers(ouDN)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(users) != 0 {
			t.Fatalf("got %d users, want 0", len(users))
		}
	})

	t.Run("search error classified", func(t *testing.T) {
		raw := &ldap.Error{ResultCode: ldap.LDAPResultNoSuchObject, Err: errors.New("gone")}
		cm := newCaptureMock(t, pagedPage{err: raw})
		l := newLDAPperWithCapture(cm)
		l.catalogAdapter = adapter()

		_, err := l.GetOUUsers(ouDN)
		if !errors.Is(err, ErrNotFound) {
			t.Fatalf("errors.Is(%v, ErrNotFound) = false", err)
		}
	})
}
