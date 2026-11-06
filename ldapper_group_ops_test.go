// Copyright 2020-2026 NGR Softlab
package ldapper

import (
	"errors"
	"strings"
	"testing"

	"github.com/go-ldap/ldap/v3"
)

// TestGetGroup covers the single-group lookup. The heavy lifting is already
// tested via searchSingleEntryLocked; this test asserts the group-specific
// wiring: SearchGroupFilterTemplate, GroupAttrs and the *types.LDAPGroup
// projection.
func TestGetGroup(t *testing.T) {
	const (
		groupTemplate = "(|(cn=%s)(sAMAccountName=%s))" // awkward on purpose: single-arg template below
		simpleTpl     = "(&(objectClass=group)(cn=%s))"
		baseDN        = "dc=example,dc=com"
	)

	_ = groupTemplate // keep both names visible for readers

	groupEntry := newLDAPEntry(
		"cn=admins,ou=Groups,dc=example,dc=com",
		map[string][]string{
			"cn":     {"admins"},
			"member": {"cn=A,ou=Users,dc=example,dc=com", "cn=B,ou=Users,dc=example,dc=com"},
			"gidNum": {"1000"},
		},
	)

	t.Run("nil connection", func(t *testing.T) {
		l := &LDAPper{catalogAdapter: &fakeAdapter{groupFilterTemplate: simpleTpl}}
		_, err := l.GetGroup("admins", baseDN)
		if !errors.Is(err, ErrClosed) {
			t.Fatalf("errors.Is(%v, ErrClosed) = false", err)
		}
	})

	t.Run("empty cn", func(t *testing.T) {
		cm := newCaptureMock(t)
		l := newLDAPperWithCapture(cm)
		l.catalogAdapter = &fakeAdapter{groupFilterTemplate: simpleTpl}
		_, err := l.GetGroup("", baseDN)
		if !errors.Is(err, ErrInvalidArgument) {
			t.Fatalf("errors.Is(%v, ErrInvalidArgument) = false", err)
		}
	})

	t.Run("not found", func(t *testing.T) {
		cm := newCaptureMock(t, pagedPage{})
		l := newLDAPperWithCapture(cm)
		l.catalogAdapter = &fakeAdapter{
			groupFilterTemplate: simpleTpl,
			groupAttrs:          []string{"cn"},
		}
		_, err := l.GetGroup("ghost", baseDN)
		if !errors.Is(err, ErrNotFound) {
			t.Fatalf("errors.Is(%v, ErrNotFound) = false", err)
		}
	})

	t.Run("ambiguous", func(t *testing.T) {
		e1 := newLDAPEntry("cn=A1,dc=x", nil)
		e2 := newLDAPEntry("cn=A2,dc=x", nil)
		cm := newCaptureMock(t, pagedPage{entries: []*ldap.Entry{e1, e2}})
		l := newLDAPperWithCapture(cm)
		l.catalogAdapter = &fakeAdapter{
			groupFilterTemplate: simpleTpl,
			groupAttrs:          []string{"cn"},
		}
		_, err := l.GetGroup("dup", baseDN)
		if !errors.Is(err, ErrAmbiguousResult) {
			t.Fatalf("errors.Is(%v, ErrAmbiguousResult) = false", err)
		}
	})

	t.Run("success: filter, attributes, mapping", func(t *testing.T) {
		cm := newCaptureMock(t, pagedPage{entries: []*ldap.Entry{groupEntry}})
		l := newLDAPperWithCapture(cm)
		l.catalogAdapter = &fakeAdapter{
			groupFilterTemplate: simpleTpl,
			groupAttrs:          []string{"cn", "member"},
		}

		group, err := l.GetGroup("admins", baseDN)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if group.DN != groupEntry.DN {
			t.Fatalf("DN = %q", group.DN)
		}
		if group.GetAttributeValue("cn") != "admins" {
			t.Fatalf("cn = %q", group.GetAttributeValue("cn"))
		}
		if got := group.Attributes["member"]; len(got) != 2 {
			t.Fatalf("member values not preserved: %v", got)
		}

		// Wire-level assertions.
		if len(cm.calls) != 1 {
			t.Fatalf("got %d calls, want 1", len(cm.calls))
		}
		if !strings.Contains(cm.calls[0].filter, "cn=admins") {
			t.Fatalf("filter missing cn: %q", cm.calls[0].filter)
		}
		if cm.calls[0].sizeLimit != 2 {
			t.Fatalf("size limit = %d, want 2", cm.calls[0].sizeLimit)
		}
		if len(cm.calls[0].attributes) != 2 || cm.calls[0].attributes[0] != "cn" {
			t.Fatalf("attributes = %v", cm.calls[0].attributes)
		}
	})

	t.Run("cn is filter-escaped", func(t *testing.T) {
		cm := newCaptureMock(t, pagedPage{})
		l := newLDAPperWithCapture(cm)
		l.catalogAdapter = &fakeAdapter{
			groupFilterTemplate: simpleTpl,
			groupAttrs:          []string{"cn"},
		}
		_, _ = l.GetGroup("a(b*c)", baseDN)
		if len(cm.calls) != 1 {
			t.Fatalf("expected one call, got %d", len(cm.calls))
		}
		if !strings.Contains(cm.calls[0].filter, `a\28b\2ac\29`) {
			t.Fatalf("filter not escaped: %q", cm.calls[0].filter)
		}
	})
}
