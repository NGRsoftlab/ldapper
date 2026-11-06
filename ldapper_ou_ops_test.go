// Copyright 2020-2026 NGR Softlab
package ldapper

import (
	"errors"
	"strings"
	"testing"

	"github.com/go-ldap/ldap/v3"
)

// TestGetOU covers the single-OU lookup. Focus:
//   - base DN validated via searchSingleEntryLocked,
//   - adapter's SearchOUFilterTemplate is used with an escaped `ou` name,
//   - result is projected into *types.LDAPOU with the adapter's OUAttrs().
//
// NB: the returned object is a *flat* LDAPOU (no children). Hierarchy is
// available via GetCatalogTree / GetSubOUs and is covered elsewhere.
func TestGetOU(t *testing.T) {
	const (
		ouTemplate = "(&(objectClass=organizationalUnit)(ou=%s))"
		baseDN     = "dc=example,dc=com"
	)

	ouEntry := newLDAPEntry(
		"ou=Sales,dc=example,dc=com",
		map[string][]string{
			"ou":          {"Sales"},
			"description": {"Sales department"},
			"objectClass": {"top", "organizationalUnit"},
		},
	)

	t.Run("nil connection", func(t *testing.T) {
		l := &LDAPper{catalogAdapter: &fakeAdapter{ouFilterTemplate: ouTemplate}}
		_, err := l.GetOU("Sales", baseDN)
		if !errors.Is(err, ErrClosed) {
			t.Fatalf("errors.Is(%v, ErrClosed) = false", err)
		}
	})

	t.Run("empty ou name", func(t *testing.T) {
		cm := newCaptureMock(t)
		l := newLDAPperWithCapture(cm)
		l.catalogAdapter = &fakeAdapter{ouFilterTemplate: ouTemplate}
		_, err := l.GetOU("", baseDN)
		if !errors.Is(err, ErrInvalidArgument) {
			t.Fatalf("errors.Is(%v, ErrInvalidArgument) = false", err)
		}
	})

	t.Run("empty base DN", func(t *testing.T) {
		cm := newCaptureMock(t)
		l := newLDAPperWithCapture(cm)
		l.catalogAdapter = &fakeAdapter{ouFilterTemplate: ouTemplate}
		_, err := l.GetOU("Sales", "")
		if !errors.Is(err, ErrInvalidArgument) {
			t.Fatalf("errors.Is(%v, ErrInvalidArgument) = false", err)
		}
	})

	t.Run("not found", func(t *testing.T) {
		cm := newCaptureMock(t, pagedPage{})
		l := newLDAPperWithCapture(cm)
		l.catalogAdapter = &fakeAdapter{
			ouFilterTemplate: ouTemplate,
			ouAttrs:          []string{"ou"},
		}
		_, err := l.GetOU("Ghost", baseDN)
		if !errors.Is(err, ErrNotFound) {
			t.Fatalf("errors.Is(%v, ErrNotFound) = false", err)
		}
	})

	t.Run("ambiguous", func(t *testing.T) {
		e1 := newLDAPEntry("ou=Sales,dc=a", nil)
		e2 := newLDAPEntry("ou=Sales,dc=b", nil)
		cm := newCaptureMock(t, pagedPage{entries: []*ldap.Entry{e1, e2}})
		l := newLDAPperWithCapture(cm)
		l.catalogAdapter = &fakeAdapter{
			ouFilterTemplate: ouTemplate,
			ouAttrs:          []string{"ou"},
		}
		_, err := l.GetOU("Sales", baseDN)
		if !errors.Is(err, ErrAmbiguousResult) {
			t.Fatalf("errors.Is(%v, ErrAmbiguousResult) = false", err)
		}
	})

	t.Run("success: filter, attributes, mapping", func(t *testing.T) {
		cm := newCaptureMock(t, pagedPage{entries: []*ldap.Entry{ouEntry}})
		l := newLDAPperWithCapture(cm)
		l.catalogAdapter = &fakeAdapter{
			ouFilterTemplate: ouTemplate,
			ouAttrs:          []string{"ou", "description", "objectClass"},
		}

		ou, err := l.GetOU("Sales", baseDN)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if ou.DN != ouEntry.DN {
			t.Fatalf("DN = %q", ou.DN)
		}
		if ou.GetAttributeValue("ou") != "Sales" {
			t.Fatalf("ou = %q", ou.GetAttributeValue("ou"))
		}
		if ou.GetAttributeValue("description") != "Sales department" {
			t.Fatalf("description = %q", ou.GetAttributeValue("description"))
		}
		if got := ou.Attributes["objectClass"]; len(got) != 2 || got[1] != "organizationalUnit" {
			t.Fatalf("objectClass not preserved: %v", got)
		}

		// Wire-level assertions.
		if len(cm.calls) != 1 {
			t.Fatalf("got %d calls, want 1", len(cm.calls))
		}
		if !strings.Contains(cm.calls[0].filter, "ou=Sales") {
			t.Fatalf("filter missing ou: %q", cm.calls[0].filter)
		}
		if cm.calls[0].sizeLimit != 2 {
			t.Fatalf("size limit = %d, want 2", cm.calls[0].sizeLimit)
		}
		if len(cm.calls[0].attributes) != 3 || cm.calls[0].attributes[0] != "ou" {
			t.Fatalf("attributes = %v", cm.calls[0].attributes)
		}
	})

	t.Run("ou name is filter-escaped", func(t *testing.T) {
		cm := newCaptureMock(t, pagedPage{})
		l := newLDAPperWithCapture(cm)
		l.catalogAdapter = &fakeAdapter{
			ouFilterTemplate: ouTemplate,
			ouAttrs:          []string{"ou"},
		}
		_, _ = l.GetOU("Sales(EMEA)*", baseDN)
		if len(cm.calls) != 1 {
			t.Fatalf("expected one call, got %d", len(cm.calls))
		}
		if !strings.Contains(cm.calls[0].filter, `Sales\28EMEA\29\2a`) {
			t.Fatalf("filter not escaped: %q", cm.calls[0].filter)
		}
	})

	t.Run("malformed base DN", func(t *testing.T) {
		cm := newCaptureMock(t)
		l := newLDAPperWithCapture(cm)
		l.catalogAdapter = &fakeAdapter{ouFilterTemplate: ouTemplate}
		_, err := l.GetOU("Sales", "not a dn")
		if !errors.Is(err, ErrInvalidArgument) {
			t.Fatalf("errors.Is(%v, ErrInvalidArgument) = false", err)
		}
	})
}
