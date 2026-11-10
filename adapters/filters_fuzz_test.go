// Copyright 2020-2026 NGR Softlab
package adapters

import (
	"fmt"
	"strings"
	"testing"

	"github.com/go-ldap/ldap/v3"

	"github.com/NGRsoftlab/ldapper/types"
)

// filterTemplateAdapter is the subset of CatalogAdapter driven here. Using
// an anonymous interface (rather than interfaces.CatalogAdapter) keeps this
// test decoupled from the full contract — a new adapter only needs to
// implement the filter methods to be picked up.
type filterTemplateAdapter interface {
	SearchUserFilterTemplate() string
	SearchUserGroupsFilterTemplate() string
	SearchUserGroupsFilterTemplateArgs(types.LDAPUser) []any
	SearchOUFilterTemplate() string
	SearchGroupFilterTemplate() string
}

// allShippedAdapters — adding an adapter here automatically extends fuzz
// coverage across every filter template it exposes.
var allShippedAdapters = []struct {
	name    string
	adapter filterTemplateAdapter
}{
	{"MSAD", MSADAdapter{}},
	{"OpenLDAP", OPENLDAPAdapter{}},
	{"ALDPro", ALDPROAdapter{}},
	{"FreeIPA", FREEIPAAdapter{}},
}

// FuzzAdapterFilterTemplates — for every adapter and every user-supplied
// value that can reach a filter, the escaped + substituted filter must be
// syntactically valid. One fuzz input drives all four adapters, so a
// regression on a shared metacharacter (or a new adapter breaking the
// arity contract) is caught in a single run.
func FuzzAdapterFilterTemplates(f *testing.F) {
	// Seeds span the byte categories LDAP filter escaping must handle:
	// plain ASCII, filter metacharacters, backslash, empty.
	f.Add("alice", "uid=alice,dc=x", "admins")
	f.Add("a*b(c)", "uid=a*b(c),dc=x", "a*d*mins")
	f.Add(`a\b`, `uid=a\b,dc=x`, `a\b`)
	f.Add("", "", "")

	f.Fuzz(func(t *testing.T, name, dn, groupCN string) {
		user := types.LDAPUser{
			DN:         dn,
			Attributes: map[string][]string{"uid": {name}},
		}

		for _, a := range allShippedAdapters {
			mustCompileTemplate(t, a.name, "SearchUserFilterTemplate",
				a.adapter.SearchUserFilterTemplate(), name)
			mustCompileTemplate(t, a.name, "SearchOUFilterTemplate",
				a.adapter.SearchOUFilterTemplate(), name)
			mustCompileTemplate(t, a.name, "SearchGroupFilterTemplate",
				a.adapter.SearchGroupFilterTemplate(), groupCN)

			// User groups: argument count is adapter-specific.
			args := a.adapter.SearchUserGroupsFilterTemplateArgs(user)
			escaped := make([]any, len(args))
			for i, arg := range args {
				escaped[i] = ldap.EscapeFilter(fmt.Sprint(arg))
			}
			mustCompileRendered(t, a.name, "SearchUserGroupsFilterTemplate",
				fmt.Sprintf(a.adapter.SearchUserGroupsFilterTemplate(), escaped...))
		}
	})
}

// mustCompileTemplate applies the single-arg convention shared by every
// template except SearchUserGroupsFilterTemplate: escape, substitute, compile.
func mustCompileTemplate(t *testing.T, adapter, kind, template, arg string) {
	t.Helper()
	mustCompileRendered(t, adapter, kind, fmt.Sprintf(template, ldap.EscapeFilter(arg)))
}

// mustCompileRendered asserts the final filter is valid and that Sprintf did
// not report an arity mismatch. The arity check is what separates a
// template/args bug from an escaping bug in the failure message.
func mustCompileRendered(t *testing.T, adapter, kind, filter string) {
	t.Helper()
	if strings.Contains(filter, "%!") {
		t.Fatalf("%s.%s: template/args arity mismatch (filter=%q)", adapter, kind, filter)
	}
	if _, err := ldap.CompileFilter(filter); err != nil {
		t.Fatalf("%s.%s: invalid filter (%q): %v", adapter, kind, filter, err)
	}
}
