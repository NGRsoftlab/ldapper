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
// syntactically valid, AND the template must reference exactly as many
// positional %[N]s verbs as the adapter supplies args.
//
// The arity check is what separates a template/args bug (silent
// over- or under-supply) from an escaping bug, and catches the case where
// fmt.Sprintf silently drops extra args (e.g. adapter returns 2 args for a
// template that only uses %[1]s).
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
			// Single-arg templates: escape, substitute, compile, and check
			// that the template references %[1]s exactly.
			mustCompileTemplate(t, a.name, "SearchUserFilterTemplate",
				a.adapter.SearchUserFilterTemplate(), name, 1)
			mustCompileTemplate(t, a.name, "SearchOUFilterTemplate",
				a.adapter.SearchOUFilterTemplate(), name, 1)
			mustCompileTemplate(t, a.name, "SearchGroupFilterTemplate",
				a.adapter.SearchGroupFilterTemplate(), groupCN, 1)

			// User groups: argument count is adapter-specific.
			args := a.adapter.SearchUserGroupsFilterTemplateArgs(user)
			escaped := make([]any, len(args))
			for i, arg := range args {
				escaped[i] = ldap.EscapeFilter(fmt.Sprint(arg))
			}
			tmpl := a.adapter.SearchUserGroupsFilterTemplate()
			validateTemplateArity(t, a.name, "SearchUserGroupsFilterTemplate", tmpl, len(escaped))
			mustCompileRendered(t, a.name, "SearchUserGroupsFilterTemplate",
				fmt.Sprintf(tmpl, escaped...))
		}
	})
}

// mustCompileTemplate applies the single-arg convention shared by every
// template except SearchUserGroupsFilterTemplate: check arity, escape,
// substitute, compile.
func mustCompileTemplate(t *testing.T, adapter, kind, template, arg string, numArgs int) {
	t.Helper()
	validateTemplateArity(t, adapter, kind, template, numArgs)
	mustCompileRendered(t, adapter, kind, fmt.Sprintf(template, ldap.EscapeFilter(arg)))
}

// mustCompileRendered asserts the final filter is valid and that Sprintf did
// not report an arity mismatch. The arity check here is what catches the
// "fewer args than verbs" case (visible as %!s(MISSING) in the output);
// validateTemplateArity catches the "more args than verbs" case.
func mustCompileRendered(t *testing.T, adapter, kind, filter string) {
	t.Helper()
	if strings.Contains(filter, "%!") {
		t.Fatalf("%s.%s: template/args arity mismatch (filter=%q)", adapter, kind, filter)
	}
	if _, err := ldap.CompileFilter(filter); err != nil {
		t.Fatalf("%s.%s: invalid filter (%q): %v", adapter, kind, filter, err)
	}
}

// validateTemplateArity checks that the set of positional %[N]s verbs
// referenced by template is exactly {1, 2, ..., numArgs}. This covers both
// directions of the arity contract:
//
//   - template references %[N]s for N outside [1, numArgs]  → Sprintf would
//     emit %!s(MISSING), caught here with a clearer message;
//   - template does not reference %[N]s for some N in [1, numArgs] → Sprintf
//     would silently drop the extra arg, caught here.
//
// Only %[N]s is considered. Bare %s (sequential verbs) is not used by any
// shipped adapter; an adapter using it would need to bypass this helper.
func validateTemplateArity(t *testing.T, adapter, kind, template string, numArgs int) {
	t.Helper()

	referenced := make(map[int]struct{})
	for i := 0; i < len(template); {
		if template[i] != '%' {
			i++
			continue
		}
		if i+1 < len(template) && template[i+1] == '%' {
			i += 2 // literal %%
			continue
		}
		if i+1 < len(template) && template[i+1] == '[' {
			j := i + 2
			n := 0
			for j < len(template) && template[j] >= '0' && template[j] <= '9' {
				n = n*10 + int(template[j]-'0')
				j++
			}
			if j < len(template) && template[j] == ']' && j+1 < len(template) && template[j+1] == 's' {
				referenced[n] = struct{}{}
				i = j + 2
				continue
			}
		}
		i++
	}

	for n := range referenced {
		if n < 1 || n > numArgs {
			t.Fatalf("%s.%s: template references %%[%d]s but only %d arg(s) supplied (template=%q)",
				adapter, kind, n, numArgs, template)
		}
	}
	for n := 1; n <= numArgs; n++ {
		if _, ok := referenced[n]; !ok {
			t.Fatalf("%s.%s: template does not reference %%[%d]s but %d arg(s) supplied (template=%q)",
				adapter, kind, n, numArgs, template)
		}
	}
}
