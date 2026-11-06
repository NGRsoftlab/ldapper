// Copyright 2020-2026 NGR Softlab
package ldapper

import (
	"reflect"
	"testing"

	"github.com/go-ldap/ldap/v3"

	"github.com/NGRsoftlab/ldapper/types"
)

// ---------- attrsToMap ----------

// TestAttrsToMap verifies that the helper projects an *ldap.Entry onto a
// map keyed by the requested attribute names only. Attributes present on
// the entry but absent from the list must NOT leak into the map, and
// missing attributes must produce a nil/empty value rather than be skipped.
func TestAttrsToMap(t *testing.T) {
	entry := &ldap.Entry{
		DN: "cn=Alice,dc=example,dc=com",
		Attributes: []*ldap.EntryAttribute{
			{Name: "cn", Values: []string{"Alice"}},
			{Name: "mail", Values: []string{"alice@example.com", "a@example.org"}},
			{Name: "extra", Values: []string{"should-not-be-copied"}},
		},
	}

	tests := []struct {
		name       string
		attributes []string
		want       map[string][]string
	}{
		{
			name:       "single present attribute",
			attributes: []string{"cn"},
			want:       map[string][]string{"cn": {"Alice"}},
		},
		{
			name:       "multi-valued attribute keeps order",
			attributes: []string{"mail"},
			want:       map[string][]string{"mail": {"alice@example.com", "a@example.org"}},
		},
		{
			name:       "missing attribute yields empty slice",
			attributes: []string{"sn"},
			want:       map[string][]string{"sn": {}},
		},
		{
			name:       "extra entry attribute not in list is excluded",
			attributes: []string{"cn"},
			want:       map[string][]string{"cn": {"Alice"}},
		},
		{
			name:       "empty attribute list",
			attributes: []string{},
			want:       map[string][]string{},
		},
		{
			name:       "nil attribute list",
			attributes: nil,
			want:       map[string][]string{},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := attrsToMap(entry, tc.attributes)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("attrsToMap() = %#v, want %#v", got, tc.want)
			}
			// Defensive: the extra attribute must never leak through, even
			// when the requested list is empty.
			if _, ok := got["extra"]; ok {
				t.Fatalf("attrsToMap leaked 'extra' attribute: %#v", got)
			}
		})
	}
}

// TestAttrsToMap_NilAttributesOnEntry verifies that entries with no
// attribute list at all (e.g. minimal server response) do not panic.
//
// NB: even for a completely attribute-less entry, GetAttributeValues
// returns an EMPTY slice per requested attribute — not nil. The test
// pins that contract so future changes to the projection helper cannot
// silently switch to nil (which would break callers using reflect.DeepEqual
// or json.Marshal semantics).
func TestAttrsToMap_NilAttributesOnEntry(t *testing.T) {
	entry := &ldap.Entry{DN: "cn=Alice,dc=example,dc=com"}
	got := attrsToMap(entry, []string{"cn", "mail"})
	want := map[string][]string{"cn": {}, "mail": {}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("attrsToMap() = %#v, want %#v", got, want)
	}
}

// ---------- escapeFilterArgs ----------

// TestEscapeFilterArgs covers RFC 4515 escaping and the nil-input shortcuts.
// Expected values are hardcoded on purpose: relying on ldap.EscapeFilter
// here would only test the library, not our wrapper contract.
func TestEscapeFilterArgs(t *testing.T) {
	tests := []struct {
		name string
		in   []any
		want []any
	}{
		{"nil slice", nil, nil},
		{"empty slice", []any{}, nil},
		{"plain string", []any{"foo"}, []any{"foo"}},
		{"parens escaped", []any{"foo(bar)"}, []any{`foo\28bar\29`}},
		{"asterisk escaped", []any{"*"}, []any{`\2a`}},
		{"backslash escaped", []any{`\`}, []any{`\5c`}},
		{"nul byte escaped", []any{"a\x00b"}, []any{`a\00b`}},
		{"combined specials", []any{`a(b*c\d)`}, []any{`a\28b\2ac\5cd\29`}},
		{"nil element renders empty", []any{nil}, []any{""}},
		{"integer via fmt.Sprint", []any{123}, []any{"123"}},
		{"boolean via fmt.Sprint", []any{true}, []any{"true"}},
		{"mixed arguments", []any{"a", nil, 7}, []any{"a", "", "7"}},
		{
			// Typical usage: DN + uid together in a two-placeholder template.
			name: "dn and uid combined",
			in:   []any{"cn=Alice,dc=example,dc=com", "alice"},
			want: []any{"cn=Alice,dc=example,dc=com", "alice"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := escapeFilterArgs(tc.in)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("escapeFilterArgs(%#v) = %#v, want %#v", tc.in, got, tc.want)
			}
		})
	}
}

// TestEscapeFilterArgs_DoesNotMutateInput guards against a regression where
// the helper might escape in place, which would silently corrupt the caller's
// slice across retries.
func TestEscapeFilterArgs_DoesNotMutateInput(t *testing.T) {
	in := []any{"*", "a(b)"}
	original := append([]any(nil), in...)

	_ = escapeFilterArgs(in)

	if !reflect.DeepEqual(in, original) {
		t.Fatalf("escapeFilterArgs mutated input: got %#v, want %#v", in, original)
	}
}

// ---------- parentDNOf ----------

// TestParentDNOf covers the DN hierarchy extraction. Contract:
//   - topmost RDN (single-RDN DN) → "",
//   - any deeper DN → parent without its first RDN,
//   - empty or malformed → "".
func TestParentDNOf(t *testing.T) {
	tests := []struct {
		name string
		dn   string
		want string
	}{
		{"single rdn yields empty parent", "dc=com", ""},
		{"two rdns", "dc=example,dc=com", "dc=com"},
		{"three rdns", "ou=Users,dc=example,dc=com", "dc=example,dc=com"},
		{"deep dn", "cn=Alice,ou=Users,ou=Staff,dc=example,dc=com", "ou=Users,ou=Staff,dc=example,dc=com"},
		{"empty dn", "", ""},
		{"malformed dn", "not a dn", ""},
		{"escaped comma preserved", `ou=A\,B,dc=example,dc=com`, "dc=example,dc=com"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := parentDNOf(tc.dn); got != tc.want {
				t.Fatalf("parentDNOf(%q) = %q, want %q", tc.dn, got, tc.want)
			}
		})
	}
}

// ---------- trimDepth ----------

// buildSampleTree returns a 3-level tree for trimDepth tests:
//
//	rootA
//	├── childA1
//	│   └── grandA1a
//	└── childA2
//	rootB
//	└── childB1
func buildSampleTree() []*types.OUNormalizedInfo {
	return []*types.OUNormalizedInfo{
		{
			Name: "rootA", DN: "ou=rootA,dc=x", OU: "rootA",
			Children: []*types.OUNormalizedInfo{
				{
					Name: "childA1", DN: "ou=childA1,ou=rootA,dc=x", OU: "childA1",
					Children: []*types.OUNormalizedInfo{
						{Name: "grandA1a", DN: "ou=grandA1a,ou=childA1,ou=rootA,dc=x", OU: "grandA1a"},
					},
				},
				{Name: "childA2", DN: "ou=childA2,ou=rootA,dc=x", OU: "childA2"},
			},
		},
		{
			Name: "rootB", DN: "ou=rootB,dc=x", OU: "rootB",
			Children: []*types.OUNormalizedInfo{
				{Name: "childB1", DN: "ou=childB1,ou=rootB,dc=x", OU: "childB1"},
			},
		},
	}
}

// TestTrimDepth verifies that trimDepth returns a *new* tree of the same
// shape, keeping only the first maxDepth levels.
func TestTrimDepth(t *testing.T) {
	tests := []struct {
		name     string
		maxDepth int
		want     func() []*types.OUNormalizedInfo
	}{
		{
			name:     "depth 1 keeps only roots",
			maxDepth: 1,
			want: func() []*types.OUNormalizedInfo {
				return []*types.OUNormalizedInfo{
					{Name: "rootA", DN: "ou=rootA,dc=x", OU: "rootA", Children: []*types.OUNormalizedInfo{}},
					{Name: "rootB", DN: "ou=rootB,dc=x", OU: "rootB", Children: []*types.OUNormalizedInfo{}},
				}
			},
		},
		{
			name:     "depth 2 keeps children truncated",
			maxDepth: 2,
			want: func() []*types.OUNormalizedInfo {
				return []*types.OUNormalizedInfo{
					{
						Name: "rootA", DN: "ou=rootA,dc=x", OU: "rootA",
						Children: []*types.OUNormalizedInfo{
							{Name: "childA1", DN: "ou=childA1,ou=rootA,dc=x", OU: "childA1", Children: []*types.OUNormalizedInfo{}},
							{Name: "childA2", DN: "ou=childA2,ou=rootA,dc=x", OU: "childA2", Children: []*types.OUNormalizedInfo{}},
						},
					},
					{
						Name: "rootB", DN: "ou=rootB,dc=x", OU: "rootB",
						Children: []*types.OUNormalizedInfo{
							{Name: "childB1", DN: "ou=childB1,ou=rootB,dc=x", OU: "childB1", Children: []*types.OUNormalizedInfo{}},
						},
					},
				}
			},
		},
		{
			name:     "depth 3 keeps whole tree but rebuilds it",
			maxDepth: 3,
			want: func() []*types.OUNormalizedInfo {
				return []*types.OUNormalizedInfo{
					{
						Name: "rootA", DN: "ou=rootA,dc=x", OU: "rootA",
						Children: []*types.OUNormalizedInfo{
							{
								Name: "childA1", DN: "ou=childA1,ou=rootA,dc=x", OU: "childA1",
								Children: []*types.OUNormalizedInfo{
									{Name: "grandA1a", DN: "ou=grandA1a,ou=childA1,ou=rootA,dc=x", OU: "grandA1a", Children: []*types.OUNormalizedInfo{}},
								},
							},
							{Name: "childA2", DN: "ou=childA2,ou=rootA,dc=x", OU: "childA2", Children: []*types.OUNormalizedInfo{}},
						},
					},
					{
						Name: "rootB", DN: "ou=rootB,dc=x", OU: "rootB",
						Children: []*types.OUNormalizedInfo{
							{Name: "childB1", DN: "ou=childB1,ou=rootB,dc=x", OU: "childB1", Children: []*types.OUNormalizedInfo{}},
						},
					},
				}
			},
		},
		{
			// NB: trimDepth is only called with maxDepth > 0 in production,
			// but the <=1 branch also catches 0 — document that contract here.
			name:     "depth 0 behaves like depth 1",
			maxDepth: 0,
			want: func() []*types.OUNormalizedInfo {
				return []*types.OUNormalizedInfo{
					{Name: "rootA", DN: "ou=rootA,dc=x", OU: "rootA", Children: []*types.OUNormalizedInfo{}},
					{Name: "rootB", DN: "ou=rootB,dc=x", OU: "rootB", Children: []*types.OUNormalizedInfo{}},
				}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := trimDepth(buildSampleTree(), tc.maxDepth)
			want := tc.want()
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("trimDepth(maxDepth=%d) mismatch\n got = %#v\nwant = %#v",
					tc.maxDepth, got, want)
			}
		})
	}
}

// TestTrimDepth_EmptyInput ensures the helper does not panic on nil / empty.
func TestTrimDepth_EmptyInput(t *testing.T) {
	if got := trimDepth(nil, 3); len(got) != 0 {
		t.Fatalf("trimDepth(nil, 3) = %#v, want empty slice", got)
	}
	if got := trimDepth([]*types.OUNormalizedInfo{}, 3); len(got) != 0 {
		t.Fatalf("trimDepth([], 3) = %#v, want empty slice", got)
	}
}

// TestTrimDepth_DoesNotMutateSource is the regression guard for shallow
// copying: after trimDepth, the original tree must still expose its
// original children everywhere.
func TestTrimDepth_DoesNotMutateSource(t *testing.T) {
	src := buildSampleTree()

	_ = trimDepth(src, 1)

	if len(src[0].Children) != 2 {
		t.Fatalf("original tree children mutated: len = %d, want 2", len(src[0].Children))
	}
	if len(src[0].Children[0].Children) != 1 {
		t.Fatalf("original grandchild mutated: len = %d, want 1", len(src[0].Children[0].Children))
	}
}

// --------- TestCanonicalDN ---------- //

func TestCanonicalDN(t *testing.T) {
	tests := []struct {
		name string
		a, b string
		want bool // true = same canonical key
	}{
		{
			name: "case-insensitive types and values",
			a:    "OU=Sales,DC=Example,DC=com",
			b:    "ou=sales,dc=example,dc=com",
			want: true,
		},
		{
			name: "different escape sequences for the same value",
			a:    `ou=Sales\, Inc,dc=x`,
			b:    `ou=Sales\2c Inc,dc=x`,
			want: true,
		},
		{
			name: "multi-valued RDN reordered",
			a:    "cn=Alice+sn=Smith,dc=x",
			b:    "sn=Smith+cn=Alice,dc=x",
			want: true,
		},
		{
			name: "insignificant trailing whitespace in value",
			a:    "ou=Sales ,dc=x",
			b:    "ou=Sales,dc=x",
			want: true,
		},
		{
			name: "different value",
			a:    "ou=Sales,dc=x",
			b:    "ou=Marketing,dc=x",
			want: false,
		},
		{
			name: "different RDN depth",
			a:    "ou=Sales,dc=x",
			b:    "ou=EMEA,ou=Sales,dc=x",
			want: false,
		},
		{
			name: "different base",
			a:    "ou=Sales,dc=x",
			b:    "ou=Sales,dc=y",
			want: false,
		},
		{
			name: "empty DNs both empty",
			a:    "",
			b:    "",
			want: true,
		},
		{
			name: "empty vs non-empty",
			a:    "",
			b:    "dc=x",
			want: false,
		},
		{
			name: "malformed falls back to lowercased raw",
			a:    "not a dn",
			b:    "NOT A DN",
			want: true, // both malformed -> strings.ToLower fallback
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ka := canonicalDN(tc.a)
			kb := canonicalDN(tc.b)
			if (ka == kb) != tc.want {
				t.Fatalf("canonicalDN(%q)=%q, canonicalDN(%q)=%q, want equal=%v",
					tc.a, ka, tc.b, kb, tc.want)
			}
		})
	}
}

// TestCanonicalDN_StableAcrossInvocations guards against non-determinism
// (map iteration, sort instability).
func TestCanonicalDN_Stable(t *testing.T) {
	inputs := []string{
		"OU=Sales,DC=Example,DC=com",
		`ou=Sales\, Inc,ou=EMEA,dc=x`,
		"cn=Alice+sn=Smith+ou=People,dc=x",
	}
	for _, in := range inputs {
		first := canonicalDN(in)
		for i := 0; i < 100; i++ {
			if got := canonicalDN(in); got != first {
				t.Fatalf("canonicalDN(%q) unstable: %q vs %q", in, first, got)
			}
		}
	}
}
