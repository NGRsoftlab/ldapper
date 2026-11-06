// Copyright 2020-2026 NGR Softlab
package types

import "testing"

// TestAttrValue covers the shared attribute getter used by LDAPUser,
// LDAPGroup and LDAPOU. The contract is intentionally simple:
//   - first element of the slice if present,
//   - empty string otherwise (missing key, empty slice, nil map).
func TestAttrValue(t *testing.T) {
	tests := []struct {
		name  string
		attrs map[string][]string
		key   string
		want  string
	}{
		{
			name:  "present with single value",
			attrs: map[string][]string{"cn": {"Alice"}},
			key:   "cn",
			want:  "Alice",
		},
		{
			name:  "present with multiple values returns first",
			attrs: map[string][]string{"mail": {"a@x", "b@y"}},
			key:   "mail",
			want:  "a@x",
		},
		{
			name:  "present but empty slice",
			attrs: map[string][]string{"cn": {}},
			key:   "cn",
			want:  "",
		},
		{
			name:  "missing key",
			attrs: map[string][]string{"sn": {"Smith"}},
			key:   "cn",
			want:  "",
		},
		{
			name:  "nil map",
			attrs: nil,
			key:   "cn",
			want:  "",
		},
		{
			name:  "empty attribute name",
			attrs: map[string][]string{"": {"x"}},
			key:   "",
			want:  "x",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := attrValue(tc.attrs, tc.key); got != tc.want {
				t.Fatalf("attrValue(%v, %q) = %q, want %q", tc.attrs, tc.key, got, tc.want)
			}
		})
	}
}

// TestFirstAttrValue covers the ordered-fallback getter. The most important
// nuance: an attribute present with a single empty string ("") must NOT stop
// the lookup — only a non-empty value terminates the search.
func TestFirstAttrValue(t *testing.T) {
	tests := []struct {
		name  string
		attrs map[string][]string
		keys  []string
		want  string
	}{
		{
			name:  "first key has value",
			attrs: map[string][]string{"a": {"A"}, "b": {"B"}},
			keys:  []string{"a", "b"},
			want:  "A",
		},
		{
			name:  "first missing, second has value",
			attrs: map[string][]string{"b": {"B"}},
			keys:  []string{"a", "b"},
			want:  "B",
		},
		{
			name:  "first present but empty slice, second has value",
			attrs: map[string][]string{"a": {}, "b": {"B"}},
			keys:  []string{"a", "b"},
			want:  "B",
		},
		{
			name:  "first present with blank string, second has value",
			attrs: map[string][]string{"a": {""}, "b": {"B"}},
			keys:  []string{"a", "b"},
			want:  "B",
		},
		{
			name:  "none present",
			attrs: map[string][]string{"c": {"C"}},
			keys:  []string{"a", "b"},
			want:  "",
		},
		{
			name:  "empty alternatives list",
			attrs: map[string][]string{"a": {"A"}},
			keys:  []string{},
			want:  "",
		},
		{
			name:  "nil map",
			attrs: nil,
			keys:  []string{"a"},
			want:  "",
		},
		{
			name:  "empty attribute name among alternatives",
			attrs: map[string][]string{"": {"X"}},
			keys:  []string{"", "a"},
			want:  "X",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := firstAttrValue(tc.attrs, tc.keys); got != tc.want {
				t.Fatalf("firstAttrValue(%v, %v) = %q, want %q", tc.attrs, tc.keys, got, tc.want)
			}
		})
	}
}
