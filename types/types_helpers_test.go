// Copyright 2020-2026 NGR Softlab
package types

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ================== attrValue ==================

func TestAttrValue(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		attrs map[string][]string
		key   string
		want  string
	}{
		{
			name:  "single value",
			attrs: map[string][]string{"cn": {"alice"}},
			key:   "cn",
			want:  "alice",
		},
		{
			name:  "multi value returns first",
			attrs: map[string][]string{"cn": {"alice", "Alice Smith"}},
			key:   "cn",
			want:  "alice",
		},
		{
			name:  "missing attribute",
			attrs: map[string][]string{"cn": {"alice"}},
			key:   "mail",
			want:  "",
		},
		{
			name:  "nil map",
			attrs: nil,
			key:   "cn",
			want:  "",
		},
		{
			name:  "empty slice value",
			attrs: map[string][]string{"cn": {}},
			key:   "cn",
			want:  "",
		},
		{
			name:  "explicit empty first value",
			attrs: map[string][]string{"cn": {""}},
			key:   "cn",
			want:  "",
		},
		{
			name:  "first empty, second present",
			attrs: map[string][]string{"cn": {"", "alice"}},
			key:   "cn",
			want:  "",
			// NB: attrValue does NOT skip empty values — that is
			// firstAttrValue's job. Callers wanting fallback semantics
			// must use the *FirstNonNull* variant.
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, attrValue(tt.attrs, tt.key))
		})
	}
}

// ================== firstAttrValue ==================

func TestFirstAttrValue(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		attrs map[string][]string
		names []string
		want  string
	}{
		{
			name:  "first name has value",
			attrs: map[string][]string{"cn": {"alice"}, "displayName": {"Alice"}},
			names: []string{"cn", "displayName"},
			want:  "alice",
		},
		{
			name:  "first missing, second present",
			attrs: map[string][]string{"displayName": {"Alice"}},
			names: []string{"cn", "displayName"},
			want:  "Alice",
		},
		{
			name:  "first empty value, second present",
			attrs: map[string][]string{"cn": {""}, "displayName": {"Alice"}},
			names: []string{"cn", "displayName"},
			want:  "Alice",
			// This is the key difference vs attrValue: empty values are
			// skipped, not returned.
		},
		{
			name:  "first attribute empty slice, second present",
			attrs: map[string][]string{"cn": {}, "displayName": {"Alice"}},
			names: []string{"cn", "displayName"},
			want:  "Alice",
		},
		{
			name:  "none present",
			attrs: map[string][]string{},
			names: []string{"cn", "displayName"},
			want:  "",
		},
		{
			name:  "nil names",
			attrs: map[string][]string{"cn": {"alice"}},
			names: nil,
			want:  "",
		},
		{
			name:  "empty names",
			attrs: map[string][]string{"cn": {"alice"}},
			names: []string{},
			want:  "",
		},
		{
			name:  "attribute with empty first value is skipped, not scanned",
			attrs: map[string][]string{"cn": {"", "alice", "bob"}},
			names: []string{"cn"},
			want:  "",
			// NB: firstAttrValue inspects only v[0] of each named attribute.
			// An empty v[0] marks the whole attribute as "not set" and the
			// search moves to the next alternative in `names` — it does NOT
			// scan the rest of the slice. This is the documented contract:
			// multi-valued attributes with an empty leading value are treated
			// as absent, which matches LDAP's "empty means not present" for
			// single-valued naming attributes (cn, uid, ...).
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, firstAttrValue(tt.attrs, tt.names))
		})
	}
}

// ================== attrRawValue ==================

func TestAttrRawValue(t *testing.T) {
	t.Parallel()

	binary := []byte{0xFF, 0x00, 0x80, 0x01} // non-UTF-8

	t.Run("returns first value as bytes", func(t *testing.T) {
		t.Parallel()

		attrs := map[string][]string{"jpegPhoto": {string(binary)}}
		got := attrRawValue(attrs, "jpegPhoto")
		assert.Equal(t, binary, got)
	})

	t.Run("missing attribute returns nil", func(t *testing.T) {
		t.Parallel()

		// NB: nil, not []byte{}. Callers distinguishing "absent" from
		// "present but empty" rely on this.
		assert.Nil(t, attrRawValue(map[string][]string{}, "photo"))
	})

	t.Run("nil map returns nil", func(t *testing.T) {
		t.Parallel()
		assert.Nil(t, attrRawValue(nil, "photo"))
	})

	t.Run("empty slice returns nil", func(t *testing.T) {
		t.Parallel()
		assert.Nil(t, attrRawValue(map[string][]string{"photo": {}}, "photo"))
	})

	t.Run("present empty string returns zero-length non-nil slice", func(t *testing.T) {
		t.Parallel()

		// This is a subtle distinction: the attribute IS present, with
		// an explicit empty string. The function returns []byte(""),
		// which is non-nil (len 0). Callers that only check len() see
		// "empty"; callers that compare against nil see "present".
		got := attrRawValue(map[string][]string{"photo": {""}}, "photo")
		assert.NotNil(t, got, "explicit empty value yields non-nil []byte")
		assert.Empty(t, got)
	})

	t.Run("preserves non-UTF-8 bytes exactly", func(t *testing.T) {
		t.Parallel()

		// The whole point of the raw variant: []byte(string(bytes))
		// round-trips losslessly through Go strings, even when the
		// bytes are not valid UTF-8.
		original := []byte{0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A}
		attrs := map[string][]string{"jpegPhoto": {string(original)}}

		got := attrRawValue(attrs, "jpegPhoto")
		require.Len(t, got, len(original))
		for i := range original {
			assert.Equal(t, original[i], got[i],
				"byte %d must be preserved exactly", i)
		}
	})
}

// ================== firstAttrRawValue ==================

func TestFirstAttrRawValue(t *testing.T) {
	t.Parallel()

	thumb := []byte{0xFF, 0xD8, 0xFF, 0xE0}
	jpeg := []byte{0xFF, 0xD8, 0xFF, 0xE1}

	tests := []struct {
		name  string
		attrs map[string][]string
		names []string
		want  []byte
	}{
		{
			name: "first present",
			attrs: map[string][]string{
				"thumbnailPhoto": {string(thumb)},
				"jpegPhoto":      {string(jpeg)},
			},
			names: []string{"thumbnailPhoto", "jpegPhoto"},
			want:  thumb,
		},
		{
			name: "first missing, second used",
			attrs: map[string][]string{
				"jpegPhoto": {string(jpeg)},
			},
			names: []string{"thumbnailPhoto", "jpegPhoto"},
			want:  jpeg,
		},
		{
			name: "first empty string, second used",
			attrs: map[string][]string{
				"thumbnailPhoto": {""},
				"jpegPhoto":      {string(jpeg)},
			},
			names: []string{"thumbnailPhoto", "jpegPhoto"},
			want:  jpeg,
			// Empty values are skipped, matching firstAttrValue semantics.
		},
		{
			name:  "none present",
			attrs: map[string][]string{},
			names: []string{"thumbnailPhoto", "jpegPhoto"},
			want:  nil,
		},
		{
			name: "empty names",
			attrs: map[string][]string{
				"jpegPhoto": {string(jpeg)},
			},
			names: nil,
			want:  nil,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, firstAttrRawValue(tt.attrs, tt.names))
		})
	}
}

// ================== contract cross-checks ==================

func TestHelpers_EmptyValueVsMissingAreDistinct(t *testing.T) {
	t.Parallel()

	// attrValue collapses "missing" and "empty" into "" — that's its
	// documented contract. attrRawValue keeps them distinct: nil vs
	// non-nil-empty. This test pins the difference so a future
	// "simplification" cannot silently break callers that rely on it.
	empty := map[string][]string{"photo": {""}}
	missing := map[string][]string{}

	assert.Equal(t, attrValue(empty, "photo"), attrValue(missing, "photo"),
		"string getters collapse empty and missing")
	assert.Nil(t, attrRawValue(missing, "photo"))
	assert.NotNil(t, attrRawValue(empty, "photo"))
}

func TestHelpers_FirstNonNullSkipsEmptyAcrossAlternatives(t *testing.T) {
	t.Parallel()

	// The MSAD photo fallback relies on exactly this: thumbnailPhoto may
	// be present but empty, and jpegPhoto must be picked up.
	attrs := map[string][]string{
		"thumbnailPhoto": {""},
		"jpegPhoto":      {"data"},
	}
	assert.Equal(t,
		"data",
		firstAttrValue(attrs, []string{"thumbnailPhoto", "jpegPhoto"}))
	assert.Equal(t,
		[]byte("data"),
		firstAttrRawValue(attrs, []string{"thumbnailPhoto", "jpegPhoto"}))
}
