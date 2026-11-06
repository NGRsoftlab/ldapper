// Copyright 2020-2026 NGR Softlab
package types

// attrValue returns the first value of the named attribute, or ""
func attrValue(attrs map[string][]string, name string) string {
	if v := attrs[name]; len(v) > 0 {
		return v[0]
	}
	return ""
}

// firstAttrValue returns the first non-empty value of the named attribute, or ""
func firstAttrValue(attrs map[string][]string, names []string) string {
	for _, n := range names {
		if v := attrs[n]; len(v) > 0 && v[0] != "" {
			return v[0]
		}
	}
	return ""
}

// attrRawValue returns the first value of the named attribute as raw bytes,
// or nil if absent. Unlike attrValue it preserves non-UTF-8 content — use
// it for binary attributes (jpegPhoto, thumbnailPhoto, objectGUID, ...).
func attrRawValue(attrs map[string][]string, name string) []byte {
	if v := attrs[name]; len(v) > 0 {
		return []byte(v[0])
	}
	return nil
}

// firstAttrRawValue returns the first non-empty raw value from the given
// attribute alternatives, or nil if none.
func firstAttrRawValue(attrs map[string][]string, names []string) []byte {
	for _, n := range names {
		if v := attrs[n]; len(v) > 0 && v[0] != "" {
			return []byte(v[0])
		}
	}
	return nil
}
