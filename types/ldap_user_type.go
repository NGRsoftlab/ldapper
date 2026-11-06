// Copyright 2020-2026 NGR Softlab
package types

type LDAPUser struct {
	DN         string              // distinguished Name of the user
	Attributes map[string][]string // map of attributes retrieved for the user
}

func (lu *LDAPUser) GetAttributeValue(attribute string) string {
	return attrValue(lu.Attributes, attribute)
}

func (lu *LDAPUser) GetFirstNonNullAttributeValue(alternatives []string) string {
	return firstAttrValue(lu.Attributes, alternatives)
}

// GetAttributeRawValue returns the first value of the named attribute as
// raw bytes. Use for binary attributes; GetAttributeValue returns a string
// and is lossy for non-UTF-8 content.
func (lu *LDAPUser) GetAttributeRawValue(attribute string) []byte {
	return attrRawValue(lu.Attributes, attribute)
}

// GetFirstNonNullAttributeRawValue returns the first non-empty raw value
// from the given attribute alternatives, or nil.
func (lu *LDAPUser) GetFirstNonNullAttributeRawValue(alternatives []string) []byte {
	return firstAttrRawValue(lu.Attributes, alternatives)
}
