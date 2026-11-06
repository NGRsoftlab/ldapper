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
