// Copyright 2020-2026 NGR Softlab
package types

type LDAPOU struct {
	DN         string
	Attributes map[string][]string
}

func (lo *LDAPOU) GetAttributeValue(attribute string) string {
	return attrValue(lo.Attributes, attribute)
}

func (lo *LDAPOU) GetFirstNonNullAttributeValue(alternatives []string) string {
	return firstAttrValue(lo.Attributes, alternatives)
}
