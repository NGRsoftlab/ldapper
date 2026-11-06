// Copyright 2020-2026 NGR Softlab
package types

type LDAPGroup struct {
	DN         string
	Attributes map[string][]string
}

func (lg *LDAPGroup) GetAttributeValue(attribute string) string {
	return attrValue(lg.Attributes, attribute)
}

func (lg *LDAPGroup) GetFirstNonNullAttributeValue(alternatives []string) string {
	return firstAttrValue(lg.Attributes, alternatives)
}
