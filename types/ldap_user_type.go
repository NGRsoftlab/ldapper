// Copyright 2020-2026 NGR Softlab
package types

type LDAPUser struct {
	DN         string              // distinguished Name of the user
	Attributes map[string][]string // map of attributes retrieved for the user
}

func (lu *LDAPUser) GetAttributeValue(attribute string) string {
	temp := lu.Attributes[attribute]
	if len(temp) == 0 {
		return ""
	}

	return temp[0]
}

func (lu *LDAPUser) GetFirstNonNullAttributeValue(alternatives []string) string {
	for _, alternative := range alternatives {
		temp := lu.Attributes[alternative]
		if len(temp) == 0 {
			continue
		}
		if temp[0] != "" {
			return temp[0]
		}
	}

	return ""
}
