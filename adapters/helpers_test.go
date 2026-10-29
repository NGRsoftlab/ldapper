// Copyright 2020-2026 NGR Softlab
package adapters

import (
	"github.com/NGRsoftlab/ldapper/types"
)

func newLDAPUser(dn string, attrs map[string][]string) types.LDAPUser {
	if attrs == nil {
		attrs = map[string][]string{}
	}
	return types.LDAPUser{DN: dn, Attributes: attrs}
}
