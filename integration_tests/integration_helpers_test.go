// Copyright 2020-2026 NGR Softlab
package ldapper_test

// Shared helpers for the *_integration_test.go suites.
//
// This file deliberately carries NO build tag, so the same helpers are
// available to every tagged suite (OpenLDAP / MSAD / FreeIPA / ALDPro)
// without duplication. Go compiles _test.go files without tags into the
// default `go test ./...` binary as well; that is safe here because the
// helpers import only the standard library and define no Test* functions.
//
// If a helper ever needs a third-party dependency (testify, ldap/v3, ...)
// or a production type, either move it into the tagged file that actually
// uses it, or gate it with the broadest relevant build tag — do not
// silently widen this file's dependency surface.

import "strings"

// containsDN reports whether any element of groups contains needle as a
// case-insensitive substring. Necessary because GetUserGroups returns
// full DNs whose attribute-type case varies across servers (AD commonly
// returns "CN=..." while OpenLDAP returns "cn=...").
func containsDN(groups []string, needle string) bool {
	needle = strings.ToLower(needle)
	for _, g := range groups {
		if strings.Contains(strings.ToLower(g), needle) {
			return true
		}
	}
	return false
}
