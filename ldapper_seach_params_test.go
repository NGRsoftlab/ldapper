// Copyright 2020-2026 NGR Softlab
package ldapper

import (
	"testing"

	"github.com/go-ldap/ldap/v3"

	"github.com/NGRsoftlab/ldapper/constants"
)

func TestNormalizeSearchLimits(t *testing.T) {
	tests := []struct {
		name string
		in   SearchLimits
		want SearchLimits
	}{
		{"non-negative", SearchLimits{10, 20}, SearchLimits{10, 20}},
		{"negative size", SearchLimits{-1, 20}, SearchLimits{0, 20}},
		{"negative time", SearchLimits{10, -5}, SearchLimits{10, 0}},
		{"both negative", SearchLimits{-1, -5}, SearchLimits{0, 0}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := normalizeSearchLimits(tc.in); got != tc.want {
				t.Fatalf("got %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestWithSearchLimits(t *testing.T) {
	conn := &LDAPper{}
	WithSearchLimits(100, 60)(conn)
	if conn.searchLimits != (SearchLimits{100, 60}) {
		t.Fatalf("unexpected limits: %+v", conn.searchLimits)
	}
}

func TestWithSearchLimits_ClampsNegative(t *testing.T) {
	conn := &LDAPper{}
	WithSearchLimits(-10, -20)(conn)
	if conn.searchLimits != (SearchLimits{0, 0}) {
		t.Fatalf("negative values must be clamped to zero, got %+v", conn.searchLimits)
	}
}

func TestSetAndGetSearchLimits(t *testing.T) {
	conn := &LDAPper{}
	conn.SetSearchLimits(42, 17)
	if got := conn.GetSearchLimits(); got != (SearchLimits{42, 17}) {
		t.Fatalf("unexpected limits: %+v", got)
	}
}

func TestSetSearchLimits_ClampsNegative(t *testing.T) {
	conn := &LDAPper{searchLimits: SearchLimits{5, 7}}
	conn.SetSearchLimits(-1, -1)
	if got := conn.GetSearchLimits(); got != (SearchLimits{0, 0}) {
		t.Fatalf("negative values must be clamped to zero, got %+v", got)
	}
}

// TestNewSearchRequest_PropagatesAllFields ensures newSearchRequest wires every
// argument plus the connection limits into the resulting *ldap.SearchRequest.
func TestNewSearchRequest_PropagatesAllFields(t *testing.T) {
	conn := &LDAPper{searchLimits: SearchLimits{SizeLimit: 100, TimeLimit: 60}}

	req := conn.newSearchRequest(
		"dc=x", ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		false, "(cn=*)", []string{"cn", "mail"}, nil,
	)

	if req.BaseDN != "dc=x" {
		t.Errorf("BaseDN: %s", req.BaseDN)
	}
	if req.Scope != ldap.ScopeWholeSubtree {
		t.Errorf("Scope: %d", req.Scope)
	}
	if req.DerefAliases != ldap.NeverDerefAliases {
		t.Errorf("DerefAliases: %d", req.DerefAliases)
	}
	if req.TypesOnly {
		t.Error("TypesOnly must be false")
	}
	if req.Filter != "(cn=*)" {
		t.Errorf("Filter: %s", req.Filter)
	}
	if req.SizeLimit != 100 || req.TimeLimit != 60 {
		t.Errorf("limits: size=%d time=%d", req.SizeLimit, req.TimeLimit)
	}
	if len(req.Attributes) != 2 {
		t.Errorf("Attributes: %v", req.Attributes)
	}
}

// TestNewSearchRequest_UsesLiveLimits verifies that newSearchRequest picks up
// the current connection limits, including after a SetSearchLimits call.
func TestNewSearchRequest_UsesLiveLimits(t *testing.T) {
	conn := &LDAPper{searchLimits: SearchLimits{
		SizeLimit: constants.DefaultSearchSizeLimit,
		TimeLimit: constants.DefaultSearchTimeLimit,
	}}

	before := conn.newSearchRequest("dc=x", ldap.ScopeBaseObject, ldap.NeverDerefAliases, false, "(objectClass=*)", nil, nil)
	if before.SizeLimit != constants.DefaultSearchSizeLimit || before.TimeLimit != constants.DefaultSearchTimeLimit {
		t.Fatalf("unexpected defaults: %+v", before)
	}

	conn.SetSearchLimits(7, 8)
	after := conn.newSearchRequest("dc=x", ldap.ScopeBaseObject, ldap.NeverDerefAliases, false, "(objectClass=*)", nil, nil)
	if after.SizeLimit != 7 || after.TimeLimit != 8 {
		t.Fatalf("updated limits not applied: %+v", after)
	}
}
