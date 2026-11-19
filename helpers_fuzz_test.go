// Copyright 2020-2026 NGR Softlab
package ldapper

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/go-ldap/ldap/v3"
)

// FuzzCanonicalDN_NoPanic — canonicalDN runs on server-returned DNs during
// tree construction. A panic here aborts the entire walk, so the only
// acceptable behaviour on arbitrary bytes is "return something".
func FuzzCanonicalDN_NoPanic(f *testing.F) {
	f.Add("cn=user,dc=example,dc=com")
	f.Add("CN=User,DC=Example,DC=Com")
	f.Add("cn=Smith\\, John,dc=x")
	f.Add("cn=a+sn=b,dc=x")
	f.Add("cn=a\\+b,dc=x")
	f.Add("not-a-dn")
	f.Add("")

	f.Fuzz(func(t *testing.T, dn string) {
		_ = canonicalDN(dn)
	})
}

// FuzzCanonicalDN_CaseEquivalence — the tree-linking contract in one line:
// case-differing representations of the same DN must produce the same key,
// otherwise entries land on the wrong parent or duplicate as roots.
func FuzzCanonicalDN_CaseEquivalence(f *testing.F) {
	f.Add("cn=user,dc=example,dc=com")
	f.Add("CN=User,DC=Example,DC=Com")
	f.Add("cn=Smith\\, John,dc=x")
	f.Add("cn=a+sn=b,dc=x")
	f.Add("cn=a\\2A,dc=x") // uppercase hex escape
	f.Add("not-a-dn")
	f.Add("")

	f.Fuzz(func(t *testing.T, dn string) {
		// strings.ToLower is not identity on invalid UTF-8. RFC 4511 permits
		// arbitrary bytes in DNs in theory, but no real server emits them;
		// skip rather than report a false positive.
		if !utf8.ValidString(dn) {
			return
		}
		got := canonicalDN(dn)
		want := canonicalDN(strings.ToLower(dn))
		if got != want {
			t.Fatalf("canonicalDN is not case-equivalent: dn=%q got=%q want=%q",
				dn, got, want)
		}
	})
}

// FuzzParentDNOf asserts the load-bearing property of parentDNOf: valid
// inputs with N>1 RDNs yield a parsable DN whose RDN list equals the
// original RDNs[1:]. Malformed inputs (and single-RDN valid DNs) yield "".
func FuzzParentDNOf(f *testing.F) {
	f.Add("cn=user,dc=example,dc=com")
	f.Add("dc=example")
	f.Add("")
	f.Add("not-a-dn")
	f.Add("cn=user,ou=sales+ou=east,dc=example")
	f.Add("cn=Smith\\, John,dc=example")

	f.Fuzz(func(t *testing.T, dn string) {
		parent := parentDNOf(dn)

		if dn == "" {
			if parent != "" {
				t.Fatalf("parentDNOf(%q) = %q; want \"\" for empty input", dn, parent)
			}
			return
		}

		parsed, err := ldap.ParseDN(dn)
		if err != nil {
			// Malformed input: parentDNOf falls back to "".
			if parent != "" {
				t.Fatalf("parentDNOf(%q) = %q; want \"\" for malformed DN", dn, parent)
			}
			return
		}

		if len(parsed.RDNs) <= 1 {
			if parent != "" {
				t.Fatalf("parentDNOf(%q) = %q; want \"\" for single-RDN DN", dn, parent)
			}
			return
		}

		// dn has >1 RDN. Parent must be a valid DN with len(RDNs)-1 RDNs,
		// and its RDN list must equal the original RDNs[1:].
		parentParsed, err := ldap.ParseDN(parent)
		if err != nil {
			t.Fatalf("parentDNOf(%q) = %q; parent does not parse: %v", dn, parent, err)
		}
		if want := len(parsed.RDNs) - 1; len(parentParsed.RDNs) != want {
			t.Fatalf("parentDNOf(%q) = %q; got %d RDNs, want %d",
				dn, parent, len(parentParsed.RDNs), want)
		}
		for i, rdn := range parentParsed.RDNs {
			origRDN := parsed.RDNs[i+1]
			if rdn.String() != origRDN.String() {
				t.Fatalf("parentDNOf(%q) = %q; RDN %d mismatch: got %q, want %q",
					dn, parent, i, rdn.String(), origRDN.String())
			}
		}
	})
}

// FuzzEscapeFilterArgs — filter-substitution contract: whatever a caller
// passes to GetUser/GetGroup/GetOU/... is escaped via ldap.EscapeFilter
// before substitution into the adapter template, and the result must be a
// valid RFC 4515 filter. A hole here is filter-injection.
func FuzzEscapeFilterArgs(f *testing.F) {
	f.Add("alice")
	f.Add("a*b(c)")
	f.Add(`a\b`)
	f.Add("\x00\x01")
	f.Add("")
	f.Add("\xff\xfe") // invalid UTF-8: filter values are byte strings

	f.Fuzz(func(t *testing.T, in string) {
		escaped := escapeFilterArgs([]any{in})
		if len(escaped) != 1 {
			t.Fatalf("escapeFilterArgs must return 1 element, got %d", len(escaped))
		}
		filter := fmt.Sprintf("(cn=%s)", escaped[0])
		if _, err := ldap.CompileFilter(filter); err != nil {
			t.Fatalf("escaped arg produced invalid filter: in=%q filter=%q err=%v",
				in, filter, err)
		}
	})
}

// FuzzValidateDN_SentinelContract — validateDN is the entry point for
// caller-supplied DNs. It must either accept the input or reject it with
// ErrInvalidArgument; any other error would silently bypass error handling
// in search methods that assume this contract.
func FuzzValidateDN_SentinelContract(f *testing.F) {
	f.Add("cn=x")
	f.Add("")
	f.Add("not-a-dn")
	f.Add("cn=a,,dc=x")
	f.Add("cn=Smith\\, John,dc=x")

	f.Fuzz(func(t *testing.T, dn string) {
		err := validateDN(dn)
		if err != nil && !errors.Is(err, ErrInvalidArgument) {
			t.Fatalf("validateDN(%q) returned non-sentinel error: %v", dn, err)
		}
	})
}

// FuzzValidateHost_SentinelContract — same contract for host strings. Host
// validation is a security boundary: a bypass would let a caller inject
// characters into the URI template that net.JoinHostPort cannot neutralise.
func FuzzValidateHost_SentinelContract(f *testing.F) {
	f.Add("example.com")
	f.Add("192.168.1.1")
	f.Add("::1")
	f.Add("")
	f.Add("bad/host")

	f.Fuzz(func(t *testing.T, host string) {
		err := validateHost(host)
		if err != nil && !errors.Is(err, ErrInvalidArgument) {
			t.Fatalf("validateHost(%q) returned non-sentinel error: %v", host, err)
		}
	})
}
