//go:build integration_aldpro
// +build integration_aldpro

package ldapper_test

// ALDPro (Astra Linux Directory Pro) integration tests.
//
// ALDPro is a commercial Russian directory service built on FreeIPA/389ds
// with schema extensions. No public Docker image exists, so this suite runs
// against stock osixia/openldap augmented with a custom schema that mirrors
// the ALDPro-specific pieces exercised by ALDPROAdapter.
//
// Schema design (matters for the tests):
//
//   - attributetype rbtadp        — department analogue (MAY on users and
//                                   on containers).
//   - objectClass   rbta-org-unit — container class using cn as its naming
//                                   attribute. Deliberately does NOT inherit
//                                   from organizationalUnit (which would
//                                   force ou as a MUST and forbid cn), so
//                                   this exercises the ou→cn fallback in
//                                   ALDPROAdapter.GetNormalizedOUInfoFromEntry.
//   - objectClass   rbta-user     — auxiliary class carrying rbtadp on users.
//
// ALDROAdapter group filter (two positional args — member/memberIndirect by
// DN, memberUid by uid):
//
//   (|(&(|(objectClass=groupOfNames)(objectClass=ipaUserGroup)(objectClass=posixGroup))
//       (|(member=%[1]s)(memberIndirect=%[1]s)))
//     (&(objectClass=posixGroup)(memberUid=%[2]s)))
//   args = [user.DN, user.uid].
//
// ALDROAdapter does NOT implement PrimaryGroupResolver — GetUserGroups
// returns only membership-based groups.
//
// Auth-path / ACL note:
//   osixia/openldap ships with `olcAccess: to * by * none` for non-admin
//   identities — only the root DN reads. On a non-root bind, a search under
//   the base DN returns LDAP Result Code 32 (noSuchObject) rather than an
//   "insufficient access" error, because every entry is hidden from the
//   reader. Tests exercise BindConn and GetUser from a real
//   authenticated non-root identity (svc-reader), so the suite replaces the
//   default ACL through cn=config right after startup with the standard
//   two-rule layout:
//
//     {0}to attrs=userPassword by self write by anonymous auth by * none
//     {1}to * by self read by users read by * none
//
//   The first rule is what makes Simple Bind possible at all: the server
//   compares userPassword as an *anonymous* identity (the bind has not
//   completed yet), so it needs `auth` — not `read` — on that attribute
//   for anonymous. A single `to * by * none` rule (tried in an earlier
//   iteration) blocks that anonymous comparison and every non-root bind
//   fails with LDAP Result Code 49 "Invalid Credentials". The second rule
//   lets authenticated non-admins read the tree, which is what
//   BindConn's base-DN probe and GetUser require.
//
//   Without this the auth-path searches would all fail with ErrNotFound
//   even though the data is present.
//
// Run with:
//   go test -tags=integration_aldpro ./...

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/NGRsoftlab/ldapper"
	"github.com/NGRsoftlab/ldapper/adapters"
	"github.com/NGRsoftlab/ldapper/constants"
	"github.com/NGRsoftlab/ldapper/interfaces"
	"github.com/NGRsoftlab/ldapper/types"
)

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const (
	aldproBaseDN    = "dc=aldpro,dc=test"
	aldproAdminDN   = "cn=admin,dc=aldpro,dc=test"
	aldproAdminPass = "adminpassword"

	// cn=admin,cn=config is the config-DB administrator. osixia creates it
	// with LDAP_CONFIG_PASSWORD when set, otherwise falls back to
	// LDAP_ADMIN_PASSWORD. The suite sets LDAP_CONFIG_PASSWORD explicitly so
	// this DN is deterministic; applyALDProACL binds as it to rewrite
	// olcAccess.
	aldproConfigDN = "cn=admin,cn=config"

	aldproUser1DN   = "cn=user1,ou=users,dc=aldpro,dc=test"
	aldproUser1UID  = "user1"
	aldproUser1Pass = "password1"

	aldproUser2DN   = "cn=user2,ou=users,dc=aldpro,dc=test"
	aldproUser2UID  = "user2"
	aldproUser2Pass = "password2"

	// svc-reader is a real inetOrgPerson used for authenticated binds — the
	// osixia admin is a simpleSecurityObject that UserFilter does not match.
	aldproSvcUID  = "svc-reader"
	aldproSvcPass = "svcpassword"
	aldproSvcDN   = "cn=svc-reader,ou=users,dc=aldpro,dc=test"

	// ALDPro-specific container: cn-named rbta-org-unit, no ou attribute.
	// Exercises the ou→cn fallback in GetNormalizedOUInfoFromEntry and the
	// cn= arm of SearchOUFilterTemplate.
	aldproDepartmentsDN = "cn=departments,dc=aldpro,dc=test"
)

// aldproSchema mirrors ALDPro-specific schema extensions. OIDs use the
// private enterprise placeholder; they need only to be unique inside the
// ephemeral test instance, not to match real ALDPro OIDs.
//
// rbta-org-unit intentionally does NOT inherit from organizationalUnit: real
// ALDPro containers use cn for naming (like FreeIPA's nsContainer), and this
// suite exists in part to exercise that fallback.
const aldproSchema = `attributetype ( 1.3.6.1.4.1.99999.1.1
    NAME 'rbtadp'
    DESC 'ALDPro department attribute'
    EQUALITY caseIgnoreMatch
    SUBSTR caseIgnoreSubstringsMatch
    SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{256} )

objectclass ( 1.3.6.1.4.1.99999.2.1
    NAME 'rbta-org-unit'
    DESC 'ALDPro organizational unit (cn-named container)'
    SUP top
    STRUCTURAL
    MUST cn
    MAY ( ou $ rbtadp $ description ) )

objectclass ( 1.3.6.1.4.1.99999.2.2
    NAME 'rbta-user'
    DESC 'ALDPro user extensions'
    SUP top
    AUXILIARY
    MAY ( rbtadp ) )
`

var (
	aldproHost string
	aldproPort uint
	aldproAdpt = adapters.ALDPROAdapter{}
)

func TestMain(m *testing.M) {
	ctx := context.Background()

	// Only schema is mounted: it must be present when slapd starts, so it
	// goes through osixia's bootstrap/schema/custom path. Data is seeded
	// from Go after the port is listening (see seedALDPro).
	tmpDir, err := os.MkdirTemp("", "ldapper-aldpro-*")
	if err != nil {
		fmt.Fprintf(os.Stderr, "cannot create temp dir: %v\n", err)
		os.Exit(1)
	}
	defer os.RemoveAll(tmpDir)

	schemaDir := filepath.Join(tmpDir, "schema")
	if err := os.MkdirAll(schemaDir, 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "cannot create schema dir: %v\n", err)
		os.Exit(1)
	}
	if err := os.WriteFile(filepath.Join(schemaDir, "99-aldpro.schema"),
		[]byte(aldproSchema), 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "cannot write schema: %v\n", err)
		os.Exit(1)
	}

	req := testcontainers.ContainerRequest{
		Image:        "osixia/openldap:1.5.0",
		ExposedPorts: []string{"389/tcp"},
		Cmd:          []string{"--copy-service"},
		Env: map[string]string{
			"LDAP_ORGANISATION":   "ALDPro Test",
			"LDAP_DOMAIN":         "aldpro.test",
			"LDAP_ADMIN_PASSWORD": aldproAdminPass,
			// LDAP_CONFIG_PASSWORD makes cn=admin,cn=config's password
			// deterministic. applyALDProACL binds as that DN to rewrite
			// olcAccess; without it osixia's fallback behaviour is
			// undocumented and varies between releases.
			"LDAP_CONFIG_PASSWORD":           aldproAdminPass,
			"LDAP_TLS":                       "false",
			"DISABLE_CHOWN":                  "true",
			"LDAP_REMOVE_CONFIG_AFTER_SETUP": "false",
		},
		Mounts: testcontainers.ContainerMounts{
			{
				Source: testcontainers.GenericBindMountSource{HostPath: schemaDir},
				Target: testcontainers.ContainerMountTarget(
					"/container/service/slapd/assets/config/bootstrap/schema/custom",
				),
			},
		},
		// Wait for the LDAP port. On osixia/openldap:1.5.0 the "slapd
		// starting" log line is emitted only once — by the final serving
		// slapd, after bootstrap LDIFs have been applied. The bootstrap
		// slapd (temp mdb, ldapi:/// only) logs "Waiting for OpenLDAP to
		// start..." instead, so wait.ForLog would match the final phase
		// anyway; ForListeningPort is simpler and equivalent here.
		WaitingFor: wait.ForListeningPort("389/tcp").WithStartupTimeout(120 * time.Second),
	}

	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "cannot start OpenLDAP for ALDPro tests: %v\n", err)
		os.Exit(1)
	}

	aldproHost, err = container.Host(ctx)
	if err != nil {
		_ = container.Terminate(ctx)
		fmt.Fprintf(os.Stderr, "cannot resolve host: %v\n", err)
		os.Exit(1)
	}

	mappedPort, err := container.MappedPort(ctx, "389")
	if err != nil {
		_ = container.Terminate(ctx)
		fmt.Fprintf(os.Stderr, "cannot resolve port: %v\n", err)
		os.Exit(1)
	}
	aldproPort = uint(mappedPort.Num())

	if !waitForALDProReady(aldproHost, aldproPort, 60*time.Second) {
		_ = container.Terminate(ctx)
		fmt.Fprintln(os.Stderr, "OpenLDAP (ALDPro) admin bind did not succeed within 60s")
		os.Exit(1)
	}

	// The port can accept connections slightly before the custom schema is
	// fully loaded (schema and slapd startup are independent). Poll the
	// subschema until rbta-org-unit is visible, otherwise seeding the
	// cn=departments entry would fail with ObjectClassViolation.
	if !waitForALDProSchema(aldproHost, aldproPort, 60*time.Second) {
		_ = container.Terminate(ctx)
		fmt.Fprintln(os.Stderr, "rbta-org-unit not present in subschema after 60s")
		os.Exit(1)
	}

	// Grant read access to authenticated identities. See the top-of-file
	// note: osixia defaults to `to * by * none` for non-root, which makes
	// every authenticated search return noSuchObject rather than
	// insufficientAccess. Must run before seeding so the admin seed
	// (which is the root identity) is unaffected but subsequent tests can
	// search as svc-reader.
	if err := applyALDProACL(aldproHost, aldproPort); err != nil {
		_ = container.Terminate(ctx)
		fmt.Fprintf(os.Stderr, "cannot apply ALDPro ACL: %v\n", err)
		os.Exit(1)
	}

	if err := seedALDPro(aldproHost, aldproPort); err != nil {
		_ = container.Terminate(ctx)
		fmt.Fprintf(os.Stderr, "cannot seed ALDPro entries: %v\n", err)
		os.Exit(1)
	}

	// Sanity check: verify each step of the search path independently so
	// that a failure here names the exact subsystem (base visibility,
	// svc-reader bind, subtree scope, entryDN filter) rather than
	// surfacing later as an opaque ErrNotFound from within BindConn.
	if err := verifyALDProState(); err != nil {
		_ = container.Terminate(ctx)
		fmt.Fprintf(os.Stderr, "ALDPro post-seed verification failed: %v\n", err)
		os.Exit(1)
	}

	code := m.Run()
	_ = container.Terminate(ctx)
	os.Exit(code)
}

// applyALDProACL replaces the olcAccess on the user database. Two rules
// are needed:
//
//  1. userPassword — Simple Bind reads userPassword as an *anonymous*
//     identity: at the moment the server verifies the password, the bind
//     has not completed yet, so the session carries no authenticated
//     identity. Without `by anonymous auth` on this attribute, every
//     Simple Bind returns LDAP Result Code 49 "Invalid Credentials" even
//     though the stored hash matches. Note: `auth` (not `read`) — bind
//     only needs to compare, not to return the value.
//
//  2. Everything else — read for any authenticated identity. This is what
//     BindConn and GetUser require when the bind identity is a
//     non-root user.
//
// Anonymous is denied everything except the `auth` check on userPassword.
// Admin (rootDN cn=admin,dc=aldpro,dc=test) bypasses ACLs entirely, so
// seeding and the reconnect-rebind test work regardless of these rules.
func applyALDProACL(host string, port uint) error {
	c, err := ldap.DialURL(fmt.Sprintf("ldap://%s:%d", host, port))
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	defer c.Close()

	if err := c.Bind(aldproConfigDN, aldproAdminPass); err != nil {
		return fmt.Errorf("config bind as %q: %w", aldproConfigDN, err)
	}

	// {1}mdb is osixia's user database for a single-domain setup; {0} is
	// the frontend/config container. If a future image changes the index,
	// this will fail loudly rather than silently applying ACL to nothing.
	modify := ldap.NewModifyRequest("olcDatabase={1}mdb,cn=config", nil)
	modify.Replace("olcAccess", []string{
		"{0}to attrs=userPassword by self write by anonymous auth by * none",
		"{1}to * by self read by users read by * none",
	})
	if err := c.Modify(modify); err != nil {
		return fmt.Errorf("set olcAccess on olcDatabase={1}mdb: %w", err)
	}
	return nil
}

// waitForALDProSchema polls the subschema until rbta-org-unit is present.
// The port is open before the schema reload finishes, so timing the wait on
// the port alone would race. Polling for the class name (or its OID, in case
// the server returns a numeric form) removes the race.
func waitForALDProSchema(host string, port uint, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		c, err := ldap.DialURL(fmt.Sprintf("ldap://%s:%d", host, port))
		if err == nil {
			if bindErr := c.Bind(aldproAdminDN, aldproAdminPass); bindErr == nil {
				req := ldap.NewSearchRequest(
					"cn=Subschema", ldap.ScopeBaseObject, ldap.NeverDerefAliases,
					1, 0, false, "(objectClass=subschema)",
					[]string{"objectClasses"}, nil,
				)
				res, searchErr := c.Search(req)
				_ = c.Close()
				if searchErr == nil && len(res.Entries) > 0 {
					for _, cls := range res.Entries[0].GetAttributeValues("objectClasses") {
						if strings.Contains(cls, "rbta-org-unit") ||
							strings.Contains(cls, "1.3.6.1.4.1.99999.2.1") {
							return true
						}
					}
				}
			} else {
				_ = c.Close()
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	return false
}

func waitForALDProReady(host string, port uint, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		c, err := ldap.DialURL(fmt.Sprintf("ldap://%s:%d", host, port))
		if err == nil {
			bindErr := c.Bind(aldproAdminDN, aldproAdminPass)
			_ = c.Close()
			if bindErr == nil {
				return true
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	return false
}

// seedALDPro creates every entry the tests depend on. Idempotent: entries
// that already exist are skipped, so re-running against the same container
// is safe.
func seedALDPro(host string, port uint) error {
	c, err := ldap.DialURL(fmt.Sprintf("ldap://%s:%d", host, port))
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	defer c.Close()
	if err := c.Bind(aldproAdminDN, aldproAdminPass); err != nil {
		return fmt.Errorf("bind: %w", err)
	}

	entries := []struct {
		dn    string
		attrs map[string][]string
	}{
		{"ou=users," + aldproBaseDN, map[string][]string{
			"objectClass": {"organizationalUnit"},
			"ou":          {"users"},
		}},
		{aldproDepartmentsDN, map[string][]string{
			"objectClass": {"rbta-org-unit"},
			"cn":          {"departments"},
			"rbtadp":      {"Department Container"},
			"description": {"ALDPro-specific cn-named container"},
		}},
		{"ou=groups," + aldproBaseDN, map[string][]string{
			"objectClass": {"organizationalUnit"},
			"ou":          {"groups"},
		}},
		{aldproUser1DN, map[string][]string{
			"objectClass":   {"inetOrgPerson", "posixAccount", "rbta-user"},
			"cn":            {"user1"},
			"sn":            {"User"},
			"uid":           {aldproUser1UID},
			"uidNumber":     {"1001"},
			"gidNumber":     {"1001"},
			"homeDirectory": {"/home/user1"},
			"userPassword":  {aldproUser1Pass},
			"mail":          {"user1@aldpro.test"},
			"rbtadp":        {"Engineering"},
		}},
		{aldproUser2DN, map[string][]string{
			"objectClass":   {"inetOrgPerson", "posixAccount", "rbta-user"},
			"cn":            {"user2"},
			"sn":            {"User"},
			"uid":           {aldproUser2UID},
			"uidNumber":     {"1002"},
			"gidNumber":     {"1002"},
			"homeDirectory": {"/home/user2"},
			"userPassword":  {aldproUser2Pass},
			"mail":          {"user2@aldpro.test"},
			"rbtadp":        {"Sales"},
		}},
		{aldproSvcDN, map[string][]string{
			"objectClass":   {"inetOrgPerson", "posixAccount", "rbta-user"},
			"cn":            {"svc-reader"},
			"sn":            {"Reader"},
			"uid":           {aldproSvcUID},
			"uidNumber":     {"1099"},
			"gidNumber":     {"1099"},
			"homeDirectory": {"/home/svc-reader"},
			"userPassword":  {aldproSvcPass},
			"mail":          {"svc-reader@aldpro.test"},
			"rbtadp":        {"IT"},
		}},
		{"cn=admins,ou=groups," + aldproBaseDN, map[string][]string{
			"objectClass": {"groupOfNames"},
			"cn":          {"admins"},
			"member":      {aldproUser1DN},
		}},
		{"cn=readers,ou=groups," + aldproBaseDN, map[string][]string{
			"objectClass": {"posixGroup"},
			"cn":          {"readers"},
			"gidNumber":   {"2001"},
			"memberUid":   {aldproUser2UID},
		}},
	}

	for _, e := range entries {
		_, err := c.Search(ldap.NewSearchRequest(
			e.dn, ldap.ScopeBaseObject, ldap.NeverDerefAliases,
			1, 0, false, "(objectClass=*)", []string{"1.1"}, nil))
		if err == nil {
			continue // already present
		}
		if !ldap.IsErrorWithCode(err, ldap.LDAPResultNoSuchObject) {
			return fmt.Errorf("search %s: %w", e.dn, err)
		}

		req := ldap.NewAddRequest(e.dn, nil)
		for name, values := range e.attrs {
			req.Attribute(name, values)
		}
		if err := c.Add(req); err != nil {
			return fmt.Errorf("add %s: %w", e.dn, err)
		}
	}
	return nil
}

// verifyALDProState checks that every LDAP operation the test suite relies
// on works from the perspective of both the admin and svc-reader. When a
// step fails, the error identifies exactly which one, so the next debugging
// round does not need to guess (base not visible / svc-reader bind rejected
// / subtree scope broken / entryDN filter rejected / ACL hides the tree).
func verifyALDProState() error {
	dial := func() (*ldap.Conn, error) {
		return ldap.DialURL(fmt.Sprintf("ldap://%s:%d", aldproHost, aldproPort))
	}

	// 1) Admin can see the base object itself.
	c1, err := dial()
	if err != nil {
		return fmt.Errorf("admin dial: %w", err)
	}
	defer c1.Close()
	if err := c1.Bind(aldproAdminDN, aldproAdminPass); err != nil {
		return fmt.Errorf("admin bind: %w", err)
	}
	if _, err := c1.Search(ldap.NewSearchRequest(
		aldproBaseDN, ldap.ScopeBaseObject, ldap.NeverDerefAliases,
		0, 30, false, "(objectClass=*)", []string{"dn"}, nil,
	)); err != nil {
		return fmt.Errorf("admin base search at %q: %w", aldproBaseDN, err)
	}

	// 2) Admin can see the svc-reader entry that was just seeded.
	res, err := c1.Search(ldap.NewSearchRequest(
		aldproSvcDN, ldap.ScopeBaseObject, ldap.NeverDerefAliases,
		0, 30, false, "(objectClass=*)", []string{"cn"}, nil,
	))
	if err != nil {
		return fmt.Errorf("admin svc-reader search at %q: %w", aldproSvcDN, err)
	}
	if len(res.Entries) == 0 {
		return fmt.Errorf("admin search: svc-reader entry %q not present after seed", aldproSvcDN)
	}

	// 3) svc-reader can bind with the seeded password.
	c2, err := dial()
	if err != nil {
		return fmt.Errorf("svc-reader dial: %w", err)
	}
	defer c2.Close()
	if err := c2.Bind(aldproSvcDN, aldproSvcPass); err != nil {
		return fmt.Errorf("svc-reader bind: %w", err)
	}

	// 4) svc-reader can search the base subtree with a simple filter
	// (no entryDN, no compound objectClass union). Fails with noSuchObject
	// if the ACL did not take effect — osixia maps "hidden" to code 32.
	if _, err := c2.Search(ldap.NewSearchRequest(
		aldproBaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		0, 30, false, "(objectClass=inetOrgPerson)", []string{"cn"}, nil,
	)); err != nil {
		return fmt.Errorf("svc-reader simple subtree search: %w", err)
	}

	// 5) svc-reader can search with the adapter's actual user filter.
	// This is the exact filter that GetUser → searchSingleEntryLocked issues;
	// if it fails here, the adapter template (entryDN arm, objectClass
	// union) is what breaks user lookups.
	tmpl := aldproAdpt.SearchUserFilterTemplate()
	filter := fmt.Sprintf(tmpl, ldap.EscapeFilter(aldproSvcDN))
	if _, err := c2.Search(ldap.NewSearchRequest(
		aldproBaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		2, 30, false, filter, aldproAdpt.UserAttrs(), nil,
	)); err != nil {
		return fmt.Errorf("svc-reader adapter-filter search failed (filter=%q): %w", filter, err)
	}

	// 6) Admin subtree enumeration: seed must have landed in the serving
	// slapd. If this fails or yields < 8 entries, the entries were written
	// to the bootstrap-phase slapd and discarded when the final slapd
	// started.
	const expectedMinEntries = 8 // base + 3 OUs + 3 users + 2 groups + departments
	all, err := c1.Search(ldap.NewSearchRequest(
		aldproBaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		0, 30, false, "(objectClass=*)", []string{"dn"}, nil,
	))
	if err != nil {
		return fmt.Errorf("admin subtree enumeration at %q: %w", aldproBaseDN, err)
	}
	if len(all.Entries) < expectedMinEntries {
		got := make([]string, 0, len(all.Entries))
		for _, e := range all.Entries {
			got = append(got, e.DN)
		}
		return fmt.Errorf(
			"admin sees only %d entries under %q (expected >= %d after seed): %v — "+
				"seed likely landed in the bootstrap-phase slapd and was discarded",
			len(all.Entries), aldproBaseDN, expectedMinEntries, got)
	}

	// 7) svc-reader subtree visibility: rules out an ACL masking the base
	// tree for authenticated non-admin identities. Insufficient access
	// shows up as noSuchObject (32) on some OpenLDAP builds, so this step
	// distinguishes "data missing" from "data present but hidden".
	sAll, err := c2.Search(ldap.NewSearchRequest(
		aldproBaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		0, 30, false, "(objectClass=*)", []string{"dn"}, nil,
	))
	if err != nil {
		return fmt.Errorf(
			"svc-reader subtree enumeration at %q failed (ACL visibility?): %w",
			aldproBaseDN, err)
	}
	if len(sAll.Entries) == 0 {
		return fmt.Errorf(
			"svc-reader sees 0 entries under %q while admin sees %d — "+
				"ACL hides the base tree from authenticated non-admin identities; "+
				"check that applyALDProACL set olcAccess on olcDatabase={1}mdb",
			aldproBaseDN, len(all.Entries))
	}

	return nil
}

func containsDN(groups []string, needle string) bool {
	needle = strings.ToLower(needle)
	for _, g := range groups {
		if strings.Contains(strings.ToLower(g), needle) {
			return true
		}
	}
	return false
}

func newALDProConn(t *testing.T, opts ...ldapper.Option) *ldapper.LDAPper {
	t.Helper()
	conn, err := ldapper.NewLDAPper(
		context.Background(),
		[]string{aldproHost}, aldproPort,
		false, true, nil,
		aldproAdpt,
		opts...,
	)
	require.NoError(t, err)
	t.Cleanup(conn.Close)
	return conn
}

func newALDProAuthConn(t *testing.T, opts ...ldapper.Option) *ldapper.LDAPper {
	t.Helper()
	conn, _, err := ldapper.NewAuthenticatedLDAPper(
		context.Background(),
		aldproSvcDN, aldproSvcPass, aldproBaseDN,
		[]string{aldproHost}, aldproPort,
		false, true, nil,
		aldproAdpt,
		opts...,
	)
	require.NoError(t, err)
	t.Cleanup(conn.Close)
	return conn
}

// ================== adapter contract (no server needed) ==================

// ALDROAdapter group template uses TWO positional args:
// member/memberIndirect (%[1]s = DN) and memberUid (%[2]s = uid).
func TestIntegrationALDPro_SearchUserGroupsFilterTemplate_TwoArgs(t *testing.T) {
	tmpl := aldproAdpt.SearchUserGroupsFilterTemplate()

	assert.Contains(t, tmpl, "member=%[1]s")
	assert.Contains(t, tmpl, "memberIndirect=%[1]s",
		"ALDPro supports nested group membership via memberIndirect")
	assert.Contains(t, tmpl, "memberUid=%[2]s")
	assert.NotContains(t, tmpl, "member=uid=",
		"filter must not hard-code uid= prefix on member")
	assert.NotContains(t, tmpl, "%[3]s",
		"only two positional arguments are supported")
}

func TestIntegrationALDPro_SearchUserGroupsFilterTemplateArgs_ReturnsDNThenUID(t *testing.T) {
	const dn = "cn=user1,ou=users,dc=aldpro,dc=test"
	user := types.LDAPUser{
		DN:         dn,
		Attributes: map[string][]string{"uid": {"user1"}},
	}
	args := aldproAdpt.SearchUserGroupsFilterTemplateArgs(user)
	require.Len(t, args, 2)
	require.Equal(t, dn, args[0], "arg 0 (DN) feeds member/memberIndirect")
	require.Equal(t, "user1", args[1], "arg 1 (uid) feeds memberUid")
}

// ALDROAdapter must not implement PrimaryGroupResolver: there is no
// primaryGroupID concept in the ALDPro schema.
var _ = func() any {
	var c any = adapters.ALDPROAdapter{}
	if _, ok := c.(interfaces.PrimaryGroupResolver); ok {
		panic("ALDPROAdapter must not implement PrimaryGroupResolver")
	}
	return nil
}()

// ================== constructor validation ==================

func TestIntegrationALDPro_NewConnection_Success(t *testing.T) {
	conn := newALDProConn(t)
	assert.True(t, conn.IsAlive(context.Background()))
}

func TestIntegrationALDPro_NewConnection_EmptyHosts(t *testing.T) {
	_, err := ldapper.NewLDAPper(context.Background(),
		nil, 389, false, true, nil, aldproAdpt)
	require.Error(t, err)
	assert.ErrorIs(t, err, ldapper.ErrInvalidArgument)
}

func TestIntegrationALDPro_NewConnection_TooManyHosts(t *testing.T) {
	hosts := make([]string, constants.DefaultMaxHostsLength+1)
	for i := range hosts {
		hosts[i] = fmt.Sprintf("host%d", i)
	}
	_, err := ldapper.NewLDAPper(context.Background(),
		hosts, 389, false, true, nil, aldproAdpt)
	require.Error(t, err)
	assert.ErrorIs(t, err, ldapper.ErrInvalidArgument)
}

func TestIntegrationALDPro_NewConnection_NilTLSConfigWhenRequired(t *testing.T) {
	_, err := ldapper.NewLDAPper(context.Background(),
		[]string{aldproHost}, aldproPort, false, false, nil, aldproAdpt)
	require.Error(t, err)
	assert.ErrorIs(t, err, ldapper.ErrInvalidArgument)
}

func TestIntegrationALDPro_NewConnection_NilCatalogAdapter(t *testing.T) {
	_, err := ldapper.NewLDAPper(context.Background(),
		[]string{aldproHost}, aldproPort, false, true, nil, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, ldapper.ErrInvalidArgument)
}

func TestIntegrationALDPro_NewConnection_InvalidPort(t *testing.T) {
	_, err := ldapper.NewLDAPper(context.Background(),
		[]string{aldproHost}, 0, false, true, nil, aldproAdpt)
	require.Error(t, err)
	assert.ErrorIs(t, err, ldapper.ErrInvalidArgument)
}

func TestIntegrationALDPro_NewConnection_SSLWithSkipTLSRejected(t *testing.T) {
	_, err := ldapper.NewLDAPper(context.Background(),
		[]string{aldproHost}, 636, true, true, nil, aldproAdpt)
	require.Error(t, err)
	assert.ErrorIs(t, err, ldapper.ErrInvalidArgument)
}

func TestIntegrationALDPro_NewConnection_UnreachableHost(t *testing.T) {
	_, err := ldapper.NewLDAPper(context.Background(),
		[]string{"127.0.0.1"}, 1, false, true, nil, aldproAdpt)
	require.Error(t, err)
	assert.ErrorIs(t, err, ldapper.ErrUnavailable)
}

func TestIntegrationALDPro_NewAuthenticatedConnection_Success(t *testing.T) {
	conn, user, err := ldapper.NewAuthenticatedLDAPper(
		context.Background(),
		aldproSvcDN, aldproSvcPass, aldproBaseDN,
		[]string{aldproHost}, aldproPort, false, true, nil, aldproAdpt,
	)
	require.NoError(t, err)
	defer conn.Close()

	require.NotNil(t, user)
	assert.Equal(t, aldproSvcDN, user.DN)
}

func TestIntegrationALDPro_NewAuthenticatedConnection_EmptyCredentials(t *testing.T) {
	_, _, err := ldapper.NewAuthenticatedLDAPper(
		context.Background(), "", "", aldproBaseDN,
		[]string{aldproHost}, aldproPort, false, true, nil, aldproAdpt,
	)
	require.Error(t, err)
	assert.ErrorIs(t, err, ldapper.ErrInvalidArgument)
}

func TestIntegrationALDPro_NewAuthenticatedConnection_WrongPassword(t *testing.T) {
	_, _, err := ldapper.NewAuthenticatedLDAPper(
		context.Background(),
		aldproSvcDN, "wrong-password", aldproBaseDN,
		[]string{aldproHost}, aldproPort, false, true, nil, aldproAdpt,
	)
	require.Error(t, err)
	assert.ErrorIs(t, err, ldapper.ErrInvalidCredentials)
}

// ================== BindConn ==================

func TestIntegrationALDPro_BindConn_Success(t *testing.T) {
	conn := newALDProConn(t)

	user, err := conn.BindConn(context.Background(),
		aldproSvcDN, aldproSvcPass, aldproBaseDN)
	require.NoError(t, err)
	require.NotNil(t, user)
	assert.Equal(t, aldproSvcDN, user.DN)
}

func TestIntegrationALDPro_BindConn_EmptyCredentials(t *testing.T) {
	conn := newALDProConn(t)
	_, err := conn.BindConn(context.Background(), "", "", aldproBaseDN)
	require.Error(t, err)
	assert.ErrorIs(t, err, ldapper.ErrInvalidArgument)
}

func TestIntegrationALDPro_BindConn_WrongPassword(t *testing.T) {
	conn := newALDProConn(t)
	_, err := conn.BindConn(context.Background(),
		aldproSvcDN, "bad-password", aldproBaseDN)
	require.Error(t, err)
	assert.ErrorIs(t, err, ldapper.ErrInvalidCredentials)
	assert.NotContains(t, err.Error(), "bad-password",
		"submitted credentials must not echo back")
}

func TestIntegrationALDPro_BindConn_NonExistentUser(t *testing.T) {
	conn := newALDProConn(t)
	_, err := conn.BindConn(context.Background(),
		"cn=ghost,ou=users,"+aldproBaseDN, "whatever", aldproBaseDN)
	require.Error(t, err)
}

// ================== CheckUserCredentials ==================

func TestIntegrationALDPro_CheckUserCredentials_Success(t *testing.T) {
	conn := newALDProAuthConn(t)

	user, err := conn.CheckUserCredentials(context.Background(), aldproUser1UID, aldproUser1Pass)
	require.NoError(t, err)
	require.NotNil(t, user)
	assert.Equal(t, aldproUser1UID, user.GetAttributeValue("uid"))
}

func TestIntegrationALDPro_CheckUserCredentials_WrongPassword(t *testing.T) {
	conn := newALDProAuthConn(t)

	user, err := conn.CheckUserCredentials(context.Background(), aldproUser1UID, "bad")
	require.Error(t, err)
	assert.ErrorIs(t, err, ldapper.ErrInvalidCredentials)
	assert.Nil(t, user)
}

func TestIntegrationALDPro_CheckUserCredentials_NonExistentUser(t *testing.T) {
	conn := newALDProAuthConn(t)

	user, err := conn.CheckUserCredentials(context.Background(), "ghost-user", "whatever")
	require.Error(t, err)
	assert.ErrorIs(t, err, ldapper.ErrInvalidCredentials,
		"missing user must be masked as invalid credentials (enumeration protection)")
	assert.Nil(t, user)
}

func TestIntegrationALDPro_CheckUserCredentials_NotAuthenticated(t *testing.T) {
	conn := newALDProConn(t)
	_, err := conn.CheckUserCredentials(context.Background(), aldproUser1UID, aldproUser1Pass)
	require.Error(t, err)
	assert.ErrorIs(t, err, ldapper.ErrNotAuthenticated)
}

func TestIntegrationALDPro_CheckUserCredentials_EmptyCredentials(t *testing.T) {
	conn := newALDProAuthConn(t)
	_, err := conn.CheckUserCredentials(context.Background(), "", "")
	require.Error(t, err)
	assert.ErrorIs(t, err, ldapper.ErrInvalidArgument)
}

// ================== IsAlive / Reconnect / EnsureAlive / Close ==================

func TestIntegrationALDPro_IsAlive_ActiveConnection(t *testing.T) {
	conn := newALDProConn(t)
	assert.True(t, conn.IsAlive(context.Background()))
}

func TestIntegrationALDPro_IsAlive_AfterClose(t *testing.T) {
	conn := newALDProConn(t)
	conn.Close()
	assert.False(t, conn.IsAlive(context.Background()))
}

func TestIntegrationALDPro_Reconnect_Unauthenticated(t *testing.T) {
	conn := newALDProConn(t)
	require.True(t, conn.IsAlive(context.Background()))
	require.NoError(t, conn.Reconnect(context.Background()))
	assert.True(t, conn.IsAlive(context.Background()))
}

func TestIntegrationALDPro_Reconnect_PreservesAuthentication(t *testing.T) {
	conn := newALDProAuthConn(t)
	require.NoError(t, conn.Reconnect(context.Background()))

	_, err := conn.CheckUserCredentials(context.Background(), aldproUser1UID, aldproUser1Pass)
	require.NoError(t, err)
}

func TestIntegrationALDPro_EnsureAlive_NoopWhenAlive(t *testing.T) {
	conn := newALDProConn(t)
	require.NoError(t, conn.EnsureAlive(context.Background()))
	assert.True(t, conn.IsAlive(context.Background()))
}

// After Close the client is terminal: EnsureAlive reports ErrClosed instead
// of silently reconnecting.
func TestIntegrationALDPro_EnsureAlive_ClosedClient_ReturnsErrClosed(t *testing.T) {
	conn := newALDProAuthConn(t)
	conn.Close()
	require.False(t, conn.IsAlive(context.Background()))

	err := conn.EnsureAlive(context.Background())
	require.Error(t, err)
	assert.ErrorIs(t, err, ldapper.ErrClosed)
}

func TestIntegrationALDPro_Close_Idempotent(t *testing.T) {
	conn := newALDProConn(t)
	conn.Close()
	conn.Close() // must not panic

	_, err := conn.GetUser(context.Background(), aldproUser1UID, aldproBaseDN)
	require.Error(t, err)
	assert.ErrorIs(t, err, ldapper.ErrClosed)
}

// ================== CustomSearch ==================

func TestIntegrationALDPro_CustomSearch_UserLookup(t *testing.T) {
	conn := newALDProAuthConn(t)

	req := ldap.NewSearchRequest(
		aldproBaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		0, 0, false, "(uid=user1)",
		[]string{"cn", "mail", "rbtadp"},
		nil,
	)

	res, err := conn.CustomSearch(context.Background(), req)
	require.NoError(t, err)
	require.Len(t, res.Entries, 1)
	assert.Equal(t, aldproUser1DN, res.Entries[0].DN)
	assert.Equal(t, "Engineering", res.Entries[0].GetAttributeValue("rbtadp"))
}

func TestIntegrationALDPro_CustomSearch_OUFilterMatchesBothTypes(t *testing.T) {
	conn := newALDProAuthConn(t)

	req := ldap.NewSearchRequest(
		aldproBaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		0, 0, false,
		aldproAdpt.OUObjectFilter(),
		[]string{"ou", "cn", "objectClass"},
		nil,
	)

	res, err := conn.CustomSearch(context.Background(), req)
	require.NoError(t, err)

	// Use the adapter's normalization — GetAttributeValue("ou") alone would
	// miss rbta-org-unit containers, which have no ou and carry the name in
	// cn. This is exactly the fallback path exercised by the adapter.
	ous := make([]string, 0, len(res.Entries))
	for _, e := range res.Entries {
		info := aldproAdpt.GetNormalizedOUInfoFromEntry(*e)
		ous = append(ous, info.OU)
	}
	assert.Contains(t, ous, "users")
	assert.Contains(t, ous, "departments",
		"rbta-org-unit must match OUObjectFilter")
	assert.Contains(t, ous, "groups")
}

func TestIntegrationALDPro_CustomSearch_NotInitialized(t *testing.T) {
	conn := newALDProConn(t)
	conn.Close()

	req := ldap.NewSearchRequest(
		aldproBaseDN, ldap.ScopeBaseObject, ldap.NeverDerefAliases,
		0, 0, false, "(objectClass=*)", nil, nil,
	)
	_, err := conn.CustomSearch(context.Background(), req)
	require.Error(t, err)
	assert.ErrorIs(t, err, ldapper.ErrClosed)
}

// ================== GetUser ==================

func TestIntegrationALDPro_GetUser_ByUID(t *testing.T) {
	conn := newALDProAuthConn(t)

	user, err := conn.GetUser(context.Background(), aldproUser1UID, aldproBaseDN)
	require.NoError(t, err)
	assert.Equal(t, aldproUser1DN, user.DN)
	assert.Equal(t, "Engineering", user.GetAttributeValue("rbtadp"))
}

func TestIntegrationALDPro_GetUser_NotFound(t *testing.T) {
	conn := newALDProAuthConn(t)
	_, err := conn.GetUser(context.Background(), "does-not-exist", aldproBaseDN)
	require.Error(t, err)
	assert.ErrorIs(t, err, ldapper.ErrNotFoundOrNotVisible)
}

func TestIntegrationALDPro_GetUser_EmptyUsername(t *testing.T) {
	conn := newALDProAuthConn(t)
	_, err := conn.GetUser(context.Background(), "", aldproBaseDN)
	require.Error(t, err)
	assert.ErrorIs(t, err, ldapper.ErrInvalidArgument)
}

func TestIntegrationALDPro_GetUser_EmptyBaseDN(t *testing.T) {
	conn := newALDProAuthConn(t)
	_, err := conn.GetUser(context.Background(), aldproUser1UID, "")
	require.Error(t, err)
	assert.ErrorIs(t, err, ldapper.ErrInvalidArgument)
}

// ================== GetGroup / GetOU ==================

func TestIntegrationALDPro_GetGroup_Success(t *testing.T) {
	conn := newALDProAuthConn(t)

	group, err := conn.GetGroup(context.Background(), "admins", aldproBaseDN)
	require.NoError(t, err)
	require.NotNil(t, group)
	assert.Equal(t, "admins", group.GetAttributeValue("cn"))
}

func TestIntegrationALDPro_GetGroup_NotFound(t *testing.T) {
	conn := newALDProAuthConn(t)
	_, err := conn.GetGroup(context.Background(), "does-not-exist", aldproBaseDN)
	require.Error(t, err)
	assert.ErrorIs(t, err, ldapper.ErrNotFoundOrNotVisible)
}

func TestIntegrationALDPro_GetOU_StandardOU(t *testing.T) {
	conn := newALDProAuthConn(t)

	ou, err := conn.GetOU(context.Background(), "users", aldproBaseDN)
	require.NoError(t, err)
	require.NotNil(t, ou)
	assert.Equal(t, "users", ou.GetAttributeValue("ou"))
}

func TestIntegrationALDPro_GetOU_ALDProOU(t *testing.T) {
	conn := newALDProAuthConn(t)

	// departments is an rbta-org-unit — SearchOUFilterTemplate matches on
	// cn= (rbta-org-unit has no ou attribute; the seed creates it with cn
	// only), and the adapter's GetNormalizedOUInfoFromEntry falls back to
	// cn when ou is absent.
	ou, err := conn.GetOU(context.Background(), "departments", aldproBaseDN)
	require.NoError(t, err)
	require.NotNil(t, ou)
	assert.Contains(t, strings.ToLower(ou.DN), "cn=departments",
		"rbta-org-unit entries are cn-named")
	assert.Empty(t, ou.GetAttributeValue("ou"),
		"rbta-org-unit has no ou attribute in this schema")
	assert.Equal(t, "departments", ou.GetAttributeValue("cn"))
}

func TestIntegrationALDPro_GetOU_NotFound(t *testing.T) {
	conn := newALDProAuthConn(t)
	_, err := conn.GetOU(context.Background(), "does-not-exist", aldproBaseDN)
	require.Error(t, err)
	assert.ErrorIs(t, err, ldapper.ErrNotFoundOrNotVisible)
}

// ================== GetCatalogTree / GetSubOUs ==================

func TestIntegrationALDPro_GetCatalogTree_Success(t *testing.T) {
	conn := newALDProAuthConn(t)

	tree, err := conn.GetCatalogTree(context.Background(), aldproBaseDN, 0)
	require.NoError(t, err)

	var names []string
	var walk func(nodes []*types.OUNormalizedInfo)
	walk = func(nodes []*types.OUNormalizedInfo) {
		for _, n := range nodes {
			names = append(names, strings.ToLower(n.Name))
			walk(n.Children)
		}
	}
	walk(tree.Tree)

	assert.Contains(t, names, "users")
	assert.Contains(t, names, "departments",
		"rbta-org-unit must be discovered as a tree node")
	assert.Contains(t, names, "groups")
}

func TestIntegrationALDPro_GetCatalogTree_NormalizesCnNamedContainer(t *testing.T) {
	conn := newALDProAuthConn(t)

	tree, err := conn.GetCatalogTree(context.Background(), aldproBaseDN, 0)
	require.NoError(t, err)

	// Find the departments node and verify the adapter populated OU from cn
	// (there is no ou on the entry — the adapter's fallback is what makes
	// this a useful node for tree rendering).
	var found *types.OUNormalizedInfo
	var walk func(nodes []*types.OUNormalizedInfo)
	walk = func(nodes []*types.OUNormalizedInfo) {
		for _, n := range nodes {
			if strings.EqualFold(n.Name, "departments") {
				found = n
			}
			walk(n.Children)
		}
	}
	walk(tree.Tree)

	require.NotNil(t, found, "departments node must be present")
	assert.Equal(t, "departments", found.OU,
		"OU must fall back to cn when ou is absent")
}

func TestIntegrationALDPro_GetCatalogTree_MaxDepth(t *testing.T) {
	conn := newALDProAuthConn(t)

	tree, err := conn.GetCatalogTree(context.Background(), aldproBaseDN, 1)
	require.NoError(t, err)
	for _, root := range tree.Tree {
		assert.Empty(t, root.Children, "maxDepth=1 must trim children")
	}
}

func TestIntegrationALDPro_GetSubOUs_SingleLevel(t *testing.T) {
	conn := newALDProAuthConn(t)

	ous, err := conn.GetSubOUs(context.Background(), aldproBaseDN, ldap.ScopeSingleLevel)
	require.NoError(t, err)

	var names []string
	for _, ou := range ous {
		names = append(names, ou.Name)
	}
	assert.Contains(t, names, "users")
	assert.Contains(t, names, "departments")
}

func TestIntegrationALDPro_ListSingleLevelOUs(t *testing.T) {
	conn := newALDProAuthConn(t)

	ous, err := conn.ListSingleLevelOUs(context.Background(), aldproBaseDN)
	require.NoError(t, err)
	assert.NotEmpty(t, ous)
}

// ================== GetUserGroups ==================

// GetUserGroups returns DNs; assertions use containsDN (case-insensitive
// substring) because DN attribute-type case may vary.
func TestIntegrationALDPro_GetUserGroups_GroupOfNamesBranch(t *testing.T) {
	conn := newALDProAuthConn(t)

	groups, err := conn.GetUserGroups(context.Background(), aldproUser1UID, aldproBaseDN)
	require.NoError(t, err)
	assert.True(t, containsDN(groups, "cn=admins"),
		"expected an admins group DN in %v", groups)
}

func TestIntegrationALDPro_GetUserGroups_PosixGroupBranch(t *testing.T) {
	conn := newALDProAuthConn(t)

	groups, err := conn.GetUserGroups(context.Background(), aldproUser2UID, aldproBaseDN)
	require.NoError(t, err)
	assert.True(t, containsDN(groups, "cn=readers"),
		"expected a readers group DN in %v", groups)
}

func TestIntegrationALDPro_GetUserGroups_NoCrossContamination(t *testing.T) {
	conn := newALDProAuthConn(t)

	groups1, err := conn.GetUserGroups(context.Background(), aldproUser1UID, aldproBaseDN)
	require.NoError(t, err)
	assert.False(t, containsDN(groups1, "cn=readers"),
		"user1 must not be in readers, got %v", groups1)

	groups2, err := conn.GetUserGroups(context.Background(), aldproUser2UID, aldproBaseDN)
	require.NoError(t, err)
	assert.False(t, containsDN(groups2, "cn=admins"),
		"user2 must not be in admins, got %v", groups2)
}

func TestIntegrationALDPro_GetUserGroups_UserNotFound(t *testing.T) {
	conn := newALDProAuthConn(t)

	_, err := conn.GetUserGroups(context.Background(), "nobody", aldproBaseDN)
	require.Error(t, err)
	assert.ErrorIs(t, err, ldapper.ErrNotFoundOrNotVisible)
}

// ================== GetOUUsers ==================

func TestIntegrationALDPro_GetOUUsers_StandardOU(t *testing.T) {
	conn := newALDProAuthConn(t)

	users, err := conn.GetOUUsers(context.Background(), "ou=users,"+aldproBaseDN)
	require.NoError(t, err)
	require.Len(t, users, 3) // user1, user2, svc-reader

	uids := make([]string, 0, len(users))
	for _, u := range users {
		uids = append(uids, u.GetAttributeValue("uid"))
	}
	assert.ElementsMatch(t,
		[]string{aldproUser1UID, aldproUser2UID, aldproSvcUID},
		uids)
}

func TestIntegrationALDPro_GetOUUsers_ALDProOU(t *testing.T) {
	conn := newALDProAuthConn(t)

	users, err := conn.GetOUUsers(context.Background(), aldproDepartmentsDN)
	require.NoError(t, err)
	assert.Empty(t, users, "departments contains no users")
}

func TestIntegrationALDPro_GetOUUsers_NotInitialized(t *testing.T) {
	conn := newALDProConn(t)
	conn.Close()

	_, err := conn.GetOUUsers(context.Background(), "ou=users,"+aldproBaseDN)
	require.Error(t, err)
	assert.ErrorIs(t, err, ldapper.ErrClosed)
}

// ================== SearchLimits / DialTimeout / OperationTimeouts ==================

func TestIntegrationALDPro_SearchLimits_Defaults(t *testing.T) {
	conn := newALDProConn(t)
	limits := conn.GetSearchLimits()
	assert.Equal(t, 0, limits.SizeLimit)
	assert.Equal(t, 30, limits.TimeLimit)
	assert.True(t, limits.RequirePaging)
}

func TestIntegrationALDPro_SearchLimits_WithOption(t *testing.T) {
	limits := ldapper.DefaultSearchLimits()
	limits.SizeLimit = 5
	limits.TimeLimit = 10

	conn := newALDProConn(t, ldapper.WithSearchLimits(limits))

	got := conn.GetSearchLimits()
	assert.Equal(t, 5, got.SizeLimit)
	assert.Equal(t, 10, got.TimeLimit)
}

func TestIntegrationALDPro_SearchLimits_SetAtRuntime(t *testing.T) {
	conn := newALDProConn(t)

	limits := conn.GetSearchLimits()
	limits.SizeLimit = 7
	limits.TimeLimit = 11
	conn.SetSearchLimits(limits)

	got := conn.GetSearchLimits()
	assert.Equal(t, 7, got.SizeLimit)
	assert.Equal(t, 11, got.TimeLimit)
}

func TestIntegrationALDPro_SearchLimits_NegativeClampedToZero(t *testing.T) {
	conn := newALDProConn(t)
	conn.SetSearchLimits(ldapper.SearchLimits{SizeLimit: -1, TimeLimit: -5})
	got := conn.GetSearchLimits()
	assert.Equal(t, 0, got.SizeLimit)
	assert.Equal(t, 0, got.TimeLimit)
}

func TestIntegrationALDPro_DialTimeout_Defaults(t *testing.T) {
	conn := newALDProConn(t)
	assert.Equal(t, constants.DefaultDialTimeout, conn.GetDialTimeout())
}

func TestIntegrationALDPro_DialTimeout_WithOption(t *testing.T) {
	conn := newALDProConn(t, ldapper.WithDialTimeout(3*time.Second))
	assert.Equal(t, 3*time.Second, conn.GetDialTimeout())
}

func TestIntegrationALDPro_DialTimeout_SetAtRuntime(t *testing.T) {
	conn := newALDProConn(t)
	conn.SetDialTimeout(2 * time.Second)
	assert.Equal(t, 2*time.Second, conn.GetDialTimeout())
}

func TestIntegrationALDPro_DialTimeout_NegativeClampedToZero(t *testing.T) {
	conn := newALDProConn(t)
	conn.SetDialTimeout(-1 * time.Second)
	assert.Equal(t, time.Duration(0), conn.GetDialTimeout())
}

func TestIntegrationALDPro_OperationTimeout_WithOption(t *testing.T) {
	conn := newALDProAuthConn(t, ldapper.WithOperationTimeout(ldapper.OperationTimeouts{
		Bind:   5 * time.Second,
		Search: 5 * time.Second,
	}))

	got := conn.GetOperationTimeout()
	assert.Equal(t, 5*time.Second, got.Bind)
	assert.Equal(t, 5*time.Second, got.Search)

	_, err := conn.GetUser(context.Background(), aldproUser1UID, aldproBaseDN)
	require.NoError(t, err)
}

// ================== Failure paths ==================

func TestIntegrationALDPro_BindConn_FailedBind_InvalidatesState(t *testing.T) {
	conn := newALDProConn(t)

	_, err := conn.BindConn(context.Background(),
		aldproSvcDN, aldproSvcPass, aldproBaseDN)
	require.NoError(t, err)

	_, err = conn.BindConn(context.Background(),
		aldproSvcDN, "wrong-password", aldproBaseDN)
	require.Error(t, err)
	assert.ErrorIs(t, err, ldapper.ErrInvalidCredentials)

	_, err = conn.CheckUserCredentials(context.Background(), aldproUser1UID, aldproUser1Pass)
	require.Error(t, err)
	assert.ErrorIs(t, err, ldapper.ErrClosed,
		"post-failed-bind connection is nil; requireConnLocked fires before the auth check")
}

// Breaks svc-reader's password via direct LDAP Modify, then verifies that
// Reconnect — which uses the stale cached password — fails and leaves the
// client unusable (ErrClosed) instead of falling back to anonymous.
func TestIntegrationALDPro_Reconnect_RebindFailure_ClosesConnection(t *testing.T) {
	conn := newALDProConn(t)
	_, err := conn.BindConn(context.Background(),
		aldproSvcDN, aldproSvcPass, aldproBaseDN)
	require.NoError(t, err)

	rawConn, err := ldap.DialURL(fmt.Sprintf("ldap://%s:%d", aldproHost, aldproPort))
	require.NoError(t, err)
	defer rawConn.Close()
	require.NoError(t, rawConn.Bind(aldproAdminDN, aldproAdminPass))

	modify := ldap.NewModifyRequest(aldproSvcDN, nil)
	modify.Replace("userPassword", []string{"temporary-during-test"})
	require.NoError(t, rawConn.Modify(modify))

	t.Cleanup(func() {
		restore := ldap.NewModifyRequest(aldproSvcDN, nil)
		restore.Replace("userPassword", []string{aldproSvcPass})
		_ = rawConn.Modify(restore)
	})

	err = conn.Reconnect(context.Background())
	require.Error(t, err)
	assert.ErrorIs(t, err, ldapper.ErrInvalidCredentials)

	_, err = conn.GetUser(context.Background(), aldproUser1UID, aldproBaseDN)
	require.Error(t, err)
	assert.ErrorIs(t, err, ldapper.ErrClosed,
		"connection must not be usable after a failed rebind")

	_, err = conn.CheckUserCredentials(context.Background(), aldproUser1UID, aldproUser1Pass)
	require.Error(t, err)
	assert.ErrorIs(t, err, ldapper.ErrClosed,
		"connection is nil after failed rebind; requireConnLocked wins over requireAuthLocked")
}
