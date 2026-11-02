//go:build integration_aldpro
// +build integration_aldpro

package ldapper_test

// ALDPro (Astra Linux Directory Pro) integration tests.
//
// ALDPro is a commercial Russian directory service built on FreeIPA/389ds
// with schema extensions (rbta-org-unit, rbtadp). No public Docker image
// exists, so this suite runs against stock osixia/openldap augmented with a
// custom schema that mirrors the ALDPro-specific pieces exercised by
// ALDROAdapter:
//   - objectClass rbta-org-unit  (used by OUObjectFilter / SearchOUFilterTemplate)
//   - attribute  rbtadp         (used as department attribute in UserAttrs)
//
// Adapter status (after the latest fix):
//
//   SearchUserGroupsFilterTemplate =
//     (|(&(|(objectClass=groupOfNames)(objectClass=ipausergroup)(objectClass=posixGroup))(member=%s))
//       (&(|(objectClass=posixGroup))(memberUid=%s)))
//
//   SearchUserGroupsFilterTemplateArgs = [ user.DN, user.GetAttributeValue("uid") ]
//
// This mirrors OPENLDAPAdapter: both group flavours are now supported:
//   - groupOfNames / ipausergroup  -> member    (DN-valued)  -> args[0] = DN
//   - posixGroup                   -> memberUid (uid-valued) -> args[1] = uid
//
// GetUserGroups tests below are POSITIVE for both branches:
//   - user1 -> ["admins"]  (groupOfNames,  member   = DN)
//   - user2 -> ["readers"] (posixGroup,    memberUid = uid)
//
// What IS covered by this suite:
//   - NewConnection / NewAuthenticatedConnection / AuthenticateConn /
//     AuthenticateUser / IsAlive / Reconnect / EnsureAlive / Close
//   - GetUser / GetOUUsers / CustomSearch / search limits
//   - rbta-org-unit objectClass matching via ALDROAdapter.OUObjectFilter
//   - Positive GetUserGroups for BOTH branches of the fixed filter
//
// What is NOT covered (needs a real ALDPro instance):
//   - FreeIPA-only objectClasses like ipausergroup (no schema in stock LDAP)
//   - Kerberos/NTLM interop and ALDPro's real ACLs
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
	"github.com/NGRsoftlab/ldapper/types"
)

// ---------------------------------------------------------------------------
// ALDPro test fixtures
// ---------------------------------------------------------------------------

const (
	aldproBaseDN    = "dc=aldpro,dc=test"
	aldproAdminDN   = "cn=admin,dc=aldpro,dc=test"
	aldproAdminPass = "adminpassword"

	aldproUser1DN   = "cn=user1,ou=users,dc=aldpro,dc=test"
	aldproUser1UID  = "user1"
	aldproUser1Pass = "password1"

	aldproUser2DN   = "cn=user2,ou=users,dc=aldpro,dc=test"
	aldproUser2UID  = "user2"
	aldproUser2Pass = "password2"
)

// aldproSchema mirrors ALDPro-specific schema extensions.
//
// OIDs use the private enterprise placeholder (1.3.6.1.4.1.99999.*); they only
// need to be unique inside the ephemeral test OpenLDAP instance and do NOT
// correspond to the real ALDPro OIDs.
const aldproSchema = `attributetype ( 1.3.6.1.4.1.99999.1.1
    NAME 'rbtadp'
    DESC 'ALDPro department attribute'
    EQUALITY caseIgnoreMatch
    SUBSTR caseIgnoreSubstringsMatch
    SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{256} )

objectclass ( 1.3.6.1.4.1.99999.2.1
    NAME 'rbta-org-unit'
    DESC 'ALDPro organizational unit'
    SUP organizationalUnit
    STRUCTURAL
    MAY ( rbtadp $ description ) )
`

// aldproBootstrapLDIF seeds:
//   - ou=users as a standard organizationalUnit with two users
//   - ou=departments as an ALDPro-specific rbta-org-unit (tests the schema)
//   - ou=groups with a groupOfNames (admins, member=user1 DN) and a
//     posixGroup (readers, memberUid=user2)
//
// The fixed adapter filter now matches BOTH branches of `member`/`memberUid`,
// so both memberships below are expected to appear in GetUserGroups.
const aldproBootstrapLDIF = `dn: ou=users,dc=aldpro,dc=test
objectClass: organizationalUnit
ou: users

dn: ou=departments,dc=aldpro,dc=test
objectClass: rbta-org-unit
ou: departments
rbtadp: Department Container
description: ALDPro-specific organizational unit

dn: ou=groups,dc=aldpro,dc=test
objectClass: organizationalUnit
ou: groups

dn: cn=user1,ou=users,dc=aldpro,dc=test
objectClass: inetOrgPerson
objectClass: posixAccount
cn: user1
sn: User
uid: user1
uidNumber: 1001
gidNumber: 1001
homeDirectory: /home/user1
userPassword: password1
mail: user1@aldpro.test
rbtadp: Engineering

dn: cn=user2,ou=users,dc=aldpro,dc=test
objectClass: inetOrgPerson
objectClass: posixAccount
cn: user2
sn: User
uid: user2
uidNumber: 1002
gidNumber: 1002
homeDirectory: /home/user2
userPassword: password2
mail: user2@aldpro.test
rbtadp: Sales

dn: cn=admins,ou=groups,dc=aldpro,dc=test
objectClass: groupOfNames
cn: admins
member: cn=user1,ou=users,dc=aldpro,dc=test

dn: cn=readers,ou=groups,dc=aldpro,dc=test
objectClass: posixGroup
cn: readers
gidNumber: 2001
memberUid: user2
`

var (
	aldproHost string
	aldproPort uint
	aldproAdpt = adapters.ALDROAdapter{}
)

func TestMain(m *testing.M) {
	ctx := context.Background()

	tmpDir, err := os.MkdirTemp("", "ldapper-aldpro-*")
	if err != nil {
		fmt.Fprintf(os.Stderr, "cannot create temp dir: %v\n", err)
		os.Exit(1)
	}
	defer os.RemoveAll(tmpDir)

	schemaPath := filepath.Join(tmpDir, "99-aldpro.schema")
	if err := os.WriteFile(schemaPath, []byte(aldproSchema), 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "cannot write schema: %v\n", err)
		os.Exit(1)
	}

	ldifPath := filepath.Join(tmpDir, "50-aldpro.ldif")
	if err := os.WriteFile(ldifPath, []byte(aldproBootstrapLDIF), 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "cannot write LDIF: %v\n", err)
		os.Exit(1)
	}

	req := testcontainers.ContainerRequest{
		Image:        "osixia/openldap:1.5.0",
		ExposedPorts: []string{"389/tcp"},
		Env: map[string]string{
			"LDAP_ORGANISATION":   "ALDPro Test",
			"LDAP_DOMAIN":         "aldpro.test",
			"LDAP_ADMIN_PASSWORD": aldproAdminPass,
		},
		Mounts: testcontainers.ContainerMounts{
			// Custom schema must be loaded before slapd accepts LDIF using it.
			testcontainers.ContainerMount{
				Source: testcontainers.GenericBindMountSource{HostPath: schemaPath},
				Target: testcontainers.ContainerMountTarget(
					"/container/service/slapd/assets/config/bootstrap/schema/99-aldpro.schema",
				),
				ReadOnly: true,
			},
			testcontainers.ContainerMount{
				Source: testcontainers.GenericBindMountSource{HostPath: ldifPath},
				Target: testcontainers.ContainerMountTarget(
					"/container/service/slapd/assets/config/bootstrap/ldif/custom/50-aldpro.ldif",
				),
				ReadOnly: true,
			},
		},
		WaitingFor: wait.ForLog("slapd starting").WithStartupTimeout(120 * time.Second),
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
		fmt.Fprintf(os.Stderr, "cannot resolve container host: %v\n", err)
		os.Exit(1)
	}

	mappedPort, err := container.MappedPort(ctx, "389")
	if err != nil {
		_ = container.Terminate(ctx)
		fmt.Fprintf(os.Stderr, "cannot resolve mapped port: %v\n", err)
		os.Exit(1)
	}
	aldproPort = uint(mappedPort.Num())

	if !waitForALDProReady(aldproHost, aldproPort, 60*time.Second) {
		_ = container.Terminate(ctx)
		fmt.Fprintln(os.Stderr, "OpenLDAP (ALDPro schema) did not become ready")
		os.Exit(1)
	}

	code := m.Run()
	_ = container.Terminate(ctx)
	os.Exit(code)
}

// waitForALDProReady polls admin bind, then verifies the custom schema and
// bootstrap LDIF were applied by looking up an rbta-org-unit entry.
func waitForALDProReady(host string, port uint, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		c, err := ldap.DialURL(fmt.Sprintf("ldap://%s:%d", host, port))
		if err == nil {
			bindErr := c.Bind(aldproAdminDN, aldproAdminPass)
			if bindErr == nil {
				req := ldap.NewSearchRequest(
					"ou=departments,"+aldproBaseDN,
					ldap.ScopeBaseObject, ldap.NeverDerefAliases,
					0, 0, false,
					"(objectClass=rbta-org-unit)",
					[]string{"ou"}, nil,
				)
				if _, err := c.Search(req); err == nil {
					_ = c.Close()
					return true
				}
			}
			_ = c.Close()
		}
		time.Sleep(500 * time.Millisecond)
	}
	return false
}

func newALDProConn(t *testing.T, opts ...ldapper.Option) *ldapper.LDAPper {
	t.Helper()
	conn, err := ldapper.NewConnection(
		[]string{aldproHost},
		aldproPort,
		false, // useSSL
		true,  // skipTLS
		nil,
		aldproAdpt,
		opts...,
	)
	require.NoError(t, err)
	t.Cleanup(conn.Close)
	return conn
}

// newALDProAuthConn authenticates as admin; bindDN = aldproBaseDN, which is
// what AuthenticateUser(username, password) uses internally after the change.
func newALDProAuthConn(t *testing.T, opts ...ldapper.Option) *ldapper.LDAPper {
	t.Helper()
	conn, _, err := ldapper.NewAuthenticatedConnection(
		aldproAdminDN, aldproAdminPass, aldproBaseDN,
		[]string{aldproHost},
		aldproPort,
		false,
		true,
		nil,
		aldproAdpt,
		opts...,
	)
	require.NoError(t, err)
	t.Cleanup(conn.Close)
	return conn
}

func aldproDNHasPrefixCI(dn, prefix string) bool {
	return strings.HasPrefix(strings.ToLower(dn), strings.ToLower(prefix))
}

// ---------------------------------------------------------------------------
// Adapter contract tests (no server needed)
// ---------------------------------------------------------------------------

// TestIntegrationALDPro_SearchUserGroupsFilterTemplate_PostFix guards the
// final filter: two %s placeholders (one for member, one for memberUid) and
// no leftover "member=uid=" construct.
func TestIntegrationALDPro_SearchUserGroupsFilterTemplate_PostFix(t *testing.T) {
	tmpl := aldproAdpt.SearchUserGroupsFilterTemplate()

	assert.NotContains(t, tmpl, "member=uid=",
		"regression: earlier versions had (member=uid=%s), which is invalid")

	// Both branches must be present.
	assert.Contains(t, tmpl, "(member=%s)",
		"groupOfNames/ipausergroup branch must query member with a DN")
	assert.Contains(t, tmpl, "(memberUid=%s)",
		"posixGroup branch must query memberUid with a uid")

	// Two %s placeholders in total, in the right order.
	assert.Equal(t, 2, strings.Count(tmpl, "%s"),
		"template must have exactly two format placeholders (member, memberUid)")
}

// TestIntegrationALDPro_SearchUserGroupsFilterTemplateArgs_ReturnsDNThenUID
// asserts the fixed args helper returns [user.DN, user.uid] in that order.
func TestIntegrationALDPro_SearchUserGroupsFilterTemplateArgs_ReturnsDNThenUID(t *testing.T) {
	const dn = "cn=user1,ou=users,dc=aldpro,dc=test"
	user := types.LDAPUser{
		DN: dn,
		Attributes: map[string][]string{
			"uid":  {"user1"},
			"mail": {"user1@aldpro.test"},
		},
	}

	args := aldproAdpt.SearchUserGroupsFilterTemplateArgs(user)
	require.Len(t, args, 2,
		"args must have one value per %s placeholder in the template")

	require.Equal(t, dn, args[0],
		"args[0] must be the user's DN for the (member=%s) branch")
	require.Equal(t, "user1", args[1],
		"args[1] must be the user's uid for the (memberUid=%s) branch")
}

// ---------------------------------------------------------------------------
// NewConnection / NewAuthenticatedConnection
// ---------------------------------------------------------------------------

func TestIntegrationALDPro_NewConnection_Success(t *testing.T) {
	conn := newALDProConn(t)
	require.NotNil(t, conn)
	assert.True(t, conn.IsAlive())
}

func TestIntegrationALDPro_NewConnection_EmptyHosts(t *testing.T) {
	_, err := ldapper.NewConnection(nil, 389, false, true, nil, aldproAdpt)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "empty hosts list")
}

func TestIntegrationALDPro_NewConnection_TooManyHosts(t *testing.T) {
	hosts := make([]string, 100)
	for i := range hosts {
		hosts[i] = fmt.Sprintf("host%d", i)
	}
	_, err := ldapper.NewConnection(hosts, 389, false, true, nil, aldproAdpt)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "too many hosts")
}

func TestIntegrationALDPro_NewConnection_NilTLSConfigWhenRequired(t *testing.T) {
	_, err := ldapper.NewConnection([]string{aldproHost}, aldproPort, false, false, nil, aldproAdpt)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "nil tls config")
}

func TestIntegrationALDPro_NewConnection_NilCatalogAdapter(t *testing.T) {
	_, err := ldapper.NewConnection([]string{aldproHost}, aldproPort, false, true, nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "nil catalog adapter")
}

func TestIntegrationALDPro_NewConnection_UnreachableHost(t *testing.T) {
	_, err := ldapper.NewConnection([]string{"127.0.0.1"}, 1, false, true, nil, aldproAdpt)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsuccessful dial")
}

func TestIntegrationALDPro_NewAuthenticatedConnection_Success(t *testing.T) {
	conn, user, err := ldapper.NewAuthenticatedConnection(
		aldproAdminDN, aldproAdminPass, aldproBaseDN,
		[]string{aldproHost}, aldproPort, false, true, nil, aldproAdpt,
	)
	require.NoError(t, err)
	defer conn.Close()

	require.NotNil(t, user)
	assert.Equal(t, aldproAdminDN, user.DN)
}

func TestIntegrationALDPro_NewAuthenticatedConnection_EmptyCredentials(t *testing.T) {
	_, _, err := ldapper.NewAuthenticatedConnection(
		"", "", aldproBaseDN,
		[]string{aldproHost}, aldproPort, false, true, nil, aldproAdpt,
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "empty bind username/password")
}

func TestIntegrationALDPro_NewAuthenticatedConnection_WrongPassword(t *testing.T) {
	_, _, err := ldapper.NewAuthenticatedConnection(
		aldproAdminDN, "wrong-password", aldproBaseDN,
		[]string{aldproHost}, aldproPort, false, true, nil, aldproAdpt,
	)
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// AuthenticateConn
// ---------------------------------------------------------------------------

func TestIntegrationALDPro_AuthenticateConn_Success(t *testing.T) {
	conn := newALDProConn(t)

	user, err := conn.AuthenticateConn(aldproAdminDN, aldproAdminPass, aldproBaseDN)
	require.NoError(t, err)
	require.NotNil(t, user)
	assert.Equal(t, aldproAdminDN, user.DN)
}

func TestIntegrationALDPro_AuthenticateConn_EmptyCredentials(t *testing.T) {
	conn := newALDProConn(t)
	_, err := conn.AuthenticateConn("", "", aldproBaseDN)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "empty bind username/password")
}

func TestIntegrationALDPro_AuthenticateConn_WrongPassword(t *testing.T) {
	conn := newALDProConn(t)
	_, err := conn.AuthenticateConn(aldproAdminDN, "bad-password", aldproBaseDN)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsuccessful bind")
}

func TestIntegrationALDPro_AuthenticateConn_NonExistentUser(t *testing.T) {
	conn := newALDProConn(t)
	_, err := conn.AuthenticateConn(
		"cn=ghost,ou=users,"+aldproBaseDN, "whatever", aldproBaseDN,
	)
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// AuthenticateUser — signature is (username, password); base DN comes from
// conn.bindDN stored by AuthenticateConn.
// ---------------------------------------------------------------------------

func TestIntegrationALDPro_AuthenticateUser_Success(t *testing.T) {
	conn := newALDProAuthConn(t)

	user, err := conn.AuthenticateUser(aldproUser1UID, aldproUser1Pass)
	require.NoError(t, err)
	require.NotNil(t, user)
	assert.Equal(t, aldproUser1UID, user.GetAttributeValue("uid"))
}

func TestIntegrationALDPro_AuthenticateUser_WrongPassword(t *testing.T) {
	conn := newALDProAuthConn(t)

	user, err := conn.AuthenticateUser(aldproUser1UID, "bad")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsuccessful bind with passed user credentials")
	require.NotNil(t, user)
	assert.Equal(t, aldproUser1UID, user.GetAttributeValue("uid"))
}

func TestIntegrationALDPro_AuthenticateUser_NonExistentUser(t *testing.T) {
	conn := newALDProAuthConn(t)
	_, err := conn.AuthenticateUser("ghost-user", "whatever")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "user does not exist")
}

func TestIntegrationALDPro_AuthenticateUser_NotAuthenticated(t *testing.T) {
	conn := newALDProConn(t)
	_, err := conn.AuthenticateUser(aldproUser1UID, aldproUser1Pass)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "connection not authenticated")
}

func TestIntegrationALDPro_AuthenticateUser_EmptyCredentials(t *testing.T) {
	conn := newALDProAuthConn(t)
	_, err := conn.AuthenticateUser("", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "empty username/password")
}

// ---------------------------------------------------------------------------
// IsAlive / Reconnect / EnsureAlive / Close
// ---------------------------------------------------------------------------

func TestIntegrationALDPro_IsAlive_ActiveConnection(t *testing.T) {
	conn := newALDProConn(t)
	assert.True(t, conn.IsAlive())
}

func TestIntegrationALDPro_IsAlive_AfterClose(t *testing.T) {
	conn := newALDProConn(t)
	conn.Close()
	assert.False(t, conn.IsAlive())
}

func TestIntegrationALDPro_Reconnect_Unauthenticated(t *testing.T) {
	conn := newALDProConn(t)
	require.True(t, conn.IsAlive())
	require.NoError(t, conn.Reconnect())
	assert.True(t, conn.IsAlive())
}

func TestIntegrationALDPro_Reconnect_PreservesAuthentication(t *testing.T) {
	conn := newALDProAuthConn(t)
	require.NoError(t, conn.Reconnect())

	_, err := conn.AuthenticateUser(aldproUser1UID, aldproUser1Pass)
	require.NoError(t, err)
}

func TestIntegrationALDPro_EnsureAlive_NoopWhenAlive(t *testing.T) {
	conn := newALDProConn(t)
	require.NoError(t, conn.EnsureAlive())
	assert.True(t, conn.IsAlive())
}

func TestIntegrationALDPro_EnsureAlive_ReconnectsAfterClose(t *testing.T) {
	conn := newALDProAuthConn(t)
	conn.Close()
	require.False(t, conn.IsAlive())

	require.NoError(t, conn.EnsureAlive())
	assert.True(t, conn.IsAlive())

	_, err := conn.AuthenticateUser(aldproUser1UID, aldproUser1Pass)
	require.NoError(t, err)
}

func TestIntegrationALDPro_Close_Idempotent(t *testing.T) {
	conn := newALDProConn(t)
	conn.Close()
	conn.Close() // must not panic

	_, err := conn.GetUser(aldproUser1UID, aldproBaseDN)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "connection not initialized")
}

// ---------------------------------------------------------------------------
// CustomSearch
// ---------------------------------------------------------------------------

func TestIntegrationALDPro_CustomSearch_UserLookup(t *testing.T) {
	conn := newALDProAuthConn(t)

	req := ldap.NewSearchRequest(
		aldproBaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		0, 0, false,
		"(uid=user1)",
		[]string{"cn", "mail", "rbtadp"},
		nil,
	)

	res, err := conn.CustomSearch(req)
	require.NoError(t, err)
	require.Len(t, res.Entries, 1)
	assert.Equal(t, aldproUser1DN, res.Entries[0].DN)
	assert.Equal(t, "user1@aldpro.test", res.Entries[0].GetAttributeValue("mail"))
	assert.Equal(t, "Engineering", res.Entries[0].GetAttributeValue("rbtadp"))
}

// TestIntegrationALDPro_CustomSearch_OUFilterMatchesBothTypes proves that the
// rbta-org-unit schema extension was actually loaded and that
// ALDROAdapter.OUObjectFilter finds BOTH standard organizationalUnit and
// ALDPro-specific rbta-org-unit entries.
func TestIntegrationALDPro_CustomSearch_OUFilterMatchesBothTypes(t *testing.T) {
	conn := newALDProAuthConn(t)

	req := ldap.NewSearchRequest(
		aldproBaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		0, 0, false,
		aldproAdpt.OUObjectFilter(), // (|(objectClass=organizationalUnit)(objectClass=rbta-org-unit))
		[]string{"ou"},
		nil,
	)

	res, err := conn.CustomSearch(req)
	require.NoError(t, err)

	ous := make([]string, 0, len(res.Entries))
	for _, e := range res.Entries {
		ous = append(ous, e.GetAttributeValue("ou"))
	}
	assert.Contains(t, ous, "users", "standard organizationalUnit must be matched")
	assert.Contains(t, ous, "departments", "ALDPro rbta-org-unit must be matched")
	assert.Contains(t, ous, "groups", "standard organizationalUnit must be matched")
}

func TestIntegrationALDPro_CustomSearch_NotInitialized(t *testing.T) {
	conn := newALDProConn(t)
	conn.Close()

	req := ldap.NewSearchRequest(
		aldproBaseDN, ldap.ScopeBaseObject, ldap.NeverDerefAliases,
		0, 0, false, "(objectClass=*)", nil, nil,
	)
	_, err := conn.CustomSearch(req)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "connection not initialized")
}

// ---------------------------------------------------------------------------
// GetUser
// ---------------------------------------------------------------------------

func TestIntegrationALDPro_GetUser_ByUID(t *testing.T) {
	conn := newALDProAuthConn(t)

	user, err := conn.GetUser(aldproUser1UID, aldproBaseDN)
	require.NoError(t, err)
	assert.Equal(t, aldproUser1DN, user.DN)
	assert.Equal(t, "user1", user.GetAttributeValue("uid"))
	assert.Equal(t, "user1@aldpro.test", user.GetAttributeValue("mail"))
	assert.Equal(t, "Engineering", user.GetAttributeValue("rbtadp"),
		"rbtadp attribute is loaded via custom ALDPro schema")
}

func TestIntegrationALDPro_GetUser_NotFound(t *testing.T) {
	conn := newALDProAuthConn(t)
	_, err := conn.GetUser("does-not-exist", aldproBaseDN)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "user does not exist")
}

func TestIntegrationALDPro_GetUser_NotInitialized(t *testing.T) {
	conn := newALDProConn(t)
	conn.Close()

	_, err := conn.GetUser(aldproUser1UID, aldproBaseDN)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "connection not initialized")
}

// ---------------------------------------------------------------------------
// GetUserGroups — POSITIVE for BOTH branches of the fixed filter.
// ---------------------------------------------------------------------------

// TestIntegrationALDPro_GetUserGroups_GroupOfNamesBranch verifies the first
// branch of the fixed filter: user1 is in `admins` (groupOfNames,
// member = full DN), matched via (member=<user.DN>).
func TestIntegrationALDPro_GetUserGroups_GroupOfNamesBranch(t *testing.T) {
	conn := newALDProAuthConn(t)

	groups, err := conn.GetUserGroups(aldproUser1UID, aldproBaseDN)
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"admins"}, groups)
}

// TestIntegrationALDPro_GetUserGroups_PosixGroupBranch verifies the second
// branch of the fixed filter: user2 is in `readers` (posixGroup,
// memberUid = uid), matched via (memberUid=<user.uid>).
func TestIntegrationALDPro_GetUserGroups_PosixGroupBranch(t *testing.T) {
	conn := newALDProAuthConn(t)

	groups, err := conn.GetUserGroups(aldproUser2UID, aldproBaseDN)
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"readers"}, groups)
}

// TestIntegrationALDPro_GetUserGroups_NoCrossContamination guards against a
// subtle bug: with two placeholders in the filter, a swapped-args mistake
// could turn (member=<uid>) / (memberUid=<DN>) and either produce false
// positives or mask real memberships. This test confirms that user1's group
// list does NOT contain readers (posixGroup/memberUid=user2) and vice versa.
func TestIntegrationALDPro_GetUserGroups_NoCrossContamination(t *testing.T) {
	conn := newALDProAuthConn(t)

	groups1, err := conn.GetUserGroups(aldproUser1UID, aldproBaseDN)
	require.NoError(t, err)
	assert.NotContains(t, groups1, "readers",
		"user1 is not in readers; args ordering must not leak")

	groups2, err := conn.GetUserGroups(aldproUser2UID, aldproBaseDN)
	require.NoError(t, err)
	assert.NotContains(t, groups2, "admins",
		"user2 is not in admins; args ordering must not leak")
}

// TestIntegrationALDPro_GetUserGroups_CrossCheckedByCustomSearch cross-checks
// both positive results above with independent CustomSearch queries over the
// correct attributes (member / memberUid), confirming that GetUserGroups is
// reporting real membership, not a filter accident.
func TestIntegrationALDPro_GetUserGroups_CrossCheckedByCustomSearch(t *testing.T) {
	conn := newALDProAuthConn(t)

	// Branch 1: groupOfNames, member = user1 DN.
	req1 := ldap.NewSearchRequest(
		aldproBaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		0, 0, false,
		fmt.Sprintf("(&(objectClass=groupOfNames)(member=%s))", aldproUser1DN),
		[]string{"cn"}, nil,
	)
	res1, err := conn.CustomSearch(req1)
	require.NoError(t, err)
	require.NotEmpty(t, res1.Entries)
	assert.Equal(t, "admins", res1.Entries[0].GetAttributeValue("cn"))

	// Branch 2: posixGroup, memberUid = user2 uid.
	req2 := ldap.NewSearchRequest(
		aldproBaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		0, 0, false,
		fmt.Sprintf("(&(objectClass=posixGroup)(memberUid=%s))", aldproUser2UID),
		[]string{"cn"}, nil,
	)
	res2, err := conn.CustomSearch(req2)
	require.NoError(t, err)
	require.NotEmpty(t, res2.Entries)
	assert.Equal(t, "readers", res2.Entries[0].GetAttributeValue("cn"))
}

func TestIntegrationALDPro_GetUserGroups_UserNotFound(t *testing.T) {
	conn := newALDProAuthConn(t)

	_, err := conn.GetUserGroups("nobody", aldproBaseDN)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "user does not exist")
}

// ---------------------------------------------------------------------------
// GetOUUsers
// ---------------------------------------------------------------------------

func TestIntegrationALDPro_GetOUUsers_StandardOU(t *testing.T) {
	conn := newALDProAuthConn(t)

	users, err := conn.GetOUUsers("ou=users," + aldproBaseDN)
	require.NoError(t, err)
	require.Len(t, users, 2)

	uids := make([]string, 0, len(users))
	for _, u := range users {
		uids = append(uids, u.GetAttributeValue("uid"))
	}
	assert.ElementsMatch(t, []string{aldproUser1UID, aldproUser2UID}, uids)
}

// TestIntegrationALDPro_GetOUUsers_ALDProOU verifies that GetOUUsers works
// even when the base DN is an rbta-org-unit. No users live under it in this
// fixture, but the empty result confirms that the schema extension is live
// and the base DN is resolvable.
func TestIntegrationALDPro_GetOUUsers_ALDProOU(t *testing.T) {
	conn := newALDProAuthConn(t)

	users, err := conn.GetOUUsers("ou=departments," + aldproBaseDN)
	require.NoError(t, err)
	assert.Empty(t, users)
}

func TestIntegrationALDPro_GetOUUsers_NotInitialized(t *testing.T) {
	conn := newALDProConn(t)
	conn.Close()

	_, err := conn.GetOUUsers("ou=users," + aldproBaseDN)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "connection not initialized")
}

// ---------------------------------------------------------------------------
// Search limits
// ---------------------------------------------------------------------------

func TestIntegrationALDPro_SearchLimits_Defaults(t *testing.T) {
	conn := newALDProConn(t)
	limits := conn.GetSearchLimits()
	assert.Equal(t, 0, limits.SizeLimit)
	assert.Equal(t, 30, limits.TimeLimit)
}

func TestIntegrationALDPro_SearchLimits_WithOption(t *testing.T) {
	conn := newALDProConn(t, ldapper.WithSearchLimits(5, 10))
	limits := conn.GetSearchLimits()
	assert.Equal(t, 5, limits.SizeLimit)
	assert.Equal(t, 10, limits.TimeLimit)
}

func TestIntegrationALDPro_SearchLimits_SetAtRuntime(t *testing.T) {
	conn := newALDProConn(t)
	conn.SetSearchLimits(7, 11)
	limits := conn.GetSearchLimits()
	assert.Equal(t, 7, limits.SizeLimit)
	assert.Equal(t, 11, limits.TimeLimit)
}

func TestIntegrationALDPro_SearchLimits_NegativeClampedToZero(t *testing.T) {
	conn := newALDProConn(t)
	conn.SetSearchLimits(-1, -5)
	limits := conn.GetSearchLimits()
	assert.Equal(t, 0, limits.SizeLimit)
	assert.Equal(t, 0, limits.TimeLimit)
}

func TestIntegrationALDPro_SearchLimits_AppliedToSearch(t *testing.T) {
	// sizeLimit=1 against a 2-user OU triggers SizeLimitExceeded on OpenLDAP.
	conn := newALDProAuthConn(t, ldapper.WithSearchLimits(1, 0))

	_, err := conn.GetOUUsers("ou=users," + aldproBaseDN)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsuccessful ou users search")
}
