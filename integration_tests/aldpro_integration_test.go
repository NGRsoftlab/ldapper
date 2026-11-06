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
//   - attribute  rbtadp          (used as department attribute in UserAttrs)
//
// Adapter status (current):
//
//   SearchUserGroupsFilterTemplate =
//     (|(&(|(objectClass=groupOfNames)(objectClass=ipausergroup)(objectClass=posixGroup))(member=%s))
//       (&(objectClass=posixGroup)(memberUid=%s)))
//
//   SearchUserGroupsFilterTemplateArgs = [ user.DN, user.GetAttributeValue("uid") ]
//
// This mirrors OPENLDAPAdapter: both group flavours are supported:
//   - groupOfNames / ipausergroup  -> member    (DN-valued)  -> args[0] = DN
//   - posixGroup                   -> memberUid (uid-valued) -> args[1] = uid
//
// GetUserGroups tests below are POSITIVE for both branches:
//   - user1 -> ["admins"]  (groupOfNames,  member   = DN)
//   - user2 -> ["readers"] (posixGroup,    memberUid = uid)
//
// Auth-path note:
//   CheckUserCredentials(username, password) has only two args. The base DN
//   for the internal GetUser comes from conn.bindDN stored by the prior
//   AuthenticateConn call. Error assertions use errors.Is against exported
//   sentinels (ErrInvalidCredentials, ErrNotFound, ...) instead of matching
//   error text — the sentinel contract is stable, the text is not.
//
// Run with:
//   go test -tags=integration_aldpro ./...

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
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

	// aldproSvcUID is a real inetOrgPerson used for tests that need an
	// authenticated bind with a person-like account (the osixia admin is a
	// simpleSecurityObject, which the adapter's SearchUserFilterTemplate
	// does not match).
	aldproSvcUID  = "svc-reader"
	aldproSvcPass = "svcpassword"
	aldproSvcDN   = "cn=svc-reader,ou=users,dc=aldpro,dc=test"
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
//   - ou=users as a standard organizationalUnit with two users plus a
//     service account used for authenticated admin-like tests
//   - ou=departments as an ALDPro-specific rbta-org-unit (tests the schema)
//   - ou=groups with a groupOfNames (admins, member=user1 DN) and a
//     posixGroup (readers, memberUid=user2)
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

dn: cn=svc-reader,ou=users,dc=aldpro,dc=test
objectClass: inetOrgPerson
objectClass: posixAccount
cn: svc-reader
sn: Reader
uid: svc-reader
uidNumber: 1099
gidNumber: 1099
homeDirectory: /home/svc-reader
userPassword: svcpassword
mail: svc-reader@aldpro.test
rbtadp: IT

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

// newALDProConn returns an unauthenticated connection.
func newALDProConn(t *testing.T, opts ...ldapper.Option) *ldapper.LDAPper {
	t.Helper()
	conn, err := ldapper.NewLDAPper(
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

// newALDProAuthConn returns a connection authenticated as the dedicated
// service account (a real inetOrgPerson). The osixia admin is a
// simpleSecurityObject and does not match the adapter's
// SearchUserFilterTemplate, so AuthenticateConn against the admin DN would
// fail on the post-bind GetUser. Using svc-reader keeps the tests valid
// under the current adapter.
func newALDProAuthConn(t *testing.T, opts ...ldapper.Option) *ldapper.LDAPper {
	t.Helper()
	conn, _, err := ldapper.NewAuthenticatedLDAPper(
		aldproSvcDN, aldproSvcPass, aldproBaseDN,
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

// ---------------------------------------------------------------------------
// Adapter contract tests (no server needed)
// ---------------------------------------------------------------------------

func TestIntegrationALDPro_SearchUserGroupsFilterTemplate_PostFix(t *testing.T) {
	tmpl := aldproAdpt.SearchUserGroupsFilterTemplate()
	assert.NotContains(t, tmpl, "member=uid=")
	assert.Contains(t, tmpl, "(member=%s)")
	assert.Contains(t, tmpl, "(memberUid=%s)")
	assert.Equal(t, 2, strings.Count(tmpl, "%s"))
}

func TestIntegrationALDPro_SearchUserGroupsFilterTemplateArgs_ReturnsDNThenUID(t *testing.T) {
	const dn = "cn=user1,ou=users,dc=aldpro,dc=test"
	user := types.LDAPUser{
		DN:         dn,
		Attributes: map[string][]string{"uid": {"user1"}},
	}
	args := aldproAdpt.SearchUserGroupsFilterTemplateArgs(user)
	require.Len(t, args, 2)
	require.Equal(t, dn, args[0])
	require.Equal(t, "user1", args[1])
}

// ---------------------------------------------------------------------------
// NewConnection / NewAuthenticatedConnection — constructor validation
// ---------------------------------------------------------------------------

func TestIntegrationALDPro_NewConnection_Success(t *testing.T) {
	conn := newALDProConn(t)
	require.NotNil(t, conn)
	assert.True(t, conn.IsAlive())
}

func TestIntegrationALDPro_NewConnection_EmptyHosts(t *testing.T) {
	_, err := ldapper.NewLDAPper(nil, 389, false, true, nil, aldproAdpt)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ldapper.ErrInvalidArgument))
}

func TestIntegrationALDPro_NewConnection_TooManyHosts(t *testing.T) {
	hosts := make([]string, 100)
	for i := range hosts {
		hosts[i] = fmt.Sprintf("host%d", i)
	}
	_, err := ldapper.NewLDAPper(hosts, 389, false, true, nil, aldproAdpt)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ldapper.ErrInvalidArgument))
}

func TestIntegrationALDPro_NewConnection_NilTLSConfigWhenRequired(t *testing.T) {
	_, err := ldapper.NewLDAPper([]string{aldproHost}, aldproPort, false, false, nil, aldproAdpt)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ldapper.ErrInvalidArgument))
}

func TestIntegrationALDPro_NewConnection_NilCatalogAdapter(t *testing.T) {
	_, err := ldapper.NewLDAPper([]string{aldproHost}, aldproPort, false, true, nil, nil)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ldapper.ErrInvalidArgument))
}

func TestIntegrationALDPro_NewConnection_InvalidPort(t *testing.T) {
	_, err := ldapper.NewLDAPper([]string{aldproHost}, 0, false, true, nil, aldproAdpt)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ldapper.ErrInvalidArgument))
}

func TestIntegrationALDPro_NewConnection_SSLWithSkipTLSRejected(t *testing.T) {
	_, err := ldapper.NewLDAPper([]string{aldproHost}, 636, true, true, nil, aldproAdpt)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ldapper.ErrInvalidArgument))
}

func TestIntegrationALDPro_NewConnection_UnreachableHost(t *testing.T) {
	_, err := ldapper.NewLDAPper([]string{"127.0.0.1"}, 1, false, true, nil, aldproAdpt)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ldapper.ErrUnavailable))
}

func TestIntegrationALDPro_NewAuthenticatedConnection_Success(t *testing.T) {
	conn, user, err := ldapper.NewAuthenticatedLDAPper(
		aldproSvcDN, aldproSvcPass, aldproBaseDN,
		[]string{aldproHost}, aldproPort, false, true, nil, aldproAdpt,
	)
	require.NoError(t, err)
	defer conn.Close()

	require.NotNil(t, user)
	assert.Equal(t, aldproSvcDN, user.DN)
	assert.Equal(t, aldproSvcUID, user.GetAttributeValue("uid"))
}

func TestIntegrationALDPro_NewAuthenticatedConnection_EmptyCredentials(t *testing.T) {
	_, _, err := ldapper.NewAuthenticatedLDAPper(
		"", "", aldproBaseDN,
		[]string{aldproHost}, aldproPort, false, true, nil, aldproAdpt,
	)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ldapper.ErrInvalidArgument))
}

func TestIntegrationALDPro_NewAuthenticatedConnection_WrongPassword(t *testing.T) {
	_, _, err := ldapper.NewAuthenticatedLDAPper(
		aldproSvcDN, "wrong-password", aldproBaseDN,
		[]string{aldproHost}, aldproPort, false, true, nil, aldproAdpt,
	)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ldapper.ErrInvalidCredentials))
}

// ---------------------------------------------------------------------------
// AuthenticateConn
// ---------------------------------------------------------------------------

func TestIntegrationALDPro_AuthenticateConn_Success(t *testing.T) {
	conn := newALDProConn(t)

	user, err := conn.AuthenticateConn(aldproSvcDN, aldproSvcPass, aldproBaseDN)
	require.NoError(t, err)
	require.NotNil(t, user)
	assert.Equal(t, aldproSvcDN, user.DN)
}

func TestIntegrationALDPro_AuthenticateConn_EmptyCredentials(t *testing.T) {
	conn := newALDProConn(t)
	_, err := conn.AuthenticateConn("", "", aldproBaseDN)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ldapper.ErrInvalidArgument))
}

func TestIntegrationALDPro_AuthenticateConn_WrongPassword(t *testing.T) {
	conn := newALDProConn(t)
	_, err := conn.AuthenticateConn(aldproSvcDN, "bad-password", aldproBaseDN)
	require.Error(t, err)
	// classifySensitiveBindError returns the sentinel without leaking raw text.
	assert.True(t, errors.Is(err, ldapper.ErrInvalidCredentials))
	assert.NotContains(t, err.Error(), "bad-password")
}

func TestIntegrationALDPro_AuthenticateConn_NonExistentUser(t *testing.T) {
	conn := newALDProConn(t)
	_, err := conn.AuthenticateConn(
		"cn=ghost,ou=users,"+aldproBaseDN, "whatever", aldproBaseDN,
	)
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// CheckUserCredentials — 2-arg signature; base DN from conn.bindDN.
// Failure modes:
//   - missing user     -> ErrInvalidCredentials (masked for enumeration)
//   - wrong password   -> ErrInvalidCredentials
//   - success          -> non-nil user, no error
// On any failure the returned user MUST be nil.
// ---------------------------------------------------------------------------

func TestIntegrationALDPro_CheckUserCredentials_Success(t *testing.T) {
	conn := newALDProAuthConn(t)

	user, err := conn.CheckUserCredentials(aldproUser1UID, aldproUser1Pass)
	require.NoError(t, err)
	require.NotNil(t, user)
	assert.Equal(t, aldproUser1UID, user.GetAttributeValue("uid"))
}

func TestIntegrationALDPro_CheckUserCredentials_WrongPassword(t *testing.T) {
	conn := newALDProAuthConn(t)

	user, err := conn.CheckUserCredentials(aldproUser1UID, "bad")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ldapper.ErrInvalidCredentials))
	// NB: user must be nil — returning the found user alongside an auth
	// failure invites mis-use ("if user != nil { authenticated }").
	assert.Nil(t, user)
}

func TestIntegrationALDPro_CheckUserCredentials_NonExistentUser(t *testing.T) {
	conn := newALDProAuthConn(t)

	user, err := conn.CheckUserCredentials("ghost-user", "whatever")
	require.Error(t, err)
	// Enumeration protection: missing user and wrong password must be
	// indistinguishable to the caller.
	assert.True(t, errors.Is(err, ldapper.ErrInvalidCredentials))
	assert.Nil(t, user)
}

func TestIntegrationALDPro_CheckUserCredentials_NotAuthenticated(t *testing.T) {
	conn := newALDProConn(t)
	_, err := conn.CheckUserCredentials(aldproUser1UID, aldproUser1Pass)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ldapper.ErrNotAuthenticated))
}

func TestIntegrationALDPro_CheckUserCredentials_EmptyCredentials(t *testing.T) {
	conn := newALDProAuthConn(t)
	_, err := conn.CheckUserCredentials("", "")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ldapper.ErrInvalidArgument))
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

	_, err := conn.CheckUserCredentials(aldproUser1UID, aldproUser1Pass)
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

	_, err := conn.CheckUserCredentials(aldproUser1UID, aldproUser1Pass)
	require.NoError(t, err)
}

func TestIntegrationALDPro_Close_Idempotent(t *testing.T) {
	conn := newALDProConn(t)
	conn.Close()
	conn.Close() // must not panic

	_, err := conn.GetUser(aldproUser1UID, aldproBaseDN)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ldapper.ErrClosed))
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
	assert.Equal(t, "Engineering", res.Entries[0].GetAttributeValue("rbtadp"))
}

func TestIntegrationALDPro_CustomSearch_OUFilterMatchesBothTypes(t *testing.T) {
	conn := newALDProAuthConn(t)

	req := ldap.NewSearchRequest(
		aldproBaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		0, 0, false,
		aldproAdpt.OUObjectFilter(),
		[]string{"ou"},
		nil,
	)

	res, err := conn.CustomSearch(req)
	require.NoError(t, err)

	ous := make([]string, 0, len(res.Entries))
	for _, e := range res.Entries {
		ous = append(ous, e.GetAttributeValue("ou"))
	}
	assert.Contains(t, ous, "users")
	assert.Contains(t, ous, "departments")
	assert.Contains(t, ous, "groups")
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
	assert.True(t, errors.Is(err, ldapper.ErrClosed))
}

// ---------------------------------------------------------------------------
// GetUser
// ---------------------------------------------------------------------------

func TestIntegrationALDPro_GetUser_ByUID(t *testing.T) {
	conn := newALDProAuthConn(t)

	user, err := conn.GetUser(aldproUser1UID, aldproBaseDN)
	require.NoError(t, err)
	assert.Equal(t, aldproUser1DN, user.DN)
	assert.Equal(t, "Engineering", user.GetAttributeValue("rbtadp"))
}

func TestIntegrationALDPro_GetUser_NotFound(t *testing.T) {
	conn := newALDProAuthConn(t)
	_, err := conn.GetUser("does-not-exist", aldproBaseDN)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ldapper.ErrNotFound))
}

func TestIntegrationALDPro_GetUser_EmptyUsername(t *testing.T) {
	conn := newALDProAuthConn(t)
	_, err := conn.GetUser("", aldproBaseDN)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ldapper.ErrInvalidArgument))
}

func TestIntegrationALDPro_GetUser_EmptyBaseDN(t *testing.T) {
	conn := newALDProAuthConn(t)
	_, err := conn.GetUser(aldproUser1UID, "")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ldapper.ErrInvalidArgument))
}

// ---------------------------------------------------------------------------
// GetGroup / GetOU — new single-object lookups
// ---------------------------------------------------------------------------

func TestIntegrationALDPro_GetGroup_Success(t *testing.T) {
	conn := newALDProAuthConn(t)

	group, err := conn.GetGroup("admins", aldproBaseDN)
	require.NoError(t, err)
	require.NotNil(t, group)
	assert.Contains(t, group.DN, "cn=admins")
	assert.Equal(t, "admins", group.GetAttributeValue("cn"))
}

func TestIntegrationALDPro_GetGroup_NotFound(t *testing.T) {
	conn := newALDProAuthConn(t)
	_, err := conn.GetGroup("does-not-exist", aldproBaseDN)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ldapper.ErrNotFound))
}

func TestIntegrationALDPro_GetOU_Success(t *testing.T) {
	conn := newALDProAuthConn(t)

	ou, err := conn.GetOU("users", aldproBaseDN)
	require.NoError(t, err)
	require.NotNil(t, ou)
	assert.Contains(t, ou.DN, "ou=users")
	assert.Equal(t, "users", ou.GetAttributeValue("ou"))
}

func TestIntegrationALDPro_GetOU_NotFound(t *testing.T) {
	conn := newALDProAuthConn(t)
	_, err := conn.GetOU("does-not-exist", aldproBaseDN)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ldapper.ErrNotFound))
}

// ---------------------------------------------------------------------------
// GetCatalogTree / GetSubOUs — new tree discovery
// ---------------------------------------------------------------------------

func TestIntegrationALDPro_GetCatalogTree_Success(t *testing.T) {
	conn := newALDProAuthConn(t)

	tree, err := conn.GetCatalogTree(aldproBaseDN, 0)
	require.NoError(t, err)

	// Both standard organizationalUnit and rbta-org-unit must be present.
	var names []string
	var collect func(nodes []*types.OUNormalizedInfo)
	collect = func(nodes []*types.OUNormalizedInfo) {
		for _, n := range nodes {
			names = append(names, n.Name)
			collect(n.Children)
		}
	}
	collect(tree.Tree)

	assert.Contains(t, names, "users")
	assert.Contains(t, names, "departments", "rbta-org-unit is discovered")
	assert.Contains(t, names, "groups")
}

func TestIntegrationALDPro_GetCatalogTree_MaxDepth(t *testing.T) {
	conn := newALDProAuthConn(t)

	tree, err := conn.GetCatalogTree(aldproBaseDN, 1)
	require.NoError(t, err)
	for _, root := range tree.Tree {
		assert.Empty(t, root.Children, "maxDepth=1 must trim children")
	}
}

func TestIntegrationALDPro_GetSubOUs_SingleLevel(t *testing.T) {
	conn := newALDProAuthConn(t)

	ous, err := conn.GetSubOUs(aldproBaseDN, ldap.ScopeSingleLevel)
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

	ous, err := conn.ListSingleLevelOUs(aldproBaseDN)
	require.NoError(t, err)
	assert.NotEmpty(t, ous)
}

// ---------------------------------------------------------------------------
// GetUserGroups — positive for BOTH branches of the fixed filter
// ---------------------------------------------------------------------------

func TestIntegrationALDPro_GetUserGroups_GroupOfNamesBranch(t *testing.T) {
	conn := newALDProAuthConn(t)

	groups, err := conn.GetUserGroups(aldproUser1UID, aldproBaseDN)
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"admins"}, groups)
}

func TestIntegrationALDPro_GetUserGroups_PosixGroupBranch(t *testing.T) {
	conn := newALDProAuthConn(t)

	groups, err := conn.GetUserGroups(aldproUser2UID, aldproBaseDN)
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"readers"}, groups)
}

func TestIntegrationALDPro_GetUserGroups_NoCrossContamination(t *testing.T) {
	conn := newALDProAuthConn(t)

	groups1, err := conn.GetUserGroups(aldproUser1UID, aldproBaseDN)
	require.NoError(t, err)
	assert.NotContains(t, groups1, "readers")

	groups2, err := conn.GetUserGroups(aldproUser2UID, aldproBaseDN)
	require.NoError(t, err)
	assert.NotContains(t, groups2, "admins")
}

func TestIntegrationALDPro_GetUserGroups_UserNotFound(t *testing.T) {
	conn := newALDProAuthConn(t)

	_, err := conn.GetUserGroups("nobody", aldproBaseDN)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ldapper.ErrNotFound))
}

// ---------------------------------------------------------------------------
// GetOUUsers
// ---------------------------------------------------------------------------

func TestIntegrationALDPro_GetOUUsers_StandardOU(t *testing.T) {
	conn := newALDProAuthConn(t)

	users, err := conn.GetOUUsers("ou=users," + aldproBaseDN)
	require.NoError(t, err)
	require.Len(t, users, 3) // user1, user2, svc-reader

	uids := make([]string, 0, len(users))
	for _, u := range users {
		uids = append(uids, u.GetAttributeValue("uid"))
	}
	assert.ElementsMatch(t, []string{aldproUser1UID, aldproUser2UID, aldproSvcUID}, uids)
}

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
	assert.True(t, errors.Is(err, ldapper.ErrClosed))
}

// ---------------------------------------------------------------------------
// Search / dial limits
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

func TestIntegrationALDPro_DialTimeout_Defaults(t *testing.T) {
	conn := newALDProConn(t)
	assert.Equal(t, time.Duration(0), conn.GetDialTimeout())
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
