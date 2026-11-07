//go:build integration_aldpro
// +build integration_aldpro

package ldapper_test

// ALDPro (Astra Linux Directory Pro) integration tests.
//
// ALDPro is a commercial Russian directory service built on FreeIPA/389ds
// with schema extensions (rbta-org-unit, rbtadp). No public Docker image
// exists, so this suite runs against stock osixia/openldap augmented with
// a custom schema that mirrors the ALDPro-specific pieces exercised by
// ALDPROAdapter:
//   - objectClass rbta-org-unit  (used by OUObjectFilter / SearchOUFilterTemplate)
//   - attribute   rbtadp         (used as department attribute in UserAttrs)
//
// ALDPROAdapter group filter (two positional args, member + memberIndirect +
// memberUid — mirroring OPENLDAP but with ipaUserGroup and memberIndirect):
//   (|(&(|(objectClass=groupOfNames)(objectClass=ipaUserGroup)(objectClass=posixGroup))
//       (|(member=%[1]s)(memberIndirect=%[1]s)))
//     (&(objectClass=posixGroup)(memberUid=%[2]s)))
// args = [user.DN, user.uid].
//
// ALDROAdapter does NOT implement PrimaryGroupResolver — GetUserGroups
// returns only membership-based groups.
//
// Auth-path note:
//   ALDPROAdapter.BindIdentity is pass-through (like MSAD), so binding by
//   full DN works. The osixia admin is a simpleSecurityObject that does not
//   match UserFilter; tests use a dedicated svc-reader inetOrgPerson.
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
	"github.com/NGRsoftlab/ldapper/types"
)

// ---------------------------------------------------------------------------
// Fixtures
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

	// svc-reader is a real inetOrgPerson used for authenticated binds — the
	// osixia admin is a simpleSecurityObject that UserFilter does not match.
	aldproSvcUID  = "svc-reader"
	aldproSvcPass = "svcpassword"
	aldproSvcDN   = "cn=svc-reader,ou=users,dc=aldpro,dc=test"
)

// aldproSchema mirrors ALDPro-specific schema extensions. OIDs use the
// private enterprise placeholder; they need only to be unique inside the
// ephemeral test instance, not to match real ALDPro OIDs.
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
	aldproAdpt = adapters.ALDPROAdapter{}
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
		Cmd:          []string{"--copy-service"},
		Env: map[string]string{
			"LDAP_ORGANISATION":              "ALDPro Test",
			"LDAP_DOMAIN":                    "aldpro.test",
			"LDAP_ADMIN_PASSWORD":            aldproAdminPass,
			"DISABLE_CHOWN":                  "true",
			"LDAP_REMOVE_CONFIG_AFTER_SETUP": "false",
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
// The previous test expected a single %s — that was wrong and would have
// failed against the current adapter.
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
	if _, ok := c.(interface {
		ResolvePrimaryGroupDN(context.Context, types.LDAPUser, any) (string, error)
	}); ok {
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
	assert.Equal(t, aldproSvcUID, user.GetAttributeValue("uid"))
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

// ================== AuthenticateConn ==================

func TestIntegrationALDPro_AuthenticateConn_Success(t *testing.T) {
	conn := newALDProConn(t)

	user, err := conn.AuthenticateConn(context.Background(),
		aldproSvcDN, aldproSvcPass, aldproBaseDN)
	require.NoError(t, err)
	require.NotNil(t, user)
	assert.Equal(t, aldproSvcDN, user.DN)
}

func TestIntegrationALDPro_AuthenticateConn_EmptyCredentials(t *testing.T) {
	conn := newALDProConn(t)
	_, err := conn.AuthenticateConn(context.Background(), "", "", aldproBaseDN)
	require.Error(t, err)
	assert.ErrorIs(t, err, ldapper.ErrInvalidArgument)
}

func TestIntegrationALDPro_AuthenticateConn_WrongPassword(t *testing.T) {
	conn := newALDProConn(t)
	_, err := conn.AuthenticateConn(context.Background(),
		aldproSvcDN, "bad-password", aldproBaseDN)
	require.Error(t, err)
	assert.ErrorIs(t, err, ldapper.ErrInvalidCredentials)
	assert.NotContains(t, err.Error(), "bad-password",
		"submitted credentials must not echo back")
}

func TestIntegrationALDPro_AuthenticateConn_NonExistentUser(t *testing.T) {
	conn := newALDProConn(t)
	_, err := conn.AuthenticateConn(context.Background(),
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
		[]string{"ou"},
		nil,
	)

	res, err := conn.CustomSearch(context.Background(), req)
	require.NoError(t, err)

	ous := make([]string, 0, len(res.Entries))
	for _, e := range res.Entries {
		ous = append(ous, e.GetAttributeValue("ou"))
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
	// cn= (since rbta-org-unit has no ou attribute), and the adapter's
	// GetNormalizedOUInfoFromEntry falls back to cn when ou is absent.
	ou, err := conn.GetOU(context.Background(), "departments", aldproBaseDN)
	require.NoError(t, err)
	require.NotNil(t, ou)
	assert.Contains(t, strings.ToLower(ou.DN), "cn=departments")
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

	users, err := conn.GetOUUsers(context.Background(), "ou=departments,"+aldproBaseDN)
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

func TestIntegrationALDPro_AuthenticateConn_FailedBind_InvalidatesState(t *testing.T) {
	conn := newALDProConn(t)

	_, err := conn.AuthenticateConn(context.Background(),
		aldproSvcDN, aldproSvcPass, aldproBaseDN)
	require.NoError(t, err)

	_, err = conn.AuthenticateConn(context.Background(),
		aldproSvcDN, "wrong-password", aldproBaseDN)
	require.Error(t, err)
	assert.ErrorIs(t, err, ldapper.ErrInvalidCredentials)

	_, err = conn.CheckUserCredentials(context.Background(), aldproUser1UID, aldproUser1Pass)
	require.Error(t, err)
	assert.ErrorIs(t, err, ldapper.ErrNotAuthenticated)
}

// Breaks svc-reader's password via direct LDAP Modify, then verifies that
// Reconnect — which uses the stale cached password — fails and leaves the
// client unusable (ErrClosed) instead of falling back to anonymous.
func TestIntegrationALDPro_Reconnect_RebindFailure_ClosesConnection(t *testing.T) {
	conn := newALDProConn(t)
	_, err := conn.AuthenticateConn(context.Background(),
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
