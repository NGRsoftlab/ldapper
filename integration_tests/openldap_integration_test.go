//go:build integration_openldap
// +build integration_openldap

package ldapper_test

// OpenLDAP integration tests against a real osixia/openldap container.
//
// Focus: full end-to-end coverage of ldapper.go + ldapper_search.go
// using adapters.OPENLDAPAdapter, which has correct member / memberUid
// group lookup filters:
//
//   (|(&(objectClass=groupOfNames)(member=%s))
//     (&(objectClass=posixGroup)(memberUid=%s)))
//
// with args [user.DN, user.uid]. Both branches are exercised below.
//
// The OPENLDAPAdapter's SearchUserFilterTemplate has an entryDN fallback,
// so AuthenticateConn with a DN-style bind principal is fully supported
// and exercised by every authenticated test in this file.
//
// Run with:
//   go test -tags=integration_openldap ./...

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
)

// ---------------------------------------------------------------------------
// OpenLDAP test fixtures
// ---------------------------------------------------------------------------

const (
	openldapBaseDN    = "dc=example,dc=org"
	openldapAdminDN   = "cn=admin,dc=example,dc=org"
	openldapAdminPass = "adminpassword"

	openldapUser1DN   = "cn=user1,ou=users,dc=example,dc=org"
	openldapUser1UID  = "user1"
	openldapUser1Pass = "password1"

	openldapUser2DN   = "cn=user2,ou=users,dc=example,dc=org"
	openldapUser2UID  = "user2"
	openldapUser2Pass = "password2"
)

const openldapBootstrapLDIF = `dn: ou=users,dc=example,dc=org
objectClass: organizationalUnit
ou: users

dn: ou=empty,dc=example,dc=org
objectClass: organizationalUnit
ou: empty

dn: ou=groups,dc=example,dc=org
objectClass: organizationalUnit
ou: groups

dn: cn=user1,ou=users,dc=example,dc=org
objectClass: inetOrgPerson
objectClass: posixAccount
cn: user1
sn: User
uid: user1
uidNumber: 1001
gidNumber: 1001
homeDirectory: /home/user1
userPassword: password1
mail: user1@example.org
displayName: User One

dn: cn=user2,ou=users,dc=example,dc=org
objectClass: inetOrgPerson
objectClass: posixAccount
cn: user2
sn: User
uid: user2
uidNumber: 1002
gidNumber: 1002
homeDirectory: /home/user2
userPassword: password2
mail: user2@example.org
displayName: User Two

dn: cn=dup1,ou=users,dc=example,dc=org
objectClass: inetOrgPerson
cn: dup1
sn: Dup
uid: duplicate
userPassword: dup1pass

dn: cn=dup2,ou=users,dc=example,dc=org
objectClass: inetOrgPerson
cn: dup2
sn: Dup
uid: duplicate
userPassword: dup2pass

dn: cn=admins,ou=groups,dc=example,dc=org
objectClass: groupOfNames
cn: admins
member: cn=user1,ou=users,dc=example,dc=org

dn: cn=readers,ou=groups,dc=example,dc=org
objectClass: posixGroup
cn: readers
gidNumber: 2001
memberUid: user2
`

var (
	openldapHost string
	openldapPort uint
	openldapAdpt = adapters.OPENLDAPAdapter{}
)

func TestMain(m *testing.M) {
	ctx := context.Background()

	ldifDir, err := os.MkdirTemp("", "ldapper-openldap-*")
	if err != nil {
		fmt.Fprintf(os.Stderr, "cannot create temp dir: %v\n", err)
		os.Exit(1)
	}
	defer os.RemoveAll(ldifDir)

	ldifPath := filepath.Join(ldifDir, "50-bootstrap.ldif")
	if err := os.WriteFile(ldifPath, []byte(openldapBootstrapLDIF), 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "cannot write LDIF: %v\n", err)
		os.Exit(1)
	}

	req := testcontainers.ContainerRequest{
		Image:        "osixia/openldap:1.5.0",
		ExposedPorts: []string{"389/tcp"},
		Env: map[string]string{
			"LDAP_ORGANISATION":   "Example Org",
			"LDAP_DOMAIN":         "example.org",
			"LDAP_ADMIN_PASSWORD": openldapAdminPass,
		},
		Mounts: testcontainers.ContainerMounts{
			testcontainers.ContainerMount{
				Source: testcontainers.GenericBindMountSource{HostPath: ldifPath},
				Target: testcontainers.ContainerMountTarget(
					"/container/service/slapd/assets/config/bootstrap/ldif/custom/50-bootstrap.ldif",
				),
				ReadOnly: true,
			},
		},
		WaitingFor: wait.ForLog("slapd starting").WithStartupTimeout(90 * time.Second),
	}

	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "cannot start OpenLDAP container: %v\n", err)
		os.Exit(1)
	}

	openldapHost, err = container.Host(ctx)
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
	openldapPort = uint(mappedPort.Num())

	if !waitForOpenLDAPReady(openldapHost, openldapPort, 60*time.Second) {
		_ = container.Terminate(ctx)
		fmt.Fprintln(os.Stderr, "OpenLDAP did not become ready")
		os.Exit(1)
	}

	code := m.Run()

	_ = container.Terminate(ctx)
	os.Exit(code)
}

func waitForOpenLDAPReady(host string, port uint, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		c, err := ldap.DialURL(fmt.Sprintf("ldap://%s:%d", host, port))
		if err == nil {
			err = c.Bind(openldapAdminDN, openldapAdminPass)
			_ = c.Close()
			if err == nil {
				return true
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	return false
}

func newOpenLDAPConn(t *testing.T, opts ...ldapper.Option) *ldapper.LDAPper {
	t.Helper()
	conn, err := ldapper.NewLDAPper(
		[]string{openldapHost},
		openldapPort,
		false, // useSSL
		true,  // skipTLS
		nil,
		openldapAdpt,
		opts...,
	)
	require.NoError(t, err)
	t.Cleanup(conn.Close)
	return conn
}

// newOpenLDAPAuthConn authenticates as user1. The OPENLDAPAdapter's search
// template has an entryDN fallback, so binding with a DN works cleanly.
func newOpenLDAPAuthConn(t *testing.T, opts ...ldapper.Option) *ldapper.LDAPper {
	t.Helper()
	conn, _, err := ldapper.NewAuthenticatedLDAPper(
		openldapUser1DN, openldapUser1Pass, openldapBaseDN,
		[]string{openldapHost},
		openldapPort,
		false,
		true,
		nil,
		openldapAdpt,
		opts...,
	)
	require.NoError(t, err)
	t.Cleanup(conn.Close)
	return conn
}

// ---------------------------------------------------------------------------
// NewConnection / NewAuthenticatedConnection
// ---------------------------------------------------------------------------

func TestIntegrationOpenLDAP_NewConnection_Success(t *testing.T) {
	conn := newOpenLDAPConn(t)
	require.NotNil(t, conn)
	assert.True(t, conn.IsAlive())
}

func TestIntegrationOpenLDAP_NewConnection_EmptyHosts(t *testing.T) {
	_, err := ldapper.NewLDAPper(nil, 389, false, true, nil, openldapAdpt)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ldapper.ErrInvalidArgument))
}

func TestIntegrationOpenLDAP_NewConnection_TooManyHosts(t *testing.T) {
	hosts := make([]string, 100)
	for i := range hosts {
		hosts[i] = fmt.Sprintf("host%d", i)
	}
	_, err := ldapper.NewLDAPper(hosts, 389, false, true, nil, openldapAdpt)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ldapper.ErrInvalidArgument))
}

func TestIntegrationOpenLDAP_NewConnection_NilTLSConfigWhenRequired(t *testing.T) {
	_, err := ldapper.NewLDAPper([]string{openldapHost}, openldapPort, false, false, nil, openldapAdpt)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ldapper.ErrInvalidArgument))
}

func TestIntegrationOpenLDAP_NewConnection_NilCatalogAdapter(t *testing.T) {
	_, err := ldapper.NewLDAPper([]string{openldapHost}, openldapPort, false, true, nil, nil)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ldapper.ErrInvalidArgument))
}

func TestIntegrationOpenLDAP_NewConnection_UnreachableHost(t *testing.T) {
	_, err := ldapper.NewLDAPper([]string{"127.0.0.1"}, 1, false, true, nil, openldapAdpt)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ldapper.ErrUnavailable))
}

func TestIntegrationOpenLDAP_NewAuthenticatedConnection_Success(t *testing.T) {
	conn, user, err := ldapper.NewAuthenticatedLDAPper(
		openldapUser1DN, openldapUser1Pass, openldapBaseDN,
		[]string{openldapHost}, openldapPort, false, true, nil, openldapAdpt,
	)
	require.NoError(t, err)
	defer conn.Close()

	require.NotNil(t, user)
	assert.Equal(t, openldapUser1DN, user.DN)
	assert.Equal(t, openldapUser1UID, user.GetAttributeValue("uid"))
}

func TestIntegrationOpenLDAP_NewAuthenticatedConnection_EmptyCredentials(t *testing.T) {
	_, _, err := ldapper.NewAuthenticatedLDAPper(
		"", "", openldapBaseDN,
		[]string{openldapHost}, openldapPort, false, true, nil, openldapAdpt,
	)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ldapper.ErrInvalidArgument))
}

func TestIntegrationOpenLDAP_NewAuthenticatedConnection_WrongPassword(t *testing.T) {
	_, _, err := ldapper.NewAuthenticatedLDAPper(
		openldapUser1DN, "wrong-password", openldapBaseDN,
		[]string{openldapHost}, openldapPort, false, true, nil, openldapAdpt,
	)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ldapper.ErrInvalidCredentials))
}

// ---------------------------------------------------------------------------
// AuthenticateConn
// ---------------------------------------------------------------------------

func TestIntegrationOpenLDAP_AuthenticateConn_Success(t *testing.T) {
	conn := newOpenLDAPConn(t)

	user, err := conn.AuthenticateConn(openldapUser1DN, openldapUser1Pass, openldapBaseDN)
	require.NoError(t, err)
	require.NotNil(t, user)
	assert.Equal(t, openldapUser1DN, user.DN)
	assert.Equal(t, openldapUser1UID, user.GetAttributeValue("uid"))
	assert.Equal(t, "user1@example.org", user.GetAttributeValue("mail"))
}

func TestIntegrationOpenLDAP_AuthenticateConn_EmptyCredentials(t *testing.T) {
	conn := newOpenLDAPConn(t)
	_, err := conn.AuthenticateConn("", "", openldapBaseDN)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ldapper.ErrInvalidArgument))
}

func TestIntegrationOpenLDAP_AuthenticateConn_WrongPassword(t *testing.T) {
	conn := newOpenLDAPConn(t)
	_, err := conn.AuthenticateConn(openldapUser1DN, "bad-password", openldapBaseDN)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ldapper.ErrInvalidCredentials))
}

func TestIntegrationOpenLDAP_AuthenticateConn_NonExistentUser(t *testing.T) {
	conn := newOpenLDAPConn(t)
	_, err := conn.AuthenticateConn("cn=ghost,ou=users,dc=example,dc=org", "whatever", openldapBaseDN)
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// CheckUserCredentials — 2-arg signature, base DN from conn.bindDN
// ---------------------------------------------------------------------------

func TestIntegrationOpenLDAP_CheckUserCredentials_Success(t *testing.T) {
	conn := newOpenLDAPAuthConn(t)

	user, err := conn.CheckUserCredentials(openldapUser2UID, openldapUser2Pass)
	require.NoError(t, err)
	require.NotNil(t, user)
	assert.Equal(t, openldapUser2DN, user.DN)
	assert.Equal(t, openldapUser2UID, user.GetAttributeValue("uid"))
}

func TestIntegrationOpenLDAP_CheckUserCredentials_WrongPassword(t *testing.T) {
	conn := newOpenLDAPAuthConn(t)

	user, err := conn.CheckUserCredentials(openldapUser2UID, "bad")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ldapper.ErrInvalidCredentials))
	assert.Nil(t, user)
}

func TestIntegrationOpenLDAP_CheckUserCredentials_NonExistentUser(t *testing.T) {
	conn := newOpenLDAPAuthConn(t)
	user, err := conn.CheckUserCredentials("ghost-user", "whatever")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ldapper.ErrInvalidCredentials))
	assert.Nil(t, user)
}

func TestIntegrationOpenLDAP_CheckUserCredentials_NotAuthenticated(t *testing.T) {
	conn := newOpenLDAPConn(t)
	_, err := conn.CheckUserCredentials(openldapUser2UID, openldapUser2Pass)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ldapper.ErrNotAuthenticated))
}

func TestIntegrationOpenLDAP_CheckUserCredentials_EmptyCredentials(t *testing.T) {
	conn := newOpenLDAPAuthConn(t)
	_, err := conn.CheckUserCredentials("", "")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ldapper.ErrInvalidArgument))
}

// ---------------------------------------------------------------------------
// IsAlive / Reconnect / EnsureAlive / Close
// ---------------------------------------------------------------------------

func TestIntegrationOpenLDAP_IsAlive_ActiveConnection(t *testing.T) {
	conn := newOpenLDAPConn(t)
	assert.True(t, conn.IsAlive())
}

func TestIntegrationOpenLDAP_IsAlive_AfterClose(t *testing.T) {
	conn := newOpenLDAPConn(t)
	conn.Close()
	assert.False(t, conn.IsAlive())
}

func TestIntegrationOpenLDAP_Reconnect_Unauthenticated(t *testing.T) {
	conn := newOpenLDAPConn(t)
	require.True(t, conn.IsAlive())
	require.NoError(t, conn.Reconnect())
	assert.True(t, conn.IsAlive())
}

func TestIntegrationOpenLDAP_Reconnect_PreservesAuthentication(t *testing.T) {
	conn := newOpenLDAPAuthConn(t)
	require.NoError(t, conn.Reconnect())

	_, err := conn.CheckUserCredentials(openldapUser2UID, openldapUser2Pass)
	require.NoError(t, err)
}

func TestIntegrationOpenLDAP_EnsureAlive_NoopWhenAlive(t *testing.T) {
	conn := newOpenLDAPConn(t)
	require.NoError(t, conn.EnsureAlive())
	assert.True(t, conn.IsAlive())
}

func TestIntegrationOpenLDAP_EnsureAlive_ReconnectsAfterClose(t *testing.T) {
	conn := newOpenLDAPAuthConn(t)
	conn.Close()
	require.False(t, conn.IsAlive())

	require.NoError(t, conn.EnsureAlive())
	assert.True(t, conn.IsAlive())

	_, err := conn.CheckUserCredentials(openldapUser2UID, openldapUser2Pass)
	require.NoError(t, err)
}

func TestIntegrationOpenLDAP_Close_Idempotent(t *testing.T) {
	conn := newOpenLDAPConn(t)
	conn.Close()
	conn.Close() // must not panic

	_, err := conn.GetUser(openldapUser1UID, openldapBaseDN)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ldapper.ErrClosed))
}

// ---------------------------------------------------------------------------
// CustomSearch
// ---------------------------------------------------------------------------

func TestIntegrationOpenLDAP_CustomSearch_Success(t *testing.T) {
	conn := newOpenLDAPAuthConn(t)

	req := ldap.NewSearchRequest(
		openldapBaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		0, 0, false, "(uid=user1)", []string{"cn", "mail"}, nil,
	)

	res, err := conn.CustomSearch(req)
	require.NoError(t, err)
	require.Len(t, res.Entries, 1)
	assert.Equal(t, openldapUser1DN, res.Entries[0].DN)
	assert.Equal(t, "user1@example.org", res.Entries[0].GetAttributeValue("mail"))
}

func TestIntegrationOpenLDAP_CustomSearch_NotInitialized(t *testing.T) {
	conn := newOpenLDAPConn(t)
	conn.Close()

	req := ldap.NewSearchRequest(
		openldapBaseDN, ldap.ScopeBaseObject, ldap.NeverDerefAliases,
		0, 0, false, "(objectClass=*)", nil, nil,
	)
	_, err := conn.CustomSearch(req)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ldapper.ErrClosed))
}

// ---------------------------------------------------------------------------
// GetUser
// ---------------------------------------------------------------------------

func TestIntegrationOpenLDAP_GetUser_ByUID(t *testing.T) {
	conn := newOpenLDAPAuthConn(t)

	user, err := conn.GetUser(openldapUser1UID, openldapBaseDN)
	require.NoError(t, err)
	assert.Equal(t, openldapUser1DN, user.DN)
	assert.Equal(t, "user1", user.GetAttributeValue("uid"))
	assert.Equal(t, "User One", user.GetAttributeValue("displayName"))
}

func TestIntegrationOpenLDAP_GetUser_ByDN(t *testing.T) {
	conn := newOpenLDAPAuthConn(t)

	user, err := conn.GetUser(openldapUser1DN, openldapBaseDN)
	require.NoError(t, err)
	assert.Equal(t, openldapUser1DN, user.DN)
}

func TestIntegrationOpenLDAP_GetUser_NotFound(t *testing.T) {
	conn := newOpenLDAPAuthConn(t)
	_, err := conn.GetUser("does-not-exist", openldapBaseDN)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ldapper.ErrNotFound))
}

func TestIntegrationOpenLDAP_GetUser_TooManyEntries(t *testing.T) {
	conn := newOpenLDAPAuthConn(t)
	_, err := conn.GetUser("duplicate", openldapBaseDN)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ldapper.ErrAmbiguousResult))
}

func TestIntegrationOpenLDAP_GetUser_NotInitialized(t *testing.T) {
	conn := newOpenLDAPConn(t)
	conn.Close()

	_, err := conn.GetUser(openldapUser1UID, openldapBaseDN)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ldapper.ErrClosed))
}

// ---------------------------------------------------------------------------
// GetGroup / GetOU
// ---------------------------------------------------------------------------

func TestIntegrationOpenLDAP_GetGroup_Success(t *testing.T) {
	conn := newOpenLDAPAuthConn(t)

	group, err := conn.GetGroup("admins", openldapBaseDN)
	require.NoError(t, err)
	require.NotNil(t, group)
	assert.Equal(t, "admins", group.GetAttributeValue("cn"))
}

func TestIntegrationOpenLDAP_GetGroup_NotFound(t *testing.T) {
	conn := newOpenLDAPAuthConn(t)
	_, err := conn.GetGroup("does-not-exist", openldapBaseDN)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ldapper.ErrNotFound))
}

func TestIntegrationOpenLDAP_GetOU_Success(t *testing.T) {
	conn := newOpenLDAPAuthConn(t)

	ou, err := conn.GetOU("users", openldapBaseDN)
	require.NoError(t, err)
	require.NotNil(t, ou)
	assert.Equal(t, "users", ou.GetAttributeValue("ou"))
}

func TestIntegrationOpenLDAP_GetOU_NotFound(t *testing.T) {
	conn := newOpenLDAPAuthConn(t)
	_, err := conn.GetOU("does-not-exist", openldapBaseDN)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ldapper.ErrNotFound))
}

// ---------------------------------------------------------------------------
// GetCatalogTree / GetSubOUs / ListSingleLevelOUs
// ---------------------------------------------------------------------------

func TestIntegrationOpenLDAP_GetCatalogTree_Success(t *testing.T) {
	conn := newOpenLDAPAuthConn(t)

	tree, err := conn.GetCatalogTree(openldapBaseDN, 0)
	require.NoError(t, err)
	assert.NotEmpty(t, tree.Tree)
}

func TestIntegrationOpenLDAP_GetCatalogTree_MaxDepth(t *testing.T) {
	conn := newOpenLDAPAuthConn(t)

	tree, err := conn.GetCatalogTree(openldapBaseDN, 1)
	require.NoError(t, err)
	for _, root := range tree.Tree {
		assert.Empty(t, root.Children)
	}
}

func TestIntegrationOpenLDAP_GetSubOUs_SingleLevel(t *testing.T) {
	conn := newOpenLDAPAuthConn(t)

	ous, err := conn.GetSubOUs(openldapBaseDN, ldap.ScopeSingleLevel)
	require.NoError(t, err)

	var names []string
	for _, ou := range ous {
		names = append(names, ou.Name)
	}
	assert.Contains(t, names, "users")
	assert.Contains(t, names, "groups")
	assert.Contains(t, names, "empty")
}

func TestIntegrationOpenLDAP_ListSingleLevelOUs(t *testing.T) {
	conn := newOpenLDAPAuthConn(t)

	ous, err := conn.ListSingleLevelOUs(openldapBaseDN)
	require.NoError(t, err)
	assert.NotEmpty(t, ous)
}

// ---------------------------------------------------------------------------
// GetUserGroups — both branches of the filter
// ---------------------------------------------------------------------------

func TestIntegrationOpenLDAP_GetUserGroups_GroupOfNamesBranch(t *testing.T) {
	conn := newOpenLDAPAuthConn(t)

	groups, err := conn.GetUserGroups(openldapUser1UID, openldapBaseDN)
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"admins"}, groups)
}

func TestIntegrationOpenLDAP_GetUserGroups_PosixGroupBranch(t *testing.T) {
	conn := newOpenLDAPAuthConn(t)

	groups, err := conn.GetUserGroups(openldapUser2UID, openldapBaseDN)
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"readers"}, groups)
}

func TestIntegrationOpenLDAP_GetUserGroups_AmbiguousUser(t *testing.T) {
	conn := newOpenLDAPAuthConn(t)

	// duplicate users resolve to more than one entry; the group search
	// must never happen and the user lookup must surface the ambiguity.
	_, err := conn.GetUserGroups("duplicate", openldapBaseDN)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ldapper.ErrAmbiguousResult))
}

func TestIntegrationOpenLDAP_GetUserGroups_UserNotFound(t *testing.T) {
	conn := newOpenLDAPAuthConn(t)

	_, err := conn.GetUserGroups("nobody", openldapBaseDN)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ldapper.ErrNotFound))
}

// ---------------------------------------------------------------------------
// GetOUUsers
// ---------------------------------------------------------------------------

func TestIntegrationOpenLDAP_GetOUUsers_Success(t *testing.T) {
	conn := newOpenLDAPAuthConn(t)

	users, err := conn.GetOUUsers("ou=users," + openldapBaseDN)
	require.NoError(t, err)
	require.Len(t, users, 4) // user1, user2, dup1, dup2

	dns := make([]string, 0, len(users))
	for _, u := range users {
		dns = append(dns, u.DN)
	}
	assert.Contains(t, dns, openldapUser1DN)
	assert.Contains(t, dns, openldapUser2DN)
}

func TestIntegrationOpenLDAP_GetOUUsers_EmptyOU(t *testing.T) {
	conn := newOpenLDAPAuthConn(t)

	users, err := conn.GetOUUsers("ou=empty," + openldapBaseDN)
	require.NoError(t, err)
	assert.Empty(t, users)
}

func TestIntegrationOpenLDAP_GetOUUsers_NotInitialized(t *testing.T) {
	conn := newOpenLDAPConn(t)
	conn.Close()

	_, err := conn.GetOUUsers("ou=users," + openldapBaseDN)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ldapper.ErrClosed))
}

// ---------------------------------------------------------------------------
// Search / dial limits
// ---------------------------------------------------------------------------

func TestIntegrationOpenLDAP_SearchLimits_Defaults(t *testing.T) {
	conn := newOpenLDAPConn(t)
	limits := conn.GetSearchLimits()
	assert.Equal(t, 0, limits.SizeLimit)
	assert.Equal(t, 30, limits.TimeLimit)
}

func TestIntegrationOpenLDAP_SearchLimits_WithOption(t *testing.T) {
	conn := newOpenLDAPConn(t, ldapper.WithSearchLimits(5, 10))
	limits := conn.GetSearchLimits()
	assert.Equal(t, 5, limits.SizeLimit)
	assert.Equal(t, 10, limits.TimeLimit)
}

func TestIntegrationOpenLDAP_SearchLimits_SetAtRuntime(t *testing.T) {
	conn := newOpenLDAPConn(t)
	conn.SetSearchLimits(7, 11)
	limits := conn.GetSearchLimits()
	assert.Equal(t, 7, limits.SizeLimit)
	assert.Equal(t, 11, limits.TimeLimit)
}

func TestIntegrationOpenLDAP_SearchLimits_NegativeClampedToZero(t *testing.T) {
	conn := newOpenLDAPConn(t)
	conn.SetSearchLimits(-1, -5)
	limits := conn.GetSearchLimits()
	assert.Equal(t, 0, limits.SizeLimit)
	assert.Equal(t, 0, limits.TimeLimit)
}

func TestIntegrationOpenLDAP_DialTimeout_Defaults(t *testing.T) {
	conn := newOpenLDAPConn(t)
	assert.Equal(t, time.Duration(0), conn.GetDialTimeout())
}

func TestIntegrationOpenLDAP_DialTimeout_WithOption(t *testing.T) {
	conn := newOpenLDAPConn(t, ldapper.WithDialTimeout(3*time.Second))
	assert.Equal(t, 3*time.Second, conn.GetDialTimeout())
}

func TestIntegrationOpenLDAP_DialTimeout_SetAtRuntime(t *testing.T) {
	conn := newOpenLDAPConn(t)
	conn.SetDialTimeout(2 * time.Second)
	assert.Equal(t, 2*time.Second, conn.GetDialTimeout())
}

func TestIntegrationOpenLDAP_DialTimeout_NegativeClampedToZero(t *testing.T) {
	conn := newOpenLDAPConn(t)
	conn.SetDialTimeout(-1 * time.Second)
	assert.Equal(t, time.Duration(0), conn.GetDialTimeout())
}

func TestIntegrationOpenLDAP_AuthenticateConn_FailedBind_InvalidatesState(t *testing.T) {
	conn := newOpenLDAPConn(t)

	// 1. Successfully authenticate as user1.
	_, err := conn.AuthenticateConn(openldapUser1DN, openldapUser1Pass, openldapBaseDN)
	require.NoError(t, err)

	// 2. Attempt to authenticate as user1 with a wrong password on the same
	//    connection. RFC 4513 §4 transitions the live session to anonymous.
	_, err = conn.AuthenticateConn(openldapUser1DN, "wrong-password", openldapBaseDN)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ldapper.ErrInvalidCredentials))

	// 3. The connection must report ErrNotAuthenticated — the cached
	//    service-session state must not survive a failed Bind.
	_, err = conn.CheckUserCredentials(openldapUser2UID, openldapUser2Pass)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ldapper.ErrNotAuthenticated),
		"post-failed-bind connection must not be treated as authenticated")
}
