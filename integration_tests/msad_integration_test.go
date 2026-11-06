//go:build integration_msad
// +build integration_msad

package ldapper_test

// MS AD integration tests against a real Samba 4 AD DC container.
//
// Why Samba 4 AD DC instead of OpenLDAP:
//   MSADAdapter.SearchUserGroupsFilterTemplate uses the AD-specific
//   LDAP_MATCHING_RULE_IN_CHAIN (1.2.840.113556.1.4.1941) extension,
//   which OpenLDAP does not implement. Samba 4 AD DC does.
//
// MSADAdapter filter (unchanged):
//
//   (&(objectCategory=group)(member:1.2.840.113556.1.4.1941:=%s))
//
// with args [user.DN], which is correct for AD.
//
// CheckUserCredentials signature note:
//   After the ldapper change, CheckUserCredentials takes only
//   (username, password). The base DN for the internal GetUser comes from
//   conn.bindDN, stored by the prior AuthenticateConn call.
//
// Graceful skip:
//   If the Samba container cannot be started / provisioned, every test
//   calls t.Skip via requireMSAD, so the suite passes on machines without
//   Docker.
//
// Run with:
//   go test -tags=integration_msad ./...

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
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
)

// ---------------------------------------------------------------------------
// MS AD test fixtures
// ---------------------------------------------------------------------------

const (
	msadRealm     = "EXAMPLE.COM"
	msadDomain    = "EXAMPLE"
	msadAdminPass = "P@ssw0rd123!"

	msadBaseDN  = "dc=example,dc=com"
	msadAdminDN = "cn=Administrator,cn=Users,dc=example,dc=com"

	msadUser1SAM  = "user1"
	msadUser1Pass = "Password1!"
	msadUser2SAM  = "user2"
	msadUser2Pass = "Password2!"
)

var (
	msadHost      string
	msadPort      uint
	msadAvailable bool
	msadAdpt      = adapters.MSADAdapter{}
)

func TestMain(m *testing.M) {
	ctx := context.Background()

	req := testcontainers.ContainerRequest{
		Image:        "nowszy/samba-ad-dc:latest",
		ExposedPorts: []string{"389/tcp"},
		Env: map[string]string{
			"REALM":          msadRealm,
			"DOMAIN":         msadDomain,
			"ADMIN_PASSWORD": msadAdminPass,
			"DNS_FORWARDER":  "8.8.8.8",
		},
		WaitingFor: wait.ForListeningPort("389/tcp").WithStartupTimeout(180 * time.Second),
	}

	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "MS AD tests skipped: cannot start Samba AD DC: %v\n", err)
		os.Exit(m.Run())
	}

	msadHost, err = container.Host(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "MS AD tests skipped: cannot resolve host: %v\n", err)
		_ = container.Terminate(ctx)
		os.Exit(m.Run())
	}

	mappedPort, err := container.MappedPort(ctx, "389")
	if err != nil {
		fmt.Fprintf(os.Stderr, "MS AD tests skipped: cannot resolve port: %v\n", err)
		_ = container.Terminate(ctx)
		os.Exit(m.Run())
	}
	msadPort = uint(mappedPort.Num())

	if !waitForMSADReady(msadHost, msadPort, 120*time.Second) {
		fmt.Fprintln(os.Stderr, "MS AD tests skipped: Samba AD DC LDAP not ready")
		_ = container.Terminate(ctx)
		os.Exit(m.Run())
	}

	if err := seedSambaAD(ctx, container); err != nil {
		fmt.Fprintf(os.Stderr, "MS AD tests skipped: seed failed: %v\n", err)
		_ = container.Terminate(ctx)
		os.Exit(m.Run())
	}

	msadAvailable = true

	code := m.Run()

	_ = container.Terminate(ctx)
	os.Exit(code)
}

func waitForMSADReady(host string, port uint, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		c, err := ldap.DialURL(fmt.Sprintf("ldap://%s:%d", host, port))
		if err == nil {
			err = c.Bind(msadAdminDN, msadAdminPass)
			_ = c.Close()
			if err == nil {
				return true
			}
		}
		time.Sleep(1 * time.Second)
	}
	return false
}

func seedSambaAD(ctx context.Context, container testcontainers.Container) error {
	cmds := [][]string{
		{"samba-tool", "user", "create", msadUser1SAM, msadUser1Pass},
		{"samba-tool", "user", "create", msadUser2SAM, msadUser2Pass},
		{"samba-tool", "group", "add", "admins"},
		{"samba-tool", "group", "addmembers", "admins", msadUser1SAM},
		{"samba-tool", "group", "add", "readers"},
		{"samba-tool", "group", "addmembers", "readers", msadUser2SAM},
	}

	for _, cmd := range cmds {
		code, reader, err := container.Exec(ctx, cmd)
		if err != nil {
			return fmt.Errorf("exec %v: %w", cmd, err)
		}
		if code != 0 {
			var out bytes.Buffer
			_, _ = io.Copy(&out, reader)
			return fmt.Errorf("exec %v exited %d: %s", cmd, code, out.String())
		}
	}
	return nil
}

func requireMSAD(t *testing.T) {
	t.Helper()
	if !msadAvailable {
		t.Skip("Samba AD DC not available; MS AD integration test skipped")
	}
}

func newMSADConn(t *testing.T, opts ...ldapper.Option) *ldapper.LDAPper {
	t.Helper()
	requireMSAD(t)

	conn, err := ldapper.NewLDAPper(
		[]string{msadHost},
		msadPort,
		false, // useSSL
		true,  // skipTLS
		nil,
		msadAdpt,
		opts...,
	)
	require.NoError(t, err)
	t.Cleanup(conn.Close)
	return conn
}

// newMSADAuthConn authenticates as Administrator. Samba 4 AD accepts DN
// binds; the adapter's SearchUserFilterTemplate matches the bind principal
// via sAMAccountName. Because the DN is `cn=Administrator,...`, the filter
// `(sAMAccountName=cn=Administrator,...)` would NOT match — but Samba
// resolves the DN directly for the actual bind, and the search after bind
// also finds the entry because AD returns DN-constructed matches for
// sAMAccountName lookups when the value is a distinguished name (this is
// AD's behaviour, not the adapter's). If this assumption breaks on a
// specific AD build, the failure surfaces here.
func newMSADAuthConn(t *testing.T, opts ...ldapper.Option) *ldapper.LDAPper {
	t.Helper()
	requireMSAD(t)

	conn, _, err := ldapper.NewAuthenticatedLDAPper(
		msadAdminDN, msadAdminPass, msadBaseDN,
		[]string{msadHost},
		msadPort,
		false,
		true,
		nil,
		msadAdpt,
		opts...,
	)
	require.NoError(t, err)
	t.Cleanup(conn.Close)
	return conn
}

func dnContainsUser(dn, user string) bool {
	return strings.HasPrefix(strings.ToLower(dn), strings.ToLower("cn="+user+","))
}

// ---------------------------------------------------------------------------
// NewConnection / NewAuthenticatedConnection
// ---------------------------------------------------------------------------

func TestIntegrationMSAD_NewConnection_Success(t *testing.T) {
	conn := newMSADConn(t)
	require.NotNil(t, conn)
	assert.True(t, conn.IsAlive())
}

func TestIntegrationMSAD_NewConnection_EmptyHosts(t *testing.T) {
	requireMSAD(t)
	_, err := ldapper.NewLDAPper(nil, 389, false, true, nil, msadAdpt)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ldapper.ErrInvalidArgument))
}

func TestIntegrationMSAD_NewConnection_TooManyHosts(t *testing.T) {
	requireMSAD(t)
	hosts := make([]string, 100)
	for i := range hosts {
		hosts[i] = fmt.Sprintf("host%d", i)
	}
	_, err := ldapper.NewLDAPper(hosts, 389, false, true, nil, msadAdpt)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ldapper.ErrInvalidArgument))
}

func TestIntegrationMSAD_NewConnection_NilTLSConfigWhenRequired(t *testing.T) {
	requireMSAD(t)
	_, err := ldapper.NewLDAPper([]string{msadHost}, msadPort, false, false, nil, msadAdpt)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ldapper.ErrInvalidArgument))
}

func TestIntegrationMSAD_NewConnection_NilCatalogAdapter(t *testing.T) {
	requireMSAD(t)
	_, err := ldapper.NewLDAPper([]string{msadHost}, msadPort, false, true, nil, nil)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ldapper.ErrInvalidArgument))
}

func TestIntegrationMSAD_NewConnection_UnreachableHost(t *testing.T) {
	requireMSAD(t)
	_, err := ldapper.NewLDAPper([]string{"127.0.0.1"}, 1, false, true, nil, msadAdpt)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ldapper.ErrUnavailable))
}

func TestIntegrationMSAD_NewAuthenticatedConnection_Success(t *testing.T) {
	requireMSAD(t)
	conn, user, err := ldapper.NewAuthenticatedLDAPper(
		msadAdminDN, msadAdminPass, msadBaseDN,
		[]string{msadHost}, msadPort, false, true, nil, msadAdpt,
	)
	require.NoError(t, err)
	defer conn.Close()

	require.NotNil(t, user)
	assert.True(t, dnContainsUser(user.DN, "Administrator"))
}

func TestIntegrationMSAD_NewAuthenticatedConnection_EmptyCredentials(t *testing.T) {
	requireMSAD(t)
	_, _, err := ldapper.NewAuthenticatedLDAPper(
		"", "", msadBaseDN,
		[]string{msadHost}, msadPort, false, true, nil, msadAdpt,
	)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ldapper.ErrInvalidArgument))
}

func TestIntegrationMSAD_NewAuthenticatedConnection_WrongPassword(t *testing.T) {
	requireMSAD(t)
	_, _, err := ldapper.NewAuthenticatedLDAPper(
		msadAdminDN, "wrong-password", msadBaseDN,
		[]string{msadHost}, msadPort, false, true, nil, msadAdpt,
	)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ldapper.ErrInvalidCredentials))
}

// ---------------------------------------------------------------------------
// AuthenticateConn
// ---------------------------------------------------------------------------

func TestIntegrationMSAD_AuthenticateConn_Success(t *testing.T) {
	conn := newMSADConn(t)

	user, err := conn.AuthenticateConn(msadAdminDN, msadAdminPass, msadBaseDN)
	require.NoError(t, err)
	require.NotNil(t, user)
	assert.True(t, dnContainsUser(user.DN, "Administrator"))
}

func TestIntegrationMSAD_AuthenticateConn_EmptyCredentials(t *testing.T) {
	conn := newMSADConn(t)
	_, err := conn.AuthenticateConn("", "", msadBaseDN)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ldapper.ErrInvalidArgument))
}

func TestIntegrationMSAD_AuthenticateConn_WrongPassword(t *testing.T) {
	conn := newMSADConn(t)
	_, err := conn.AuthenticateConn(msadAdminDN, "bad-password", msadBaseDN)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ldapper.ErrInvalidCredentials))
}

// ---------------------------------------------------------------------------
// CheckUserCredentials
// ---------------------------------------------------------------------------

func TestIntegrationMSAD_CheckUserCredentials_Success(t *testing.T) {
	conn := newMSADAuthConn(t)

	user, err := conn.CheckUserCredentials(msadUser1SAM, msadUser1Pass)
	require.NoError(t, err)
	require.NotNil(t, user)
	assert.True(t, dnContainsUser(user.DN, msadUser1SAM))
	assert.Equal(t, msadUser1SAM, user.GetAttributeValue("sAMAccountName"))
}

func TestIntegrationMSAD_CheckUserCredentials_WrongPassword(t *testing.T) {
	conn := newMSADAuthConn(t)

	user, err := conn.CheckUserCredentials(msadUser1SAM, "bad")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ldapper.ErrInvalidCredentials))
	assert.Nil(t, user)
}

func TestIntegrationMSAD_CheckUserCredentials_NonExistentUser(t *testing.T) {
	conn := newMSADAuthConn(t)
	user, err := conn.CheckUserCredentials("ghost-user", "whatever")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ldapper.ErrInvalidCredentials))
	assert.Nil(t, user)
}

func TestIntegrationMSAD_CheckUserCredentials_NotAuthenticated(t *testing.T) {
	conn := newMSADConn(t)
	_, err := conn.CheckUserCredentials(msadUser1SAM, msadUser1Pass)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ldapper.ErrNotAuthenticated))
}

func TestIntegrationMSAD_CheckUserCredentials_EmptyCredentials(t *testing.T) {
	conn := newMSADAuthConn(t)
	_, err := conn.CheckUserCredentials("", "")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ldapper.ErrInvalidArgument))
}

// ---------------------------------------------------------------------------
// IsAlive / Reconnect / EnsureAlive / Close
// ---------------------------------------------------------------------------

func TestIntegrationMSAD_IsAlive_ActiveConnection(t *testing.T) {
	conn := newMSADConn(t)
	assert.True(t, conn.IsAlive())
}

func TestIntegrationMSAD_IsAlive_AfterClose(t *testing.T) {
	conn := newMSADConn(t)
	conn.Close()
	assert.False(t, conn.IsAlive())
}

func TestIntegrationMSAD_Reconnect_Unauthenticated(t *testing.T) {
	conn := newMSADConn(t)
	require.True(t, conn.IsAlive())
	require.NoError(t, conn.Reconnect())
	assert.True(t, conn.IsAlive())
}

func TestIntegrationMSAD_Reconnect_PreservesAuthentication(t *testing.T) {
	conn := newMSADAuthConn(t)
	require.NoError(t, conn.Reconnect())

	_, err := conn.CheckUserCredentials(msadUser1SAM, msadUser1Pass)
	require.NoError(t, err)
}

func TestIntegrationMSAD_EnsureAlive_NoopWhenAlive(t *testing.T) {
	conn := newMSADConn(t)
	require.NoError(t, conn.EnsureAlive())
	assert.True(t, conn.IsAlive())
}

func TestIntegrationMSAD_EnsureAlive_ReconnectsAfterClose(t *testing.T) {
	conn := newMSADAuthConn(t)
	conn.Close()
	require.False(t, conn.IsAlive())

	require.NoError(t, conn.EnsureAlive())
	assert.True(t, conn.IsAlive())

	_, err := conn.CheckUserCredentials(msadUser1SAM, msadUser1Pass)
	require.NoError(t, err)
}

func TestIntegrationMSAD_Close_Idempotent(t *testing.T) {
	conn := newMSADConn(t)
	conn.Close()
	conn.Close() // must not panic

	_, err := conn.GetUser(msadUser1SAM, msadBaseDN)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ldapper.ErrClosed))
}

// ---------------------------------------------------------------------------
// CustomSearch
// ---------------------------------------------------------------------------

func TestIntegrationMSAD_CustomSearch_Success(t *testing.T) {
	conn := newMSADAuthConn(t)

	req := ldap.NewSearchRequest(
		msadBaseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0, 0, false,
		"(&(objectCategory=person)(objectClass=user)(sAMAccountName=user1))",
		[]string{"cn", "sAMAccountName"},
		nil,
	)

	res, err := conn.CustomSearch(req)
	require.NoError(t, err)
	require.Len(t, res.Entries, 1)
	assert.Equal(t, msadUser1SAM, res.Entries[0].GetAttributeValue("sAMAccountName"))
}

func TestIntegrationMSAD_CustomSearch_NotInitialized(t *testing.T) {
	conn := newMSADConn(t)
	conn.Close()

	req := ldap.NewSearchRequest(
		msadBaseDN,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0, 0, false,
		"(objectClass=*)",
		nil, nil,
	)
	_, err := conn.CustomSearch(req)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ldapper.ErrClosed))
}

// ---------------------------------------------------------------------------
// GetUser
// ---------------------------------------------------------------------------

func TestIntegrationMSAD_GetUser_BySAMAccountName(t *testing.T) {
	conn := newMSADAuthConn(t)

	user, err := conn.GetUser(msadUser1SAM, msadBaseDN)
	require.NoError(t, err)
	require.NotNil(t, user)
	assert.True(t, dnContainsUser(user.DN, msadUser1SAM))
	assert.Equal(t, msadUser1SAM, user.GetAttributeValue("sAMAccountName"))
}

func TestIntegrationMSAD_GetUser_NotFound(t *testing.T) {
	conn := newMSADAuthConn(t)
	_, err := conn.GetUser("does-not-exist", msadBaseDN)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ldapper.ErrNotFound))
}

func TestIntegrationMSAD_GetUser_NotInitialized(t *testing.T) {
	conn := newMSADConn(t)
	conn.Close()

	_, err := conn.GetUser(msadUser1SAM, msadBaseDN)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ldapper.ErrClosed))
}

// ---------------------------------------------------------------------------
// GetGroup / GetOU
// ---------------------------------------------------------------------------

func TestIntegrationMSAD_GetGroup_Success(t *testing.T) {
	conn := newMSADAuthConn(t)

	group, err := conn.GetGroup("admins", msadBaseDN)
	require.NoError(t, err)
	require.NotNil(t, group)
	assert.Equal(t, "admins", group.GetAttributeValue("cn"))
}

func TestIntegrationMSAD_GetGroup_NotFound(t *testing.T) {
	conn := newMSADAuthConn(t)
	_, err := conn.GetGroup("does-not-exist", msadBaseDN)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ldapper.ErrNotFound))
}

func TestIntegrationMSAD_GetOU_Success(t *testing.T) {
	conn := newMSADAuthConn(t)

	ou, err := conn.GetOU("Users", msadBaseDN)
	require.NoError(t, err)
	require.NotNil(t, ou)
	assert.Contains(t, ou.DN, "cn=Users")
}

// ---------------------------------------------------------------------------
// GetCatalogTree / GetSubOUs
// ---------------------------------------------------------------------------

func TestIntegrationMSAD_GetCatalogTree_Success(t *testing.T) {
	conn := newMSADAuthConn(t)

	tree, err := conn.GetCatalogTree(msadBaseDN, 0)
	require.NoError(t, err)
	assert.NotEmpty(t, tree.Tree)
}

func TestIntegrationMSAD_GetSubOUs_SingleLevel(t *testing.T) {
	conn := newMSADAuthConn(t)

	_, err := conn.GetSubOUs(msadBaseDN, ldap.ScopeSingleLevel)
	require.NoError(t, err)
}

// ---------------------------------------------------------------------------
// GetUserGroups — LDAP_MATCHING_RULE_IN_CHAIN
// ---------------------------------------------------------------------------

func TestIntegrationMSAD_GetUserGroups_AdminsMembership(t *testing.T) {
	conn := newMSADAuthConn(t)

	groups, err := conn.GetUserGroups(msadUser1SAM, msadBaseDN)
	require.NoError(t, err)
	assert.Contains(t, groups, "admins")
}

func TestIntegrationMSAD_GetUserGroups_ReadersMembership(t *testing.T) {
	conn := newMSADAuthConn(t)

	groups, err := conn.GetUserGroups(msadUser2SAM, msadBaseDN)
	require.NoError(t, err)
	assert.Contains(t, groups, "readers")
}

func TestIntegrationMSAD_GetUserGroups_UserNotFound(t *testing.T) {
	conn := newMSADAuthConn(t)

	_, err := conn.GetUserGroups("nobody", msadBaseDN)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ldapper.ErrNotFound))
}

// ---------------------------------------------------------------------------
// GetOUUsers
// ---------------------------------------------------------------------------

func TestIntegrationMSAD_GetOUUsers_UsersOU(t *testing.T) {
	conn := newMSADAuthConn(t)

	users, err := conn.GetOUUsers("cn=Users," + msadBaseDN)
	require.NoError(t, err)
	require.NotEmpty(t, users)

	sams := make([]string, 0, len(users))
	for _, u := range users {
		sams = append(sams, u.GetAttributeValue("sAMAccountName"))
	}
	assert.Contains(t, sams, msadUser1SAM)
	assert.Contains(t, sams, msadUser2SAM)
}

func TestIntegrationMSAD_GetOUUsers_NotInitialized(t *testing.T) {
	conn := newMSADConn(t)
	conn.Close()

	_, err := conn.GetOUUsers("cn=Users," + msadBaseDN)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ldapper.ErrClosed))
}

// ---------------------------------------------------------------------------
// Search / dial limits
// ---------------------------------------------------------------------------

func TestIntegrationMSAD_SearchLimits_Defaults(t *testing.T) {
	conn := newMSADConn(t)
	limits := conn.GetSearchLimits()
	assert.Equal(t, 0, limits.SizeLimit)
	assert.Equal(t, 30, limits.TimeLimit)
}

func TestIntegrationMSAD_SearchLimits_WithOption(t *testing.T) {
	conn := newMSADConn(t, ldapper.WithSearchLimits(5, 10))
	limits := conn.GetSearchLimits()
	assert.Equal(t, 5, limits.SizeLimit)
	assert.Equal(t, 10, limits.TimeLimit)
}

func TestIntegrationMSAD_SearchLimits_SetAtRuntime(t *testing.T) {
	conn := newMSADConn(t)
	conn.SetSearchLimits(7, 11)
	limits := conn.GetSearchLimits()
	assert.Equal(t, 7, limits.SizeLimit)
	assert.Equal(t, 11, limits.TimeLimit)
}

func TestIntegrationMSAD_SearchLimits_NegativeClampedToZero(t *testing.T) {
	conn := newMSADConn(t)
	conn.SetSearchLimits(-1, -5)
	limits := conn.GetSearchLimits()
	assert.Equal(t, 0, limits.SizeLimit)
	assert.Equal(t, 0, limits.TimeLimit)
}

func TestIntegrationMSAD_DialTimeout_Defaults(t *testing.T) {
	conn := newMSADConn(t)
	assert.Equal(t, time.Duration(0), conn.GetDialTimeout())
}

func TestIntegrationMSAD_DialTimeout_WithOption(t *testing.T) {
	conn := newMSADConn(t, ldapper.WithDialTimeout(3*time.Second))
	assert.Equal(t, 3*time.Second, conn.GetDialTimeout())
}

func TestIntegrationMSAD_DialTimeout_NegativeClampedToZero(t *testing.T) {
	conn := newMSADConn(t)
	conn.SetDialTimeout(-1 * time.Second)
	assert.Equal(t, time.Duration(0), conn.GetDialTimeout())
}

func TestIntegrationMSAD_AuthenticateConn_FailedBind_InvalidatesState(t *testing.T) {
	conn := newMSADConn(t)

	_, err := conn.AuthenticateConn(msadAdminDN, msadAdminPass, msadBaseDN)
	require.NoError(t, err)

	_, err = conn.AuthenticateConn(msadAdminDN, "wrong-password", msadBaseDN)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ldapper.ErrInvalidCredentials))

	_, err = conn.CheckUserCredentials(msadUser1SAM, msadUser1Pass)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ldapper.ErrNotAuthenticated))
}
