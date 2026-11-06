//go:build integration_freeipa
// +build integration_freeipa

package ldapper_test

// FreeIPA integration tests against a real FreeIPA server container.
//
// Adapter status (current):
//   SearchUserGroupsFilterTemplate     = (&(|(objectClass=groupOfNames)
//                                            (objectClass=posixGroup)
//                                            (objectClass=ipausergroup))(member=%s))
//   SearchUserGroupsFilterTemplateArgs = [ ldapUser.DN ]
//
// FreeIPA's `ipa group-add-member` populates `member` (DN-valued) on groups
// that are also ipausergroup/posixGroup, so the filter matches real
// memberships. GetUserGroups tests below are positive:
//   - user1 -> ["admins"]
//   - user2 -> ["readers"]
//
// CheckUserCredentials(username, password) takes only two args. Base DN for
// the internal GetUser comes from conn.bindDN stored by AuthenticateConn.
// Failure assertions use errors.Is against exported sentinels.
//
// Graceful skip:
//   FreeIPA containers are heavy (systemd, privileged mode, FQDN). On any
//   setup failure the whole suite is skipped, not failed.
//
// Run with:
//   go test -tags=integration_freeipa ./...

import (
	"context"
	"errors"
	"fmt"
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
	"github.com/NGRsoftlab/ldapper/types"
)

// ---------------------------------------------------------------------------
// FreeIPA test fixtures
// ---------------------------------------------------------------------------

const (
	freeipaFQDN      = "ipa.example.test"
	freeipaBaseDN    = "dc=example,dc=test"
	freeipaAdminPass = "Secret123!"

	freeipaAdminDN = "uid=admin,cn=users,cn=accounts,dc=example,dc=test"
	freeipaDM      = "cn=Directory Manager"

	freeipaUser1UID  = "user1"
	freeipaUser1Pass = "User1Pass1!"
	freeipaUser2UID  = "user2"
	freeipaUser2Pass = "User2Pass2!"
)

var (
	freeipaHost      string
	freeipaPort      uint
	freeipaAvailable bool
	freeipaSeeded    bool
	freeipaAdpt      = adapters.FREEIPAAdapter{}
)

func TestMain(m *testing.M) {
	ctx := context.Background()

	req := testcontainers.ContainerRequest{
		Image:        "freeipa/freeipa-server:rocky-9",
		ExposedPorts: []string{"389/tcp"},
		Privileged:   true,
		Hostname:     freeipaFQDN,
		Env:          map[string]string{"PASSWORD": freeipaAdminPass},
		WaitingFor:   wait.ForListeningPort("389/tcp").WithStartupTimeout(5 * time.Minute),
	}

	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "FreeIPA tests skipped: cannot start container: %v\n", err)
		os.Exit(m.Run())
	}

	freeipaHost, err = container.Host(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "FreeIPA tests skipped: cannot resolve host: %v\n", err)
		_ = container.Terminate(ctx)
		os.Exit(m.Run())
	}

	mappedPort, err := container.MappedPort(ctx, "389")
	if err != nil {
		fmt.Fprintf(os.Stderr, "FreeIPA tests skipped: cannot resolve port: %v\n", err)
		_ = container.Terminate(ctx)
		os.Exit(m.Run())
	}
	freeipaPort = uint(mappedPort.Num())

	if !waitForFreeIPAReady(freeipaHost, freeipaPort, 4*time.Minute) {
		fmt.Fprintln(os.Stderr, "FreeIPA tests skipped: LDAP did not become ready")
		_ = container.Terminate(ctx)
		os.Exit(m.Run())
	}

	freeipaAvailable = true

	if err := seedFreeIPA(ctx, container); err == nil {
		freeipaSeeded = true
	} else {
		fmt.Fprintf(os.Stderr, "FreeIPA seeding failed (user tests will skip): %v\n", err)
	}

	code := m.Run()
	_ = container.Terminate(ctx)
	os.Exit(code)
}

func waitForFreeIPAReady(host string, port uint, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		c, err := ldap.DialURL(fmt.Sprintf("ldap://%s:%d", host, port))
		if err == nil {
			err = c.Bind(freeipaDM, freeipaAdminPass)
			_ = c.Close()
			if err == nil {
				return true
			}
		}
		time.Sleep(2 * time.Second)
	}
	return false
}

func seedFreeIPA(ctx context.Context, container testcontainers.Container) error {
	kinitCmd := []string{
		"sh", "-c",
		fmt.Sprintf("echo '%s' | kinit admin", freeipaAdminPass),
	}
	if code, _, err := container.Exec(ctx, kinitCmd); err != nil || code != 0 {
		return fmt.Errorf("kinit admin failed (code=%d, err=%v)", code, err)
	}

	users := []struct{ uid, pass, first, last string }{
		{freeipaUser1UID, freeipaUser1Pass, "User", "One"},
		{freeipaUser2UID, freeipaUser2Pass, "User", "Two"},
	}
	for _, u := range users {
		cmd := []string{
			"ipa", "user-add", u.uid,
			"--first=" + u.first, "--last=" + u.last,
			"--password=" + u.pass,
		}
		if code, _, err := container.Exec(ctx, cmd); err != nil || code != 0 {
			return fmt.Errorf("ipa user-add %s failed (code=%d, err=%v)", u.uid, code, err)
		}
	}

	groupCmds := [][]string{
		{"ipa", "group-add", "admins"},
		{"ipa", "group-add-member", "admins", "--users=" + freeipaUser1UID},
		{"ipa", "group-add", "readers"},
		{"ipa", "group-add-member", "readers", "--users=" + freeipaUser2UID},
	}
	for _, cmd := range groupCmds {
		if code, _, err := container.Exec(ctx, cmd); err != nil || code != 0 {
			return fmt.Errorf("%v failed (code=%d, err=%v)", cmd, code, err)
		}
	}
	return nil
}

func requireFreeIPA(t *testing.T) {
	t.Helper()
	if !freeipaAvailable {
		t.Skip("FreeIPA container not available; test skipped")
	}
}

func requireFreeIPAUsers(t *testing.T) {
	t.Helper()
	requireFreeIPA(t)
	if !freeipaSeeded {
		t.Skip("FreeIPA users were not seeded; test skipped")
	}
}

func newFreeIPAConn(t *testing.T, opts ...ldapper.Option) *ldapper.LDAPper {
	t.Helper()
	requireFreeIPA(t)

	conn, err := ldapper.NewLDAPper(
		[]string{freeipaHost},
		freeipaPort,
		false, // useSSL
		true,  // skipTLS
		nil,
		freeipaAdpt,
		opts...,
	)
	require.NoError(t, err)
	t.Cleanup(conn.Close)
	return conn
}

// newFreeIPAAuthConn authenticates as admin (uid=admin DN). FreeIPA's admin
// is a real inetOrgPerson-like entry with uid=admin, so the adapter's
// SearchUserFilterTemplate matches the bind principal via uid.
func newFreeIPAAuthConn(t *testing.T, opts ...ldapper.Option) *ldapper.LDAPper {
	t.Helper()
	requireFreeIPA(t)

	conn, _, err := ldapper.NewAuthenticatedLDAPper(
		freeipaAdminDN, freeipaAdminPass, freeipaBaseDN,
		[]string{freeipaHost},
		freeipaPort,
		false,
		true,
		nil,
		freeipaAdpt,
		opts...,
	)
	require.NoError(t, err)
	t.Cleanup(conn.Close)
	return conn
}

func freeipaDNHasPrefixCI(dn, prefix string) bool {
	return strings.HasPrefix(strings.ToLower(dn), strings.ToLower(prefix))
}

// ---------------------------------------------------------------------------
// Adapter contract tests
// ---------------------------------------------------------------------------

func TestIntegrationFreeIPA_SearchUserGroupsFilterTemplate_PostFix(t *testing.T) {
	tmpl := freeipaAdpt.SearchUserGroupsFilterTemplate()
	assert.NotContains(t, tmpl, "member=uid=")
	assert.Contains(t, tmpl, "(member=%s)")
	assert.Equal(t, 1, strings.Count(tmpl, "%s"))
}

func TestIntegrationFreeIPA_SearchUserGroupsFilterTemplateArgs_ReturnsDN(t *testing.T) {
	const dn = "uid=user1,cn=users,cn=accounts,dc=example,dc=test"
	user := types.LDAPUser{
		DN:         dn,
		Attributes: map[string][]string{"uid": {"user1"}},
	}
	args := freeipaAdpt.SearchUserGroupsFilterTemplateArgs(user)
	require.Len(t, args, 1)
	require.Equal(t, dn, args[0])
}

// ---------------------------------------------------------------------------
// NewConnection / NewAuthenticatedConnection
// ---------------------------------------------------------------------------

func TestIntegrationFreeIPA_NewConnection_Success(t *testing.T) {
	conn := newFreeIPAConn(t)
	require.NotNil(t, conn)
	assert.True(t, conn.IsAlive())
}

func TestIntegrationFreeIPA_NewConnection_EmptyHosts(t *testing.T) {
	requireFreeIPA(t)
	_, err := ldapper.NewLDAPper(nil, 389, false, true, nil, freeipaAdpt)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ldapper.ErrInvalidArgument))
}

func TestIntegrationFreeIPA_NewConnection_TooManyHosts(t *testing.T) {
	requireFreeIPA(t)
	hosts := make([]string, 100)
	for i := range hosts {
		hosts[i] = fmt.Sprintf("host%d", i)
	}
	_, err := ldapper.NewLDAPper(hosts, 389, false, true, nil, freeipaAdpt)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ldapper.ErrInvalidArgument))
}

func TestIntegrationFreeIPA_NewConnection_NilTLSConfigWhenRequired(t *testing.T) {
	requireFreeIPA(t)
	_, err := ldapper.NewLDAPper([]string{freeipaHost}, freeipaPort, false, false, nil, freeipaAdpt)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ldapper.ErrInvalidArgument))
}

func TestIntegrationFreeIPA_NewConnection_NilCatalogAdapter(t *testing.T) {
	requireFreeIPA(t)
	_, err := ldapper.NewLDAPper([]string{freeipaHost}, freeipaPort, false, true, nil, nil)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ldapper.ErrInvalidArgument))
}

func TestIntegrationFreeIPA_NewConnection_UnreachableHost(t *testing.T) {
	requireFreeIPA(t)
	_, err := ldapper.NewLDAPper([]string{"127.0.0.1"}, 1, false, true, nil, freeipaAdpt)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ldapper.ErrUnavailable))
}

func TestIntegrationFreeIPA_NewAuthenticatedConnection_Success(t *testing.T) {
	requireFreeIPA(t)

	conn, user, err := ldapper.NewAuthenticatedLDAPper(
		freeipaAdminDN, freeipaAdminPass, freeipaBaseDN,
		[]string{freeipaHost}, freeipaPort, false, true, nil, freeipaAdpt,
	)
	require.NoError(t, err)
	defer conn.Close()

	require.NotNil(t, user)
	assert.True(t, freeipaDNHasPrefixCI(user.DN, "uid=admin,"))
}

func TestIntegrationFreeIPA_NewAuthenticatedConnection_EmptyCredentials(t *testing.T) {
	requireFreeIPA(t)
	_, _, err := ldapper.NewAuthenticatedLDAPper(
		"", "", freeipaBaseDN,
		[]string{freeipaHost}, freeipaPort, false, true, nil, freeipaAdpt,
	)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ldapper.ErrInvalidArgument))
}

func TestIntegrationFreeIPA_NewAuthenticatedConnection_WrongPassword(t *testing.T) {
	requireFreeIPA(t)
	_, _, err := ldapper.NewAuthenticatedLDAPper(
		freeipaAdminDN, "wrong-password", freeipaBaseDN,
		[]string{freeipaHost}, freeipaPort, false, true, nil, freeipaAdpt,
	)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ldapper.ErrInvalidCredentials))
}

// ---------------------------------------------------------------------------
// AuthenticateConn
// ---------------------------------------------------------------------------

func TestIntegrationFreeIPA_AuthenticateConn_Success(t *testing.T) {
	conn := newFreeIPAConn(t)

	user, err := conn.AuthenticateConn(freeipaAdminDN, freeipaAdminPass, freeipaBaseDN)
	require.NoError(t, err)
	require.NotNil(t, user)
	assert.True(t, freeipaDNHasPrefixCI(user.DN, "uid=admin,"))
}

func TestIntegrationFreeIPA_AuthenticateConn_EmptyCredentials(t *testing.T) {
	conn := newFreeIPAConn(t)
	_, err := conn.AuthenticateConn("", "", freeipaBaseDN)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ldapper.ErrInvalidArgument))
}

func TestIntegrationFreeIPA_AuthenticateConn_WrongPassword(t *testing.T) {
	conn := newFreeIPAConn(t)
	_, err := conn.AuthenticateConn(freeipaAdminDN, "bad-password", freeipaBaseDN)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ldapper.ErrInvalidCredentials))
}

func TestIntegrationFreeIPA_AuthenticateConn_NonExistentUser(t *testing.T) {
	conn := newFreeIPAConn(t)
	_, err := conn.AuthenticateConn(
		"uid=ghost,cn=users,cn=accounts,dc=example,dc=test", "whatever", freeipaBaseDN,
	)
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// CheckUserCredentials
// ---------------------------------------------------------------------------

func TestIntegrationFreeIPA_CheckUserCredentials_Success(t *testing.T) {
	requireFreeIPAUsers(t)
	conn := newFreeIPAAuthConn(t)

	user, err := conn.CheckUserCredentials(freeipaUser1UID, freeipaUser1Pass)
	require.NoError(t, err)
	require.NotNil(t, user)
	assert.Equal(t, freeipaUser1UID, user.GetAttributeValue("uid"))
}

func TestIntegrationFreeIPA_CheckUserCredentials_WrongPassword(t *testing.T) {
	requireFreeIPAUsers(t)
	conn := newFreeIPAAuthConn(t)

	user, err := conn.CheckUserCredentials(freeipaUser1UID, "bad")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ldapper.ErrInvalidCredentials))
	assert.Nil(t, user)
}

func TestIntegrationFreeIPA_CheckUserCredentials_NonExistentUser(t *testing.T) {
	conn := newFreeIPAAuthConn(t)
	user, err := conn.CheckUserCredentials("ghost-user", "whatever")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ldapper.ErrInvalidCredentials))
	assert.Nil(t, user)
}

func TestIntegrationFreeIPA_CheckUserCredentials_NotAuthenticated(t *testing.T) {
	conn := newFreeIPAConn(t)
	_, err := conn.CheckUserCredentials("anyone", "anything")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ldapper.ErrNotAuthenticated))
}

func TestIntegrationFreeIPA_CheckUserCredentials_EmptyCredentials(t *testing.T) {
	conn := newFreeIPAAuthConn(t)
	_, err := conn.CheckUserCredentials("", "")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ldapper.ErrInvalidArgument))
}

// ---------------------------------------------------------------------------
// IsAlive / Reconnect / EnsureAlive / Close
// ---------------------------------------------------------------------------

func TestIntegrationFreeIPA_IsAlive_ActiveConnection(t *testing.T) {
	conn := newFreeIPAConn(t)
	assert.True(t, conn.IsAlive())
}

func TestIntegrationFreeIPA_IsAlive_AfterClose(t *testing.T) {
	conn := newFreeIPAConn(t)
	conn.Close()
	assert.False(t, conn.IsAlive())
}

func TestIntegrationFreeIPA_Reconnect_Unauthenticated(t *testing.T) {
	conn := newFreeIPAConn(t)
	require.True(t, conn.IsAlive())
	require.NoError(t, conn.Reconnect())
	assert.True(t, conn.IsAlive())
}

func TestIntegrationFreeIPA_Reconnect_PreservesAuthentication(t *testing.T) {
	requireFreeIPAUsers(t)
	conn := newFreeIPAAuthConn(t)
	require.NoError(t, conn.Reconnect())

	_, err := conn.CheckUserCredentials(freeipaUser1UID, freeipaUser1Pass)
	require.NoError(t, err)
}

func TestIntegrationFreeIPA_EnsureAlive_NoopWhenAlive(t *testing.T) {
	conn := newFreeIPAConn(t)
	require.NoError(t, conn.EnsureAlive())
	assert.True(t, conn.IsAlive())
}

func TestIntegrationFreeIPA_EnsureAlive_ReconnectsAfterClose(t *testing.T) {
	requireFreeIPAUsers(t)
	conn := newFreeIPAAuthConn(t)
	conn.Close()
	require.False(t, conn.IsAlive())

	require.NoError(t, conn.EnsureAlive())
	assert.True(t, conn.IsAlive())

	_, err := conn.CheckUserCredentials(freeipaUser1UID, freeipaUser1Pass)
	require.NoError(t, err)
}

func TestIntegrationFreeIPA_Close_Idempotent(t *testing.T) {
	conn := newFreeIPAConn(t)
	conn.Close()
	conn.Close() // must not panic

	_, err := conn.GetUser("admin", freeipaBaseDN)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ldapper.ErrClosed))
}

// ---------------------------------------------------------------------------
// CustomSearch
// ---------------------------------------------------------------------------

func TestIntegrationFreeIPA_CustomSearch_Success(t *testing.T) {
	conn := newFreeIPAAuthConn(t)

	req := ldap.NewSearchRequest(
		freeipaBaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		0, 0, false, "(uid=admin)", []string{"cn", "mail"}, nil,
	)

	res, err := conn.CustomSearch(req)
	require.NoError(t, err)
	require.NotEmpty(t, res.Entries)
	assert.True(t, freeipaDNHasPrefixCI(res.Entries[0].DN, "uid=admin,"))
}

func TestIntegrationFreeIPA_CustomSearch_NotInitialized(t *testing.T) {
	conn := newFreeIPAConn(t)
	conn.Close()

	req := ldap.NewSearchRequest(
		freeipaBaseDN, ldap.ScopeBaseObject, ldap.NeverDerefAliases,
		0, 0, false, "(objectClass=*)", nil, nil,
	)
	_, err := conn.CustomSearch(req)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ldapper.ErrClosed))
}

// ---------------------------------------------------------------------------
// GetUser
// ---------------------------------------------------------------------------

func TestIntegrationFreeIPA_GetUser_Admin(t *testing.T) {
	conn := newFreeIPAAuthConn(t)

	user, err := conn.GetUser("admin", freeipaBaseDN)
	require.NoError(t, err)
	assert.True(t, freeipaDNHasPrefixCI(user.DN, "uid=admin,"))
	assert.Equal(t, "admin", user.GetAttributeValue("uid"))
}

func TestIntegrationFreeIPA_GetUser_SeededUser(t *testing.T) {
	requireFreeIPAUsers(t)
	conn := newFreeIPAAuthConn(t)

	user, err := conn.GetUser(freeipaUser1UID, freeipaBaseDN)
	require.NoError(t, err)
	assert.Equal(t, freeipaUser1UID, user.GetAttributeValue("uid"))
}

func TestIntegrationFreeIPA_GetUser_NotFound(t *testing.T) {
	conn := newFreeIPAAuthConn(t)
	_, err := conn.GetUser("does-not-exist", freeipaBaseDN)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ldapper.ErrNotFound))
}

func TestIntegrationFreeIPA_GetUser_NotInitialized(t *testing.T) {
	conn := newFreeIPAConn(t)
	conn.Close()

	_, err := conn.GetUser("admin", freeipaBaseDN)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ldapper.ErrClosed))
}

// ---------------------------------------------------------------------------
// GetGroup / GetOU
// ---------------------------------------------------------------------------

func TestIntegrationFreeIPA_GetGroup_Success(t *testing.T) {
	requireFreeIPAUsers(t)
	conn := newFreeIPAAuthConn(t)

	group, err := conn.GetGroup("admins", freeipaBaseDN)
	require.NoError(t, err)
	require.NotNil(t, group)
	assert.Equal(t, "admins", group.GetAttributeValue("cn"))
}

func TestIntegrationFreeIPA_GetGroup_NotFound(t *testing.T) {
	conn := newFreeIPAAuthConn(t)
	_, err := conn.GetGroup("does-not-exist", freeipaBaseDN)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ldapper.ErrNotFound))
}

func TestIntegrationFreeIPA_GetOU_Success(t *testing.T) {
	conn := newFreeIPAAuthConn(t)

	// "users" is a standard ou under cn=accounts in FreeIPA.
	ou, err := conn.GetOU("users", "cn=accounts,"+freeipaBaseDN)
	require.NoError(t, err)
	require.NotNil(t, ou)
}

// ---------------------------------------------------------------------------
// GetCatalogTree / GetSubOUs
// ---------------------------------------------------------------------------

func TestIntegrationFreeIPA_GetCatalogTree_Success(t *testing.T) {
	conn := newFreeIPAAuthConn(t)

	tree, err := conn.GetCatalogTree(freeipaBaseDN, 0)
	require.NoError(t, err)
	// The base DN itself is excluded, but some structure must be present.
	assert.NotEmpty(t, tree.Tree)
}

func TestIntegrationFreeIPA_GetSubOUs_SingleLevel(t *testing.T) {
	conn := newFreeIPAAuthConn(t)

	_, err := conn.GetSubOUs(freeipaBaseDN, ldap.ScopeSingleLevel)
	require.NoError(t, err)
}

// ---------------------------------------------------------------------------
// GetUserGroups
// ---------------------------------------------------------------------------

func TestIntegrationFreeIPA_GetUserGroups_AdminsMembership(t *testing.T) {
	requireFreeIPAUsers(t)
	conn := newFreeIPAAuthConn(t)

	groups, err := conn.GetUserGroups(freeipaUser1UID, freeipaBaseDN)
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"admins"}, groups)
}

func TestIntegrationFreeIPA_GetUserGroups_ReadersMembership(t *testing.T) {
	requireFreeIPAUsers(t)
	conn := newFreeIPAAuthConn(t)

	groups, err := conn.GetUserGroups(freeipaUser2UID, freeipaBaseDN)
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"readers"}, groups)
}

func TestIntegrationFreeIPA_GetUserGroups_UserNotFound(t *testing.T) {
	conn := newFreeIPAAuthConn(t)

	_, err := conn.GetUserGroups("nobody", freeipaBaseDN)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ldapper.ErrNotFound))
}

// ---------------------------------------------------------------------------
// GetOUUsers
// ---------------------------------------------------------------------------

func TestIntegrationFreeIPA_GetOUUsers_UsersContainer(t *testing.T) {
	conn := newFreeIPAAuthConn(t)

	users, err := conn.GetOUUsers("cn=users,cn=accounts," + freeipaBaseDN)
	require.NoError(t, err)
	require.NotEmpty(t, users)

	uids := make([]string, 0, len(users))
	for _, u := range users {
		uids = append(uids, u.GetAttributeValue("uid"))
	}
	assert.Contains(t, uids, "admin")
}

func TestIntegrationFreeIPA_GetOUUsers_EmptyOU(t *testing.T) {
	conn := newFreeIPAAuthConn(t)

	users, err := conn.GetOUUsers("ou=empty," + freeipaBaseDN)
	require.NoError(t, err)
	assert.Empty(t, users)
}
