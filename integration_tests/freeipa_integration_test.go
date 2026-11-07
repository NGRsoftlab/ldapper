//go:build integration_freeipa
// +build integration_freeipa

package ldapper_test

// FreeIPA integration tests against a real FreeIPA server container.
//
// FREEIPAAdapter group filter uses both DN- and uid-valued membership:
//   (|(&(|(objectClass=groupOfNames)(objectClass=ipaUserGroup)(objectClass=posixGroup))
//       (|(member=%[1]s)(memberIndirect=%[1]s)))
//     (&(objectClass=posixGroup)(memberUid=%[2]s)))
// args = [user.DN, user.uid].
//
// FreeIPA does NOT implement PrimaryGroupResolver — GetUserGroups returns
// only membership-based groups (no implicit primary-group injection).
//
// Graceful skip:
//   FreeIPA containers are heavy (systemd, privileged mode, FQDN). Any
//   setup failure skips the whole suite (not fails it) via requireFreeIPA.
//
// Run with:
//   go test -tags=integration_freeipa ./...

import (
	"context"
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
	"github.com/NGRsoftlab/ldapper/constants"
	"github.com/NGRsoftlab/ldapper/types"
)

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
	freeipaContainer testcontainers.Container
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
	freeipaContainer = container

	freeipaHost, err = container.Host(ctx)
	if err != nil {
		_ = container.Terminate(ctx)
		fmt.Fprintf(os.Stderr, "FreeIPA tests skipped: cannot resolve host: %v\n", err)
		os.Exit(m.Run())
	}

	mappedPort, err := container.MappedPort(ctx, "389")
	if err != nil {
		_ = container.Terminate(ctx)
		fmt.Fprintf(os.Stderr, "FreeIPA tests skipped: cannot resolve port: %v\n", err)
		os.Exit(m.Run())
	}
	freeipaPort = uint(mappedPort.Num())

	if !waitForFreeIPAReady(freeipaHost, freeipaPort, 4*time.Minute) {
		_ = container.Terminate(ctx)
		fmt.Fprintln(os.Stderr, "FreeIPA tests skipped: LDAP did not become ready")
		os.Exit(m.Run())
	}

	freeipaAvailable = true

	if err := seedFreeIPA(ctx); err == nil {
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

// seedFreeIPA runs `kinit admin` once, then creates users and groups via the
// ipa CLI. Failure is non-fatal — tests requiring seeded users will skip.
func seedFreeIPA(ctx context.Context) error {
	kinitCmd := []string{
		"sh", "-c",
		fmt.Sprintf("echo '%s' | kinit admin", freeipaAdminPass),
	}
	if code, _, err := freeipaContainer.Exec(ctx, kinitCmd); err != nil || code != 0 {
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
		if code, _, err := freeipaContainer.Exec(ctx, cmd); err != nil || code != 0 {
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
		if code, _, err := freeipaContainer.Exec(ctx, cmd); err != nil || code != 0 {
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

func containsDN(groups []string, needle string) bool {
	needle = strings.ToLower(needle)
	for _, g := range groups {
		if strings.Contains(strings.ToLower(g), needle) {
			return true
		}
	}
	return false
}

func newFreeIPAConn(t *testing.T, opts ...ldapper.Option) *ldapper.LDAPper {
	t.Helper()
	requireFreeIPA(t)

	conn, err := ldapper.NewLDAPper(
		context.Background(),
		[]string{freeipaHost}, freeipaPort,
		false, true, nil,
		freeipaAdpt,
		opts...,
	)
	require.NoError(t, err)
	t.Cleanup(conn.Close)
	return conn
}

func newFreeIPAAuthConn(t *testing.T, opts ...ldapper.Option) *ldapper.LDAPper {
	t.Helper()
	requireFreeIPA(t)

	conn, _, err := ldapper.NewAuthenticatedLDAPper(
		context.Background(),
		freeipaAdminDN, freeipaAdminPass, freeipaBaseDN,
		[]string{freeipaHost}, freeipaPort,
		false, true, nil,
		freeipaAdpt,
		opts...,
	)
	require.NoError(t, err)
	t.Cleanup(conn.Close)
	return conn
}

// ================== adapter contract (no server needed, still runs) ==================

// FreeIPA's filter uses TWO positional args (%[1]s = DN, %[2]s = uid).
// The previous test expected a single %s — that was wrong and would have
// failed against the current adapter; this version asserts the real shape.
func TestIntegrationFreeIPA_SearchUserGroupsFilterTemplate_TwoArgs(t *testing.T) {
	tmpl := freeipaAdpt.SearchUserGroupsFilterTemplate()

	assert.Contains(t, tmpl, "member=%[1]s")
	assert.Contains(t, tmpl, "memberIndirect=%[1]s")
	assert.Contains(t, tmpl, "memberUid=%[2]s")
	assert.NotContains(t, tmpl, "member=uid=",
		"filter must not hard-code uid= prefix on member")

	assert.NotContains(t, tmpl, "%[3]s",
		"only two positional arguments are supported")
}

func TestIntegrationFreeIPA_SearchUserGroupsFilterTemplateArgs_ReturnsDNThenUID(t *testing.T) {
	const dn = "uid=user1,cn=users,cn=accounts,dc=example,dc=test"
	user := types.LDAPUser{
		DN:         dn,
		Attributes: map[string][]string{"uid": {"user1"}},
	}
	args := freeipaAdpt.SearchUserGroupsFilterTemplateArgs(user)
	require.Len(t, args, 2)
	require.Equal(t, dn, args[0], "arg 0 is DN — feeds member/memberIndirect")
	require.Equal(t, "user1", args[1], "arg 1 is uid — feeds memberUid")
}

// FreeIPA must not implement PrimaryGroupResolver: there is no
// primaryGroupID concept in the schema, and its presence would make
// GetUserGroups try to resolve a non-existent attribute.
var _ = func() any {
	var c any = adapters.FREEIPAAdapter{}
	if _, ok := c.(interface {
		ResolvePrimaryGroupDN(context.Context, types.LDAPUser, any) (string, error)
	}); ok {
		panic("FREEIPAAdapter must not implement PrimaryGroupResolver")
	}
	return nil
}()

// ================== constructor validation ==================

func TestIntegrationFreeIPA_NewConnection_Success(t *testing.T) {
	conn := newFreeIPAConn(t)
	assert.True(t, conn.IsAlive(context.Background()))
}

func TestIntegrationFreeIPA_NewConnection_EmptyHosts(t *testing.T) {
	requireFreeIPA(t)
	_, err := ldapper.NewLDAPper(context.Background(),
		nil, 389, false, true, nil, freeipaAdpt)
	require.Error(t, err)
	assert.ErrorIs(t, err, ldapper.ErrInvalidArgument)
}

func TestIntegrationFreeIPA_NewConnection_TooManyHosts(t *testing.T) {
	requireFreeIPA(t)
	hosts := make([]string, constants.DefaultMaxHostsLength+1)
	for i := range hosts {
		hosts[i] = fmt.Sprintf("host%d", i)
	}
	_, err := ldapper.NewLDAPper(context.Background(),
		hosts, 389, false, true, nil, freeipaAdpt)
	require.Error(t, err)
	assert.ErrorIs(t, err, ldapper.ErrInvalidArgument)
}

func TestIntegrationFreeIPA_NewConnection_NilTLSConfigWhenRequired(t *testing.T) {
	requireFreeIPA(t)
	_, err := ldapper.NewLDAPper(context.Background(),
		[]string{freeipaHost}, freeipaPort, false, false, nil, freeipaAdpt)
	require.Error(t, err)
	assert.ErrorIs(t, err, ldapper.ErrInvalidArgument)
}

func TestIntegrationFreeIPA_NewConnection_NilCatalogAdapter(t *testing.T) {
	requireFreeIPA(t)
	_, err := ldapper.NewLDAPper(context.Background(),
		[]string{freeipaHost}, freeipaPort, false, true, nil, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, ldapper.ErrInvalidArgument)
}

func TestIntegrationFreeIPA_NewConnection_UnreachableHost(t *testing.T) {
	requireFreeIPA(t)
	_, err := ldapper.NewLDAPper(context.Background(),
		[]string{"127.0.0.1"}, 1, false, true, nil, freeipaAdpt)
	require.Error(t, err)
	assert.ErrorIs(t, err, ldapper.ErrUnavailable)
}

func TestIntegrationFreeIPA_NewAuthenticatedConnection_Success(t *testing.T) {
	requireFreeIPA(t)

	conn, user, err := ldapper.NewAuthenticatedLDAPper(
		context.Background(),
		freeipaAdminDN, freeipaAdminPass, freeipaBaseDN,
		[]string{freeipaHost}, freeipaPort, false, true, nil, freeipaAdpt,
	)
	require.NoError(t, err)
	defer conn.Close()

	require.NotNil(t, user)
	assert.True(t,
		strings.HasPrefix(strings.ToLower(user.DN), "uid=admin,"),
		"expected admin DN, got %q", user.DN)
}

func TestIntegrationFreeIPA_NewAuthenticatedConnection_EmptyCredentials(t *testing.T) {
	requireFreeIPA(t)
	_, _, err := ldapper.NewAuthenticatedLDAPper(
		context.Background(), "", "", freeipaBaseDN,
		[]string{freeipaHost}, freeipaPort, false, true, nil, freeipaAdpt,
	)
	require.Error(t, err)
	assert.ErrorIs(t, err, ldapper.ErrInvalidArgument)
}

func TestIntegrationFreeIPA_NewAuthenticatedConnection_WrongPassword(t *testing.T) {
	requireFreeIPA(t)
	_, _, err := ldapper.NewAuthenticatedLDAPper(
		context.Background(),
		freeipaAdminDN, "wrong-password", freeipaBaseDN,
		[]string{freeipaHost}, freeipaPort, false, true, nil, freeipaAdpt,
	)
	require.Error(t, err)
	assert.ErrorIs(t, err, ldapper.ErrInvalidCredentials)
}

// ================== AuthenticateConn ==================

func TestIntegrationFreeIPA_AuthenticateConn_Success(t *testing.T) {
	conn := newFreeIPAConn(t)

	user, err := conn.AuthenticateConn(context.Background(),
		freeipaAdminDN, freeipaAdminPass, freeipaBaseDN)
	require.NoError(t, err)
	require.NotNil(t, user)
	assert.True(t, strings.HasPrefix(strings.ToLower(user.DN), "uid=admin,"))
}

func TestIntegrationFreeIPA_AuthenticateConn_EmptyCredentials(t *testing.T) {
	conn := newFreeIPAConn(t)
	_, err := conn.AuthenticateConn(context.Background(), "", "", freeipaBaseDN)
	require.Error(t, err)
	assert.ErrorIs(t, err, ldapper.ErrInvalidArgument)
}

func TestIntegrationFreeIPA_AuthenticateConn_WrongPassword(t *testing.T) {
	conn := newFreeIPAConn(t)
	_, err := conn.AuthenticateConn(context.Background(),
		freeipaAdminDN, "bad-password", freeipaBaseDN)
	require.Error(t, err)
	assert.ErrorIs(t, err, ldapper.ErrInvalidCredentials)
}

func TestIntegrationFreeIPA_AuthenticateConn_NonExistentUser(t *testing.T) {
	conn := newFreeIPAConn(t)
	_, err := conn.AuthenticateConn(context.Background(),
		"uid=ghost,cn=users,cn=accounts,dc=example,dc=test", "whatever", freeipaBaseDN)
	require.Error(t, err)
}

// ================== CheckUserCredentials ==================

func TestIntegrationFreeIPA_CheckUserCredentials_Success(t *testing.T) {
	requireFreeIPAUsers(t)
	conn := newFreeIPAAuthConn(t)

	user, err := conn.CheckUserCredentials(context.Background(), freeipaUser1UID, freeipaUser1Pass)
	require.NoError(t, err)
	require.NotNil(t, user)
	assert.Equal(t, freeipaUser1UID, user.GetAttributeValue("uid"))
}

func TestIntegrationFreeIPA_CheckUserCredentials_WrongPassword(t *testing.T) {
	requireFreeIPAUsers(t)
	conn := newFreeIPAAuthConn(t)

	user, err := conn.CheckUserCredentials(context.Background(), freeipaUser1UID, "bad")
	require.Error(t, err)
	assert.ErrorIs(t, err, ldapper.ErrInvalidCredentials)
	assert.Nil(t, user)
}

func TestIntegrationFreeIPA_CheckUserCredentials_NonExistentUser(t *testing.T) {
	conn := newFreeIPAAuthConn(t)
	user, err := conn.CheckUserCredentials(context.Background(), "ghost-user", "whatever")
	require.Error(t, err)
	assert.ErrorIs(t, err, ldapper.ErrInvalidCredentials)
	assert.Nil(t, user)
}

func TestIntegrationFreeIPA_CheckUserCredentials_NotAuthenticated(t *testing.T) {
	conn := newFreeIPAConn(t)
	_, err := conn.CheckUserCredentials(context.Background(), "anyone", "anything")
	require.Error(t, err)
	assert.ErrorIs(t, err, ldapper.ErrNotAuthenticated)
}

func TestIntegrationFreeIPA_CheckUserCredentials_EmptyCredentials(t *testing.T) {
	conn := newFreeIPAAuthConn(t)
	_, err := conn.CheckUserCredentials(context.Background(), "", "")
	require.Error(t, err)
	assert.ErrorIs(t, err, ldapper.ErrInvalidArgument)
}

// ================== IsAlive / Reconnect / EnsureAlive / Close ==================

func TestIntegrationFreeIPA_IsAlive_ActiveConnection(t *testing.T) {
	conn := newFreeIPAConn(t)
	assert.True(t, conn.IsAlive(context.Background()))
}

func TestIntegrationFreeIPA_IsAlive_AfterClose(t *testing.T) {
	conn := newFreeIPAConn(t)
	conn.Close()
	assert.False(t, conn.IsAlive(context.Background()))
}

func TestIntegrationFreeIPA_Reconnect_Unauthenticated(t *testing.T) {
	conn := newFreeIPAConn(t)
	require.True(t, conn.IsAlive(context.Background()))
	require.NoError(t, conn.Reconnect(context.Background()))
	assert.True(t, conn.IsAlive(context.Background()))
}

func TestIntegrationFreeIPA_Reconnect_PreservesAuthentication(t *testing.T) {
	requireFreeIPAUsers(t)
	conn := newFreeIPAAuthConn(t)
	require.NoError(t, conn.Reconnect(context.Background()))

	_, err := conn.CheckUserCredentials(context.Background(), freeipaUser1UID, freeipaUser1Pass)
	require.NoError(t, err)
}

func TestIntegrationFreeIPA_EnsureAlive_NoopWhenAlive(t *testing.T) {
	conn := newFreeIPAConn(t)
	require.NoError(t, conn.EnsureAlive(context.Background()))
	assert.True(t, conn.IsAlive(context.Background()))
}

// After Close the client is terminal: EnsureAlive reports ErrClosed instead
// of silently reconnecting.
func TestIntegrationFreeIPA_EnsureAlive_ClosedClient_ReturnsErrClosed(t *testing.T) {
	conn := newFreeIPAAuthConn(t)
	conn.Close()
	require.False(t, conn.IsAlive(context.Background()))

	err := conn.EnsureAlive(context.Background())
	require.Error(t, err)
	assert.ErrorIs(t, err, ldapper.ErrClosed)
}

func TestIntegrationFreeIPA_Close_Idempotent(t *testing.T) {
	conn := newFreeIPAConn(t)
	conn.Close()
	conn.Close() // must not panic

	_, err := conn.GetUser(context.Background(), "admin", freeipaBaseDN)
	require.Error(t, err)
	assert.ErrorIs(t, err, ldapper.ErrClosed)
}

// ================== CustomSearch ==================

func TestIntegrationFreeIPA_CustomSearch_Success(t *testing.T) {
	conn := newFreeIPAAuthConn(t)

	req := ldap.NewSearchRequest(
		freeipaBaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		0, 0, false, "(uid=admin)", []string{"cn", "mail"}, nil,
	)

	res, err := conn.CustomSearch(context.Background(), req)
	require.NoError(t, err)
	require.NotEmpty(t, res.Entries)
	assert.True(t,
		strings.HasPrefix(strings.ToLower(res.Entries[0].DN), "uid=admin,"))
}

func TestIntegrationFreeIPA_CustomSearch_NotInitialized(t *testing.T) {
	conn := newFreeIPAConn(t)
	conn.Close()

	req := ldap.NewSearchRequest(
		freeipaBaseDN, ldap.ScopeBaseObject, ldap.NeverDerefAliases,
		0, 0, false, "(objectClass=*)", nil, nil,
	)
	_, err := conn.CustomSearch(context.Background(), req)
	require.Error(t, err)
	assert.ErrorIs(t, err, ldapper.ErrClosed)
}

// ================== GetUser ==================

func TestIntegrationFreeIPA_GetUser_Admin(t *testing.T) {
	conn := newFreeIPAAuthConn(t)

	user, err := conn.GetUser(context.Background(), "admin", freeipaBaseDN)
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(strings.ToLower(user.DN), "uid=admin,"))
	assert.Equal(t, "admin", user.GetAttributeValue("uid"))
}

func TestIntegrationFreeIPA_GetUser_SeededUser(t *testing.T) {
	requireFreeIPAUsers(t)
	conn := newFreeIPAAuthConn(t)

	user, err := conn.GetUser(context.Background(), freeipaUser1UID, freeipaBaseDN)
	require.NoError(t, err)
	assert.Equal(t, freeipaUser1UID, user.GetAttributeValue("uid"))
}

func TestIntegrationFreeIPA_GetUser_NotFound(t *testing.T) {
	conn := newFreeIPAAuthConn(t)
	_, err := conn.GetUser(context.Background(), "does-not-exist", freeipaBaseDN)
	require.Error(t, err)
	// Zero entries from a subtree search: ErrNotFoundOrNotVisible, not
	// ErrNotFound (which requires a definitive LDAPResultNoSuchObject).
	assert.ErrorIs(t, err, ldapper.ErrNotFoundOrNotVisible)
}

func TestIntegrationFreeIPA_GetUser_NotInitialized(t *testing.T) {
	conn := newFreeIPAConn(t)
	conn.Close()

	_, err := conn.GetUser(context.Background(), "admin", freeipaBaseDN)
	require.Error(t, err)
	assert.ErrorIs(t, err, ldapper.ErrClosed)
}

// ================== GetGroup / GetOU ==================

func TestIntegrationFreeIPA_GetGroup_Success(t *testing.T) {
	requireFreeIPAUsers(t)
	conn := newFreeIPAAuthConn(t)

	group, err := conn.GetGroup(context.Background(), "admins", freeipaBaseDN)
	require.NoError(t, err)
	require.NotNil(t, group)
	assert.Equal(t, "admins", group.GetAttributeValue("cn"))
}

func TestIntegrationFreeIPA_GetGroup_NotFound(t *testing.T) {
	conn := newFreeIPAAuthConn(t)
	_, err := conn.GetGroup(context.Background(), "does-not-exist", freeipaBaseDN)
	require.Error(t, err)
	assert.ErrorIs(t, err, ldapper.ErrNotFoundOrNotVisible)
}

func TestIntegrationFreeIPA_GetOU_Success(t *testing.T) {
	conn := newFreeIPAAuthConn(t)

	// "users" is cn=users under cn=accounts. FreeIPA's SearchOUFilterTemplate
	// matches on ou= or cn=, so this resolves the cn=users container.
	ou, err := conn.GetOU(context.Background(), "users", "cn=accounts,"+freeipaBaseDN)
	require.NoError(t, err)
	require.NotNil(t, ou)
	assert.Contains(t, strings.ToLower(ou.DN), "cn=users")
}

// ================== GetCatalogTree / GetSubOUs ==================

func TestIntegrationFreeIPA_GetCatalogTree_Success(t *testing.T) {
	conn := newFreeIPAAuthConn(t)

	tree, err := conn.GetCatalogTree(context.Background(), freeipaBaseDN, 0)
	require.NoError(t, err)
	assert.NotEmpty(t, tree.Tree)
}

func TestIntegrationFreeIPA_GetSubOUs_SingleLevel(t *testing.T) {
	conn := newFreeIPAAuthConn(t)

	_, err := conn.GetSubOUs(context.Background(), freeipaBaseDN, ldap.ScopeSingleLevel)
	require.NoError(t, err)
}

// ================== GetUserGroups ==================

// GetUserGroups returns DNs. The FreeIPA filter hits member/memberIndirect
// on the DN. Assertions use containsDN (case-insensitive substring).
func TestIntegrationFreeIPA_GetUserGroups_AdminsMembership(t *testing.T) {
	requireFreeIPAUsers(t)
	conn := newFreeIPAAuthConn(t)

	groups, err := conn.GetUserGroups(context.Background(), freeipaUser1UID, freeipaBaseDN)
	require.NoError(t, err)
	assert.True(t, containsDN(groups, "cn=admins"),
		"expected an admins group DN in %v", groups)
}

func TestIntegrationFreeIPA_GetUserGroups_ReadersMembership(t *testing.T) {
	requireFreeIPAUsers(t)
	conn := newFreeIPAAuthConn(t)

	groups, err := conn.GetUserGroups(context.Background(), freeipaUser2UID, freeipaBaseDN)
	require.NoError(t, err)
	assert.True(t, containsDN(groups, "cn=readers"),
		"expected a readers group DN in %v", groups)
}

func TestIntegrationFreeIPA_GetUserGroups_NoCrossContamination(t *testing.T) {
	requireFreeIPAUsers(t)
	conn := newFreeIPAAuthConn(t)

	groups1, err := conn.GetUserGroups(context.Background(), freeipaUser1UID, freeipaBaseDN)
	require.NoError(t, err)
	assert.False(t, containsDN(groups1, "cn=readers"),
		"user1 must not be in readers, got %v", groups1)
}

func TestIntegrationFreeIPA_GetUserGroups_UserNotFound(t *testing.T) {
	conn := newFreeIPAAuthConn(t)

	_, err := conn.GetUserGroups(context.Background(), "nobody", freeipaBaseDN)
	require.Error(t, err)
	assert.ErrorIs(t, err, ldapper.ErrNotFoundOrNotVisible)
}

// ================== GetOUUsers ==================

func TestIntegrationFreeIPA_GetOUUsers_UsersContainer(t *testing.T) {
	conn := newFreeIPAAuthConn(t)

	users, err := conn.GetOUUsers(context.Background(),
		"cn=users,cn=accounts,"+freeipaBaseDN)
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

	users, err := conn.GetOUUsers(context.Background(), "ou=empty,"+freeipaBaseDN)
	require.NoError(t, err)
	assert.Empty(t, users)
}

// ================== SearchLimits / DialTimeout / OperationTimeouts ==================

func TestIntegrationFreeIPA_SearchLimits_Defaults(t *testing.T) {
	conn := newFreeIPAConn(t)
	limits := conn.GetSearchLimits()
	assert.Equal(t, 0, limits.SizeLimit)
	assert.Equal(t, 30, limits.TimeLimit)
	assert.True(t, limits.RequirePaging)
}

func TestIntegrationFreeIPA_SearchLimits_WithOption(t *testing.T) {
	limits := ldapper.DefaultSearchLimits()
	limits.SizeLimit = 5
	limits.TimeLimit = 10

	conn := newFreeIPAConn(t, ldapper.WithSearchLimits(limits))

	got := conn.GetSearchLimits()
	assert.Equal(t, 5, got.SizeLimit)
	assert.Equal(t, 10, got.TimeLimit)
}

func TestIntegrationFreeIPA_SearchLimits_SetAtRuntime(t *testing.T) {
	conn := newFreeIPAConn(t)

	limits := conn.GetSearchLimits()
	limits.SizeLimit = 7
	limits.TimeLimit = 11
	conn.SetSearchLimits(limits)

	got := conn.GetSearchLimits()
	assert.Equal(t, 7, got.SizeLimit)
	assert.Equal(t, 11, got.TimeLimit)
}

func TestIntegrationFreeIPA_DialTimeout_Defaults(t *testing.T) {
	conn := newFreeIPAConn(t)
	assert.Equal(t, constants.DefaultDialTimeout, conn.GetDialTimeout())
}

func TestIntegrationFreeIPA_DialTimeout_WithOption(t *testing.T) {
	conn := newFreeIPAConn(t, ldapper.WithDialTimeout(3*time.Second))
	assert.Equal(t, 3*time.Second, conn.GetDialTimeout())
}

func TestIntegrationFreeIPA_OperationTimeout_WithOption(t *testing.T) {
	conn := newFreeIPAAuthConn(t, ldapper.WithOperationTimeout(ldapper.OperationTimeouts{
		Bind:   5 * time.Second,
		Search: 5 * time.Second,
	}))

	got := conn.GetOperationTimeout()
	assert.Equal(t, 5*time.Second, got.Bind)
	assert.Equal(t, 5*time.Second, got.Search)

	_, err := conn.GetUser(context.Background(), "admin", freeipaBaseDN)
	require.NoError(t, err)
}

// ================== Failure paths ==================

// A failed Bind transitions the session to anonymous (RFC 4513 §4). The
// cached auth state must be invalidated, so subsequent operations do not
// silently run under the previously-bound principal.
func TestIntegrationFreeIPA_AuthenticateConn_FailedBind_InvalidatesState(t *testing.T) {
	requireFreeIPAUsers(t)
	conn := newFreeIPAConn(t)

	_, err := conn.AuthenticateConn(context.Background(),
		freeipaAdminDN, freeipaAdminPass, freeipaBaseDN)
	require.NoError(t, err)

	_, err = conn.AuthenticateConn(context.Background(),
		freeipaAdminDN, "wrong-password", freeipaBaseDN)
	require.Error(t, err)
	assert.ErrorIs(t, err, ldapper.ErrInvalidCredentials)

	_, err = conn.CheckUserCredentials(context.Background(), freeipaUser1UID, freeipaUser1Pass)
	require.Error(t, err)
	assert.ErrorIs(t, err, ldapper.ErrNotAuthenticated)
}

// Reconnect-after-rebind-failure requires breaking a user's password so the
// cached credentials are rejected. FreeIPA stores passwords in a format that
// direct LDAP Modify cannot reliably set (PBKDF2-SHA512 by default, plus
// krbPrincipalKey), and `ipa passwd` is interactive. The same code path
// (reconnectLocked → restoreServiceBindLocked → invalidateAuthLocked) is
// exercised by TestIntegrationOpenLDAP_Reconnect_RebindFailure_ClosesConnection,
// which uses an OpenLDAP user whose password can be safely restored via
// t.Cleanup. Skipping here avoids a fragile, non-restorable fixture.
func TestIntegrationFreeIPA_Reconnect_RebindFailure_ClosesConnection(t *testing.T) {
	t.Skip("FreeIPA password rotation is not scriptable here; " +
		"the reconnect-rebind-failure path is covered by " +
		"TestIntegrationOpenLDAP_Reconnect_RebindFailure_ClosesConnection")
}
