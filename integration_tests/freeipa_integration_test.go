//go:build integration_freeipa
// +build integration_freeipa

package ldapper_test

// FreeIPA integration tests against a real FreeIPA server container.
//
// Adapter status (after the args-helper fix):
//   SearchUserGroupsFilterTemplate     = (&(|(objectClass=groupOfNames)
//                                            (objectClass=posixGroup)
//                                            (objectClass=ipausergroup))(member=%s))
//   SearchUserGroupsFilterTemplateArgs = [ ldapUser.DN ]
//
// FreeIPA's `ipa group-add-member` populates `member` (DN-valued) on groups
// that are also ipausergroup/posixGroup, so the filter now matches real
// memberships. GetUserGroups tests below are positive:
//   - user1 -> ["admins"]
//   - user2 -> ["readers"]
//
// Graceful skip:
//   FreeIPA containers are heavy (systemd, privileged mode, FQDN). On any
//   setup failure the whole suite is skipped, not failed.
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

// waitForFreeIPAReady polls Directory Manager bind until LDAP is fully ready.
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

// seedFreeIPA creates two users and two groups using the `ipa` CLI.
// `ipa group-add-member` populates `member` (DN) on the group, which is
// exactly the attribute the fixed adapter filter now correctly queries.
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

	conn, err := ldapper.NewConnection(
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

// newFreeIPAAuthConn authenticates as admin; bindDN = freeipaBaseDN, which is
// what AuthenticateUser(username, password) uses internally after the change.
func newFreeIPAAuthConn(t *testing.T, opts ...ldapper.Option) *ldapper.LDAPper {
	t.Helper()
	requireFreeIPA(t)

	conn, _, err := ldapper.NewAuthenticatedConnection(
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
// Adapter contract tests (no server needed)
// ---------------------------------------------------------------------------

// TestIntegrationFreeIPA_SearchUserGroupsFilterTemplate_PostFix guards the
// final state of the template: a single %s placeholder and no leftover
// "member=uid=" construct from the earlier broken version.
func TestIntegrationFreeIPA_SearchUserGroupsFilterTemplate_PostFix(t *testing.T) {
	tmpl := freeipaAdpt.SearchUserGroupsFilterTemplate()

	assert.NotContains(t, tmpl, "member=uid=",
		"regression: earlier versions had (member=uid=%s), which is invalid")
	assert.Contains(t, tmpl, "(member=%s)",
		"template must use a single %s placeholder for the member assertion")
}

// TestIntegrationFreeIPA_SearchUserGroupsFilterTemplateArgs_ReturnsDN asserts
// the fixed args helper returns the user's DN — the value the filter's
// (member=%s) assertion needs.
func TestIntegrationFreeIPA_SearchUserGroupsFilterTemplateArgs_ReturnsDN(t *testing.T) {
	const dn = "uid=user1,cn=users,cn=accounts,dc=example,dc=test"
	user := types.LDAPUser{
		DN: dn,
		Attributes: map[string][]string{
			"uid":  {"user1"},
			"mail": {"user1@example.test"},
		},
	}

	args := freeipaAdpt.SearchUserGroupsFilterTemplateArgs(user)
	require.Len(t, args, 1)
	require.Equal(t, dn, args[0],
		"args[0] must be the user's DN so that (member=%s) matches group.member")
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
	_, err := ldapper.NewConnection(nil, 389, false, true, nil, freeipaAdpt)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "empty hosts list")
}

func TestIntegrationFreeIPA_NewConnection_TooManyHosts(t *testing.T) {
	requireFreeIPA(t)
	hosts := make([]string, 100)
	for i := range hosts {
		hosts[i] = fmt.Sprintf("host%d", i)
	}
	_, err := ldapper.NewConnection(hosts, 389, false, true, nil, freeipaAdpt)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "too many hosts")
}

func TestIntegrationFreeIPA_NewConnection_NilTLSConfigWhenRequired(t *testing.T) {
	requireFreeIPA(t)
	_, err := ldapper.NewConnection([]string{freeipaHost}, freeipaPort, false, false, nil, freeipaAdpt)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "nil tls config")
}

func TestIntegrationFreeIPA_NewConnection_NilCatalogAdapter(t *testing.T) {
	requireFreeIPA(t)
	_, err := ldapper.NewConnection([]string{freeipaHost}, freeipaPort, false, true, nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "nil catalog adapter")
}

func TestIntegrationFreeIPA_NewConnection_UnreachableHost(t *testing.T) {
	requireFreeIPA(t)
	_, err := ldapper.NewConnection([]string{"127.0.0.1"}, 1, false, true, nil, freeipaAdpt)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsuccessful dial")
}

func TestIntegrationFreeIPA_NewAuthenticatedConnection_Success(t *testing.T) {
	requireFreeIPA(t)

	conn, user, err := ldapper.NewAuthenticatedConnection(
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
	_, _, err := ldapper.NewAuthenticatedConnection(
		"", "", freeipaBaseDN,
		[]string{freeipaHost}, freeipaPort, false, true, nil, freeipaAdpt,
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "empty bind username/password")
}

func TestIntegrationFreeIPA_NewAuthenticatedConnection_WrongPassword(t *testing.T) {
	requireFreeIPA(t)
	_, _, err := ldapper.NewAuthenticatedConnection(
		freeipaAdminDN, "wrong-password", freeipaBaseDN,
		[]string{freeipaHost}, freeipaPort, false, true, nil, freeipaAdpt,
	)
	require.Error(t, err)
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
	assert.Contains(t, err.Error(), "empty bind username/password")
}

func TestIntegrationFreeIPA_AuthenticateConn_WrongPassword(t *testing.T) {
	conn := newFreeIPAConn(t)
	_, err := conn.AuthenticateConn(freeipaAdminDN, "bad-password", freeipaBaseDN)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsuccessful bind")
}

func TestIntegrationFreeIPA_AuthenticateConn_NonExistentUser(t *testing.T) {
	conn := newFreeIPAConn(t)
	_, err := conn.AuthenticateConn(
		"uid=ghost,cn=users,cn=accounts,dc=example,dc=test", "whatever", freeipaBaseDN,
	)
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// AuthenticateUser — signature is (username, password); base DN comes from
// conn.bindDN stored by AuthenticateConn.
// ---------------------------------------------------------------------------

func TestIntegrationFreeIPA_AuthenticateUser_Success(t *testing.T) {
	requireFreeIPAUsers(t)
	conn := newFreeIPAAuthConn(t)

	user, err := conn.AuthenticateUser(freeipaUser1UID, freeipaUser1Pass)
	require.NoError(t, err)
	require.NotNil(t, user)
	assert.Equal(t, freeipaUser1UID, user.GetAttributeValue("uid"))
}

func TestIntegrationFreeIPA_AuthenticateUser_WrongPassword(t *testing.T) {
	requireFreeIPAUsers(t)
	conn := newFreeIPAAuthConn(t)

	user, err := conn.AuthenticateUser(freeipaUser1UID, "bad")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsuccessful bind with passed user credentials")
	require.NotNil(t, user)
	assert.Equal(t, freeipaUser1UID, user.GetAttributeValue("uid"))
}

func TestIntegrationFreeIPA_AuthenticateUser_NonExistentUser(t *testing.T) {
	conn := newFreeIPAAuthConn(t)
	_, err := conn.AuthenticateUser("ghost-user", "whatever")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "user does not exist")
}

func TestIntegrationFreeIPA_AuthenticateUser_NotAuthenticated(t *testing.T) {
	conn := newFreeIPAConn(t)
	_, err := conn.AuthenticateUser("anyone", "anything")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "connection not authenticated")
}

func TestIntegrationFreeIPA_AuthenticateUser_EmptyCredentials(t *testing.T) {
	conn := newFreeIPAAuthConn(t)
	_, err := conn.AuthenticateUser("", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "empty username/password")
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

	_, err := conn.AuthenticateUser(freeipaUser1UID, freeipaUser1Pass)
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

	_, err := conn.AuthenticateUser(freeipaUser1UID, freeipaUser1Pass)
	require.NoError(t, err)
}

func TestIntegrationFreeIPA_Close_Idempotent(t *testing.T) {
	conn := newFreeIPAConn(t)
	conn.Close()
	conn.Close() // must not panic

	_, err := conn.GetUser("admin", freeipaBaseDN)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "connection not initialized")
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
	assert.Contains(t, err.Error(), "connection not initialized")
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
	assert.Contains(t, err.Error(), "user does not exist")
}

func TestIntegrationFreeIPA_GetUser_NotInitialized(t *testing.T) {
	conn := newFreeIPAConn(t)
	conn.Close()

	_, err := conn.GetUser("admin", freeipaBaseDN)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "connection not initialized")
}

// ---------------------------------------------------------------------------
// GetUserGroups — POSITIVE after the args fix. FreeIPA's group memberships
// are stored in `member` as DN values, so (member=<user.DN>) matches.
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

// TestIntegrationFreeIPA_GetUserGroups_CrossCheckedByCustomSearch verifies
// that the positive result above agrees with an independent CustomSearch
// over the same `member=<DN>` filter — i.e., GetUserGroups is not accidentally
// returning a false positive for some other reason.
func TestIntegrationFreeIPA_GetUserGroups_CrossCheckedByCustomSearch(t *testing.T) {
	requireFreeIPAUsers(t)
	conn := newFreeIPAAuthConn(t)

	user, err := conn.GetUser(freeipaUser1UID, freeipaBaseDN)
	require.NoError(t, err)
	require.NotEmpty(t, user.DN)

	req := ldap.NewSearchRequest(
		freeipaBaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		0, 0, false,
		fmt.Sprintf("(&(objectClass=ipausergroup)(member=%s))", user.DN),
		[]string{"cn"}, nil,
	)
	res, err := conn.CustomSearch(req)
	require.NoError(t, err)
	require.NotEmpty(t, res.Entries)

	cns := make([]string, 0, len(res.Entries))
	for _, e := range res.Entries {
		cns = append(cns, e.GetAttributeValue("cn"))
	}
	assert.Contains(t, cns, "admins")
}

func TestIntegrationFreeIPA_GetUserGroups_UserNotFound(t *testing.T) {
	conn := newFreeIPAAuthConn(t)

	_, err := conn.GetUserGroups("nobody", freeipaBaseDN)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "user does not exist")
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

func TestIntegrationFreeIPA_GetOUUsers_NotInitialized(t *testing.T) {
	conn := newFreeIPAConn(t)
	conn.Close()

	_, err := conn.GetOUUsers("cn=users,cn=accounts," + freeipaBaseDN)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "connection not initialized")
}

// ---------------------------------------------------------------------------
// Search limits
// ---------------------------------------------------------------------------

func TestIntegrationFreeIPA_SearchLimits_Defaults(t *testing.T) {
	conn := newFreeIPAConn(t)
	limits := conn.GetSearchLimits()
	assert.Equal(t, 0, limits.SizeLimit)
	assert.Equal(t, 30, limits.TimeLimit)
}

func TestIntegrationFreeIPA_SearchLimits_WithOption(t *testing.T) {
	conn := newFreeIPAConn(t, ldapper.WithSearchLimits(5, 10))
	limits := conn.GetSearchLimits()
	assert.Equal(t, 5, limits.SizeLimit)
	assert.Equal(t, 10, limits.TimeLimit)
}

func TestIntegrationFreeIPA_SearchLimits_SetAtRuntime(t *testing.T) {
	conn := newFreeIPAConn(t)
	conn.SetSearchLimits(7, 11)
	limits := conn.GetSearchLimits()
	assert.Equal(t, 7, limits.SizeLimit)
	assert.Equal(t, 11, limits.TimeLimit)
}

func TestIntegrationFreeIPA_SearchLimits_NegativeClampedToZero(t *testing.T) {
	conn := newFreeIPAConn(t)
	conn.SetSearchLimits(-1, -5)
	limits := conn.GetSearchLimits()
	assert.Equal(t, 0, limits.SizeLimit)
	assert.Equal(t, 0, limits.TimeLimit)
}
