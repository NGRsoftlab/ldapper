//go:build integration_opendj
// +build integration_opendj

package ldapper_test

// OpenDJ integration tests.
//
// OpenDJAdapter extends OPENLDAPAdapter with the virtual isMemberOf
// attribute. The group model is the standard LDAP one
// (groupOfNames / groupOfUniqueNames / posixGroup), so most behaviour is
// inherited and exercised against a real OpenDJ instance here.
//
// Image notes:
//   - openidentityplatform/opendj listens on :1389 (LDAP) and :1636 (LDAPS).
//   - BASE_DN, ROOT_USER_DN and ROOT_PASSWORD are configured through env.
//   - The container is seeded from Go after the port is listening.
//
// Run with:
//   go test -tags=integration_opendj ./...

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
	"github.com/NGRsoftlab/ldapper/interfaces"
	"github.com/NGRsoftlab/ldapper/types"
)

const (
	opendjBaseDN   = "dc=example,dc=com"
	opendjRootDN   = "cn=Directory Manager"
	opendjRootPass = "DirectoryManagerPass1!"

	opendjUser1DN   = "uid=user1,ou=People," + opendjBaseDN
	opendjUser1UID  = "user1"
	opendjUser1Pass = "User1Pass1!"

	opendjUser2DN   = "uid=user2,ou=People," + opendjBaseDN
	opendjUser2UID  = "user2"
	opendjUser2Pass = "User2Pass2!"

	opendjEmptyOUDN = "ou=empty," + opendjBaseDN
)

var (
	opendjHost      string
	opendjPort      uint
	opendjContainer testcontainers.Container
	opendjAvailable bool
	opendjAdpt      = adapters.OpenDJAdapter{}
)

func TestMain(m *testing.M) {
	ctx := context.Background()

	req := testcontainers.ContainerRequest{
		Image:        "openidentityplatform/opendj:latest",
		ExposedPorts: []string{"1389/tcp"},
		Env: map[string]string{
			"BASE_DN":       opendjBaseDN,
			"ROOT_USER_DN":  opendjRootDN,
			"ROOT_PASSWORD": opendjRootPass,
		},
		WaitingFor: wait.ForListeningPort("1389/tcp").WithStartupTimeout(180 * time.Second),
	}

	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "OpenDJ tests skipped: cannot start container: %v\n", err)
		os.Exit(m.Run())
	}
	opendjContainer = container

	opendjHost, err = container.Host(ctx)
	if err != nil {
		_ = container.Terminate(ctx)
		fmt.Fprintf(os.Stderr, "OpenDJ tests skipped: cannot resolve host: %v\n", err)
		os.Exit(m.Run())
	}

	mappedPort, err := container.MappedPort(ctx, "1389")
	if err != nil {
		_ = container.Terminate(ctx)
		fmt.Fprintf(os.Stderr, "OpenDJ tests skipped: cannot resolve port: %v\n", err)
		os.Exit(m.Run())
	}
	opendjPort = uint(mappedPort.Num())

	if !waitForOpenDJReady(opendjHost, opendjPort, 120*time.Second) {
		_ = container.Terminate(ctx)
		fmt.Fprintln(os.Stderr, "OpenDJ tests skipped: LDAP not ready")
		os.Exit(m.Run())
	}

	if err := seedOpenDJ(opendjHost, opendjPort); err != nil {
		_ = container.Terminate(ctx)
		fmt.Fprintf(os.Stderr, "OpenDJ tests skipped: seed failed: %v\n", err)
		os.Exit(m.Run())
	}

	opendjAvailable = true
	code := m.Run()
	_ = container.Terminate(ctx)
	os.Exit(code)
}

func waitForOpenDJReady(host string, port uint, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		c, err := ldap.DialURL(fmt.Sprintf("ldap://%s:%d", host, port))
		if err == nil {
			err = c.Bind(opendjRootDN, opendjRootPass)
			_ = c.Close()
			if err == nil {
				return true
			}
		}
		time.Sleep(1 * time.Second)
	}
	return false
}

func seedOpenDJ(host string, port uint) error {
	c, err := ldap.DialURL(fmt.Sprintf("ldap://%s:%d", host, port))
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	defer c.Close()
	if err := c.Bind(opendjRootDN, opendjRootPass); err != nil {
		return fmt.Errorf("bind: %w", err)
	}

	entries := []struct {
		dn    string
		attrs map[string][]string
	}{
		{"ou=People," + opendjBaseDN, map[string][]string{
			"objectClass": {"top", "organizationalUnit"},
			"ou":          {"People"},
		}},
		{opendjEmptyOUDN, map[string][]string{
			"objectClass": {"top", "organizationalUnit"},
			"ou":          {"empty"},
		}},
		{"ou=Groups," + opendjBaseDN, map[string][]string{
			"objectClass": {"top", "organizationalUnit"},
			"ou":          {"Groups"},
		}},
		{opendjUser1DN, map[string][]string{
			"objectClass":   {"top", "inetOrgPerson", "posixAccount"},
			"cn":            {"user1"},
			"sn":            {"User"},
			"uid":           {opendjUser1UID},
			"uidNumber":     {"1001"},
			"gidNumber":     {"1001"},
			"homeDirectory": {"/home/user1"},
			"userPassword":  {opendjUser1Pass},
			"mail":          {"user1@example.com"},
		}},
		{opendjUser2DN, map[string][]string{
			"objectClass":   {"top", "inetOrgPerson", "posixAccount"},
			"cn":            {"user2"},
			"sn":            {"User"},
			"uid":           {opendjUser2UID},
			"uidNumber":     {"1002"},
			"gidNumber":     {"1002"},
			"homeDirectory": {"/home/user2"},
			"userPassword":  {opendjUser2Pass},
			"mail":          {"user2@example.com"},
		}},
		{"cn=admins,ou=Groups," + opendjBaseDN, map[string][]string{
			"objectClass": {"top", "groupOfNames"},
			"cn":          {"admins"},
			"member":      {opendjUser1DN},
		}},
		{"cn=readers,ou=Groups," + opendjBaseDN, map[string][]string{
			"objectClass": {"top", "posixGroup"},
			"cn":          {"readers"},
			"gidNumber":   {"2001"},
			"memberUid":   {opendjUser2UID},
		}},
	}

	for _, e := range entries {
		_, err := c.Search(ldap.NewSearchRequest(
			e.dn, ldap.ScopeBaseObject, ldap.NeverDerefAliases,
			1, 0, false, "(objectClass=*)", []string{"1.1"}, nil))
		if err == nil {
			continue
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

func requireOpenDJ(t *testing.T) {
	t.Helper()
	if !opendjAvailable {
		t.Skip("OpenDJ not available; test skipped")
	}
}

func newOpenDJConn(t *testing.T, opts ...ldapper.Option) *ldapper.LDAPper {
	t.Helper()
	requireOpenDJ(t)
	conn, err := ldapper.NewLDAPper(
		context.Background(), []string{opendjHost}, opendjPort,
		false, true, nil, opendjAdpt, opts...,
	)
	require.NoError(t, err)
	t.Cleanup(conn.Close)
	return conn
}

func newOpenDJAuthConn(t *testing.T, opts ...ldapper.Option) *ldapper.LDAPper {
	t.Helper()
	requireOpenDJ(t)
	conn, err := ldapper.NewAuthenticatedLDAPper(
		context.Background(), opendjRootDN, opendjRootPass, opendjBaseDN,
		[]string{opendjHost}, opendjPort, false, true, nil, opendjAdpt, opts...,
	)
	require.NoError(t, err)
	t.Cleanup(conn.Close)
	return conn
}

// ================== constructor validation ==================

func TestIntegrationOpenDJ_NewConnection_Success(t *testing.T) {
	conn := newOpenDJConn(t)
	assert.True(t, conn.IsAlive(context.Background()))
}

func TestIntegrationOpenDJ_NewConnection_EmptyHosts(t *testing.T) {
	requireOpenDJ(t)
	_, err := ldapper.NewLDAPper(context.Background(), nil, 1389, false, true, nil, opendjAdpt)
	require.Error(t, err)
	assert.ErrorIs(t, err, ldapper.ErrInvalidArgument)
}

func TestIntegrationOpenDJ_NewConnection_TooManyHosts(t *testing.T) {
	requireOpenDJ(t)
	hosts := make([]string, constants.DefaultMaxHostsLength+1)
	for i := range hosts {
		hosts[i] = fmt.Sprintf("host%d", i)
	}
	_, err := ldapper.NewLDAPper(context.Background(), hosts, 1389, false, true, nil, opendjAdpt)
	require.Error(t, err)
	assert.ErrorIs(t, err, ldapper.ErrInvalidArgument)
}

func TestIntegrationOpenDJ_NewConnection_NilCatalogAdapter(t *testing.T) {
	requireOpenDJ(t)
	_, err := ldapper.NewLDAPper(context.Background(), []string{opendjHost}, opendjPort, false, true, nil, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, ldapper.ErrInvalidArgument)
}

func TestIntegrationOpenDJ_NewConnection_UnreachableHost(t *testing.T) {
	requireOpenDJ(t)
	_, err := ldapper.NewLDAPper(context.Background(), []string{"127.0.0.1"}, 1, false, true, nil, opendjAdpt)
	require.Error(t, err)
	assert.ErrorIs(t, err, ldapper.ErrUnavailable)
}

func TestIntegrationOpenDJ_NewAuthenticatedConnection_Success(t *testing.T) {
	requireOpenDJ(t)
	conn, err := ldapper.NewAuthenticatedLDAPper(
		context.Background(), opendjRootDN, opendjRootPass, opendjBaseDN,
		[]string{opendjHost}, opendjPort, false, true, nil, opendjAdpt,
	)
	require.NoError(t, err)
	defer conn.Close()
}

func TestIntegrationOpenDJ_NewAuthenticatedConnection_WrongPassword(t *testing.T) {
	requireOpenDJ(t)
	_, err := ldapper.NewAuthenticatedLDAPper(
		context.Background(), opendjRootDN, "wrong-password", opendjBaseDN,
		[]string{opendjHost}, opendjPort, false, true, nil, opendjAdpt,
	)
	require.Error(t, err)
	assert.ErrorIs(t, err, ldapper.ErrInvalidCredentials)
}

// ================== BindConn / CheckUserCredentials ==================

func TestIntegrationOpenDJ_BindConn_Success(t *testing.T) {
	conn := newOpenDJConn(t)
	err := conn.BindConn(context.Background(), opendjRootDN, opendjRootPass, opendjBaseDN)
	require.NoError(t, err)
}

func TestIntegrationOpenDJ_BindConn_WrongPassword(t *testing.T) {
	conn := newOpenDJConn(t)
	err := conn.BindConn(context.Background(), opendjRootDN, "bad-password", opendjBaseDN)
	require.Error(t, err)
	assert.ErrorIs(t, err, ldapper.ErrInvalidCredentials)
}

func TestIntegrationOpenDJ_CheckUserCredentials_Success(t *testing.T) {
	conn := newOpenDJAuthConn(t)
	user, err := conn.CheckUserCredentials(context.Background(), opendjUser1UID, opendjUser1Pass)
	require.NoError(t, err)
	require.NotNil(t, user)
	assert.Equal(t, opendjUser1UID, user.GetAttributeValue("uid"))
}

func TestIntegrationOpenDJ_CheckUserCredentials_WrongPassword(t *testing.T) {
	conn := newOpenDJAuthConn(t)
	user, err := conn.CheckUserCredentials(context.Background(), opendjUser1UID, "bad")
	require.Error(t, err)
	assert.ErrorIs(t, err, ldapper.ErrInvalidCredentials)
	assert.Nil(t, user)
}

func TestIntegrationOpenDJ_CheckUserCredentials_NotAuthenticated(t *testing.T) {
	conn := newOpenDJConn(t)
	_, err := conn.CheckUserCredentials(context.Background(), opendjUser1UID, opendjUser1Pass)
	require.Error(t, err)
	assert.ErrorIs(t, err, ldapper.ErrNotAuthenticated)
}

// ================== GetUser / GetGroup / GetOU ==================

func TestIntegrationOpenDJ_GetUser_ByUID(t *testing.T) {
	conn := newOpenDJAuthConn(t)
	user, err := conn.GetUser(context.Background(), opendjUser1UID, opendjBaseDN)
	require.NoError(t, err)
	assert.Equal(t, opendjUser1DN, user.DN)
	assert.Equal(t, "user1", user.GetAttributeValue("uid"))
}

func TestIntegrationOpenDJ_GetUser_NotFound(t *testing.T) {
	conn := newOpenDJAuthConn(t)
	_, err := conn.GetUser(context.Background(), "does-not-exist", opendjBaseDN)
	require.Error(t, err)
	assert.ErrorIs(t, err, ldapper.ErrNotFoundOrNotVisible)
}

func TestIntegrationOpenDJ_GetGroup_Success(t *testing.T) {
	conn := newOpenDJAuthConn(t)
	group, err := conn.GetGroup(context.Background(), "admins", opendjBaseDN)
	require.NoError(t, err)
	require.NotNil(t, group)
	assert.Equal(t, "admins", group.GetAttributeValue("cn"))
}

func TestIntegrationOpenDJ_GetOU_Success(t *testing.T) {
	conn := newOpenDJAuthConn(t)
	ou, err := conn.GetOU(context.Background(), "People", opendjBaseDN)
	require.NoError(t, err)
	require.NotNil(t, ou)
	assert.Equal(t, "People", ou.GetAttributeValue("ou"))
}

// ================== GetUserGroups ==================

func TestIntegrationOpenDJ_GetUserGroups_GroupOfNamesBranch(t *testing.T) {
	conn := newOpenDJAuthConn(t)
	groups, err := conn.GetUserGroups(context.Background(), opendjUser1UID, opendjBaseDN)
	require.NoError(t, err)
	assert.True(t, containsDN(groups, "cn=admins"),
		"expected an admins group DN in %v", groups)
}

func TestIntegrationOpenDJ_GetUserGroups_PosixGroupBranch(t *testing.T) {
	conn := newOpenDJAuthConn(t)
	groups, err := conn.GetUserGroups(context.Background(), opendjUser2UID, opendjBaseDN)
	require.NoError(t, err)
	assert.True(t, containsDN(groups, "cn=readers"),
		"expected a readers group DN in %v", groups)
}

// ================== GetCatalogTree / GetSubOUs / GetOUUsers ==================

func TestIntegrationOpenDJ_GetCatalogTree_Success(t *testing.T) {
	conn := newOpenDJAuthConn(t)
	tree, err := conn.GetCatalogTree(context.Background(), opendjBaseDN, 0)
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
	assert.Contains(t, names, "people")
	assert.Contains(t, names, "groups")
	assert.Contains(t, names, "empty")
}

func TestIntegrationOpenDJ_GetSubOUs_SingleLevel(t *testing.T) {
	conn := newOpenDJAuthConn(t)
	ous, err := conn.GetSubOUs(context.Background(), opendjBaseDN, ldap.ScopeSingleLevel)
	require.NoError(t, err)

	var names []string
	for _, ou := range ous {
		names = append(names, ou.Name)
	}
	assert.Contains(t, names, "People")
	assert.Contains(t, names, "Groups")
	assert.Contains(t, names, "empty")
}

func TestIntegrationOpenDJ_GetOUUsers(t *testing.T) {
	conn := newOpenDJAuthConn(t)
	users, err := conn.GetOUUsers(context.Background(), "ou=People,"+opendjBaseDN)
	require.NoError(t, err)
	require.Len(t, users, 2)

	uids := make([]string, 0, len(users))
	for _, u := range users {
		uids = append(uids, u.GetAttributeValue("uid"))
	}
	assert.ElementsMatch(t, []string{opendjUser1UID, opendjUser2UID}, uids)
}

// ================== Health checks / Reconnect / Close ==================

func TestIntegrationOpenDJ_IsAlive_AfterClose(t *testing.T) {
	conn := newOpenDJConn(t)
	conn.Close()
	assert.False(t, conn.IsAlive(context.Background()))
}

func TestIntegrationOpenDJ_Reconnect_PreservesAuthentication(t *testing.T) {
	conn := newOpenDJAuthConn(t)
	require.NoError(t, conn.Reconnect(context.Background()))
	_, err := conn.CheckUserCredentials(context.Background(), opendjUser1UID, opendjUser1Pass)
	require.NoError(t, err)
}

func TestIntegrationOpenDJ_EnsureAlive_ClosedClient_ReturnsErrClosed(t *testing.T) {
	conn := newOpenDJAuthConn(t)
	conn.Close()
	require.False(t, conn.IsAlive(context.Background()))

	err := conn.EnsureAlive(context.Background())
	require.Error(t, err)
	assert.ErrorIs(t, err, ldapper.ErrClosed)
}

// OpenDJAdapter must NOT implement PrimaryGroupResolver — OpenDJ has no
// primaryGroupID concept, and the presence of the interface would make
// GetUserGroups try to resolve a non-existent attribute. Go has no static
// "does not implement" assertion; the init-time check below panics if a
// future edit adds the method.
var _ = func() any {
	if _, ok := any(adapters.OpenDJAdapter{}).(interfaces.PrimaryGroupResolver); ok {
		panic("OpenDJAdapter must not implement PrimaryGroupResolver")
	}
	return nil
}()
