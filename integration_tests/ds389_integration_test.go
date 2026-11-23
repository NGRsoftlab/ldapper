//go:build integration_389ds
// +build integration_389ds

package ldapper_test

// 389 Directory Server integration tests.
//
// DS389Adapter is a thin extension of OPENLDAPAdapter: it adds the
// Netscape-specific nsAccount / nsOrgPerson object classes to the user
// filter and requests nsAccountLock in UserAttrs. Everything else (group
// model, short-form bind expansion, attribute mapping) is inherited and
// therefore exercised against a real 389-DS instance here.
//
// Image notes:
//   - 389ds/dirsrv exposes LDAP on :3389 (not :389), which is why
//     ds389Port is mapped from 3389/tcp.
//   - The container is seeded from Go after the port is listening — the
//     image's bootstrap timing is not reliable enough to depend on.
//
// Run with:
//   go test -tags=integration_389ds ./...

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
	ds389BaseDN   = "dc=example,dc=com"
	ds389RootDN   = "cn=Directory Manager"
	ds389RootPass = "DirectoryManagerPass1!"

	ds389User1DN   = "uid=user1,ou=People," + ds389BaseDN
	ds389User1UID  = "user1"
	ds389User1Pass = "User1Pass1!"

	ds389User2DN   = "uid=user2,ou=People," + ds389BaseDN
	ds389User2UID  = "user2"
	ds389User2Pass = "User2Pass2!"

	ds389EmptyOUDN = "ou=empty," + ds389BaseDN
)

var (
	ds389Host      string
	ds389Port      uint
	ds389Container testcontainers.Container
	ds389Available bool
	ds389Adpt      = adapters.DS389Adapter{}
)

func TestMain(m *testing.M) {
	ctx := context.Background()

	req := testcontainers.ContainerRequest{
		Image:        "389ds/dirsrv:latest",
		ExposedPorts: []string{"3389/tcp"},
		Env: map[string]string{
			"DS_DM_PASSWORD": ds389RootPass,
		},
		WaitingFor: wait.ForListeningPort("3389/tcp").WithStartupTimeout(180 * time.Second),
	}

	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "389-DS tests skipped: cannot start container: %v\n", err)
		os.Exit(m.Run())
	}
	ds389Container = container

	ds389Host, err = container.Host(ctx)
	if err != nil {
		_ = container.Terminate(ctx)
		fmt.Fprintf(os.Stderr, "389-DS tests skipped: cannot resolve host: %v\n", err)
		os.Exit(m.Run())
	}

	mappedPort, err := container.MappedPort(ctx, "3389")
	if err != nil {
		_ = container.Terminate(ctx)
		fmt.Fprintf(os.Stderr, "389-DS tests skipped: cannot resolve port: %v\n", err)
		os.Exit(m.Run())
	}
	ds389Port = uint(mappedPort.Num())

	if !waitForDS389Ready(ds389Host, ds389Port, 120*time.Second) {
		_ = container.Terminate(ctx)
		fmt.Fprintln(os.Stderr, "389-DS tests skipped: LDAP not ready")
		os.Exit(m.Run())
	}

	if err := seedDS389(ds389Host, ds389Port); err != nil {
		_ = container.Terminate(ctx)
		fmt.Fprintf(os.Stderr, "389-DS tests skipped: seed failed: %v\n", err)
		os.Exit(m.Run())
	}

	ds389Available = true
	code := m.Run()
	_ = container.Terminate(ctx)
	os.Exit(code)
}

func waitForDS389Ready(host string, port uint, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		c, err := ldap.DialURL(fmt.Sprintf("ldap://%s:%d", host, port))
		if err == nil {
			err = c.Bind(ds389RootDN, ds389RootPass)
			_ = c.Close()
			if err == nil {
				return true
			}
		}
		time.Sleep(1 * time.Second)
	}
	return false
}

func seedDS389(host string, port uint) error {
	c, err := ldap.DialURL(fmt.Sprintf("ldap://%s:%d", host, port))
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	defer c.Close()
	if err := c.Bind(ds389RootDN, ds389RootPass); err != nil {
		return fmt.Errorf("bind: %w", err)
	}

	entries := []struct {
		dn    string
		attrs map[string][]string
	}{
		{"ou=People," + ds389BaseDN, map[string][]string{
			"objectClass": {"top", "organizationalUnit"},
			"ou":          {"People"},
		}},
		{ds389EmptyOUDN, map[string][]string{
			"objectClass": {"top", "organizationalUnit"},
			"ou":          {"empty"},
		}},
		{"ou=Groups," + ds389BaseDN, map[string][]string{
			"objectClass": {"top", "organizationalUnit"},
			"ou":          {"Groups"},
		}},
		{ds389User1DN, map[string][]string{
			"objectClass":   {"top", "nsAccount", "nsOrgPerson", "inetOrgPerson", "posixAccount"},
			"cn":            {"user1"},
			"sn":            {"User"},
			"uid":           {ds389User1UID},
			"uidNumber":     {"1001"},
			"gidNumber":     {"1001"},
			"homeDirectory": {"/home/user1"},
			"userPassword":  {ds389User1Pass},
			"mail":          {"user1@example.com"},
		}},
		{ds389User2DN, map[string][]string{
			"objectClass":   {"top", "nsAccount", "nsOrgPerson", "inetOrgPerson", "posixAccount"},
			"cn":            {"user2"},
			"sn":            {"User"},
			"uid":           {ds389User2UID},
			"uidNumber":     {"1002"},
			"gidNumber":     {"1002"},
			"homeDirectory": {"/home/user2"},
			"userPassword":  {ds389User2Pass},
			"mail":          {"user2@example.com"},
		}},
		{"cn=admins,ou=Groups," + ds389BaseDN, map[string][]string{
			"objectClass": {"top", "groupOfNames"},
			"cn":          {"admins"},
			"member":      {ds389User1DN},
		}},
		{"cn=readers,ou=Groups," + ds389BaseDN, map[string][]string{
			"objectClass": {"top", "posixGroup"},
			"cn":          {"readers"},
			"gidNumber":   {"2001"},
			"memberUid":   {ds389User2UID},
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

func requireDS389(t *testing.T) {
	t.Helper()
	if !ds389Available {
		t.Skip("389-DS not available; test skipped")
	}
}

func newDS389Conn(t *testing.T, opts ...ldapper.Option) *ldapper.LDAPper {
	t.Helper()
	requireDS389(t)
	conn, err := ldapper.NewLDAPper(
		context.Background(), []string{ds389Host}, ds389Port,
		false, true, nil, ds389Adpt, opts...,
	)
	require.NoError(t, err)
	t.Cleanup(conn.Close)
	return conn
}

func newDS389AuthConn(t *testing.T, opts ...ldapper.Option) *ldapper.LDAPper {
	t.Helper()
	requireDS389(t)
	conn, err := ldapper.NewAuthenticatedLDAPper(
		context.Background(), ds389RootDN, ds389RootPass, ds389BaseDN,
		[]string{ds389Host}, ds389Port, false, true, nil, ds389Adpt, opts...,
	)
	require.NoError(t, err)
	t.Cleanup(conn.Close)
	return conn
}

// ================== constructor validation ==================

func TestIntegrationDS389_NewConnection_Success(t *testing.T) {
	conn := newDS389Conn(t)
	assert.True(t, conn.IsAlive(context.Background()))
}

func TestIntegrationDS389_NewConnection_EmptyHosts(t *testing.T) {
	requireDS389(t)
	_, err := ldapper.NewLDAPper(context.Background(), nil, 3389, false, true, nil, ds389Adpt)
	require.Error(t, err)
	assert.ErrorIs(t, err, ldapper.ErrInvalidArgument)
}

func TestIntegrationDS389_NewConnection_TooManyHosts(t *testing.T) {
	requireDS389(t)
	hosts := make([]string, constants.DefaultMaxHostsLength+1)
	for i := range hosts {
		hosts[i] = fmt.Sprintf("host%d", i)
	}
	_, err := ldapper.NewLDAPper(context.Background(), hosts, 3389, false, true, nil, ds389Adpt)
	require.Error(t, err)
	assert.ErrorIs(t, err, ldapper.ErrInvalidArgument)
}

func TestIntegrationDS389_NewConnection_NilCatalogAdapter(t *testing.T) {
	requireDS389(t)
	_, err := ldapper.NewLDAPper(context.Background(), []string{ds389Host}, ds389Port, false, true, nil, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, ldapper.ErrInvalidArgument)
}

func TestIntegrationDS389_NewConnection_UnreachableHost(t *testing.T) {
	requireDS389(t)
	_, err := ldapper.NewLDAPper(context.Background(), []string{"127.0.0.1"}, 1, false, true, nil, ds389Adpt)
	require.Error(t, err)
	assert.ErrorIs(t, err, ldapper.ErrUnavailable)
}

func TestIntegrationDS389_NewAuthenticatedConnection_Success(t *testing.T) {
	requireDS389(t)
	conn, err := ldapper.NewAuthenticatedLDAPper(
		context.Background(), ds389RootDN, ds389RootPass, ds389BaseDN,
		[]string{ds389Host}, ds389Port, false, true, nil, ds389Adpt,
	)
	require.NoError(t, err)
	defer conn.Close()
}

func TestIntegrationDS389_NewAuthenticatedConnection_WrongPassword(t *testing.T) {
	requireDS389(t)
	_, err := ldapper.NewAuthenticatedLDAPper(
		context.Background(), ds389RootDN, "wrong-password", ds389BaseDN,
		[]string{ds389Host}, ds389Port, false, true, nil, ds389Adpt,
	)
	require.Error(t, err)
	assert.ErrorIs(t, err, ldapper.ErrInvalidCredentials)
}

// ================== BindConn / CheckUserCredentials ==================

func TestIntegrationDS389_BindConn_Success(t *testing.T) {
	conn := newDS389Conn(t)
	err := conn.BindConn(context.Background(), ds389RootDN, ds389RootPass, ds389BaseDN)
	require.NoError(t, err)
}

func TestIntegrationDS389_BindConn_WrongPassword(t *testing.T) {
	conn := newDS389Conn(t)
	err := conn.BindConn(context.Background(), ds389RootDN, "bad-password", ds389BaseDN)
	require.Error(t, err)
	assert.ErrorIs(t, err, ldapper.ErrInvalidCredentials)
}

func TestIntegrationDS389_CheckUserCredentials_Success(t *testing.T) {
	conn := newDS389AuthConn(t)
	user, err := conn.CheckUserCredentials(context.Background(), ds389User1UID, ds389User1Pass)
	require.NoError(t, err)
	require.NotNil(t, user)
	assert.Equal(t, ds389User1UID, user.GetAttributeValue("uid"))
}

func TestIntegrationDS389_CheckUserCredentials_WrongPassword(t *testing.T) {
	conn := newDS389AuthConn(t)
	user, err := conn.CheckUserCredentials(context.Background(), ds389User1UID, "bad")
	require.Error(t, err)
	assert.ErrorIs(t, err, ldapper.ErrInvalidCredentials)
	assert.Nil(t, user)
}

func TestIntegrationDS389_CheckUserCredentials_NotAuthenticated(t *testing.T) {
	conn := newDS389Conn(t)
	_, err := conn.CheckUserCredentials(context.Background(), ds389User1UID, ds389User1Pass)
	require.Error(t, err)
	assert.ErrorIs(t, err, ldapper.ErrNotAuthenticated)
}

// ================== GetUser / GetGroup / GetOU ==================

func TestIntegrationDS389_GetUser_ByUID(t *testing.T) {
	conn := newDS389AuthConn(t)
	user, err := conn.GetUser(context.Background(), ds389User1UID, ds389BaseDN)
	require.NoError(t, err)
	assert.Equal(t, ds389User1DN, user.DN)
	assert.Equal(t, "user1", user.GetAttributeValue("uid"))
}

func TestIntegrationDS389_GetUser_NotFound(t *testing.T) {
	conn := newDS389AuthConn(t)
	_, err := conn.GetUser(context.Background(), "does-not-exist", ds389BaseDN)
	require.Error(t, err)
	assert.ErrorIs(t, err, ldapper.ErrNotFoundOrNotVisible)
}

func TestIntegrationDS389_GetGroup_Success(t *testing.T) {
	conn := newDS389AuthConn(t)
	group, err := conn.GetGroup(context.Background(), "admins", ds389BaseDN)
	require.NoError(t, err)
	require.NotNil(t, group)
	assert.Equal(t, "admins", group.GetAttributeValue("cn"))
}

func TestIntegrationDS389_GetOU_Success(t *testing.T) {
	conn := newDS389AuthConn(t)
	ou, err := conn.GetOU(context.Background(), "People", ds389BaseDN)
	require.NoError(t, err)
	require.NotNil(t, ou)
	assert.Equal(t, "People", ou.GetAttributeValue("ou"))
}

// ================== GetUserGroups ==================

func TestIntegrationDS389_GetUserGroups_GroupOfNamesBranch(t *testing.T) {
	conn := newDS389AuthConn(t)
	groups, err := conn.GetUserGroups(context.Background(), ds389User1UID, ds389BaseDN)
	require.NoError(t, err)
	assert.True(t, containsDN(groups, "cn=admins"),
		"expected an admins group DN in %v", groups)
}

func TestIntegrationDS389_GetUserGroups_PosixGroupBranch(t *testing.T) {
	conn := newDS389AuthConn(t)
	groups, err := conn.GetUserGroups(context.Background(), ds389User2UID, ds389BaseDN)
	require.NoError(t, err)
	assert.True(t, containsDN(groups, "cn=readers"),
		"expected a readers group DN in %v", groups)
}

// ================== GetCatalogTree / GetSubOUs / GetOUUsers ==================

func TestIntegrationDS389_GetCatalogTree_Success(t *testing.T) {
	conn := newDS389AuthConn(t)
	tree, err := conn.GetCatalogTree(context.Background(), ds389BaseDN, 0)
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

func TestIntegrationDS389_GetSubOUs_SingleLevel(t *testing.T) {
	conn := newDS389AuthConn(t)
	ous, err := conn.GetSubOUs(context.Background(), ds389BaseDN, ldap.ScopeSingleLevel)
	require.NoError(t, err)

	var names []string
	for _, ou := range ous {
		names = append(names, ou.Name)
	}
	assert.Contains(t, names, "People")
	assert.Contains(t, names, "Groups")
	assert.Contains(t, names, "empty")
}

func TestIntegrationDS389_GetOUUsers(t *testing.T) {
	conn := newDS389AuthConn(t)
	users, err := conn.GetOUUsers(context.Background(), "ou=People,"+ds389BaseDN)
	require.NoError(t, err)
	require.Len(t, users, 2)

	uids := make([]string, 0, len(users))
	for _, u := range users {
		uids = append(uids, u.GetAttributeValue("uid"))
	}
	assert.ElementsMatch(t, []string{ds389User1UID, ds389User2UID}, uids)
}

// ================== Health checks / Reconnect / Close ==================

func TestIntegrationDS389_IsAlive_AfterClose(t *testing.T) {
	conn := newDS389Conn(t)
	conn.Close()
	assert.False(t, conn.IsAlive(context.Background()))
}

func TestIntegrationDS389_Reconnect_PreservesAuthentication(t *testing.T) {
	conn := newDS389AuthConn(t)
	require.NoError(t, conn.Reconnect(context.Background()))
	_, err := conn.CheckUserCredentials(context.Background(), ds389User1UID, ds389User1Pass)
	require.NoError(t, err)
}

func TestIntegrationDS389_EnsureAlive_ClosedClient_ReturnsErrClosed(t *testing.T) {
	conn := newDS389AuthConn(t)
	conn.Close()
	require.False(t, conn.IsAlive(context.Background()))

	err := conn.EnsureAlive(context.Background())
	require.Error(t, err)
	assert.ErrorIs(t, err, ldapper.ErrClosed)
}

// DS389Adapter must NOT implement PrimaryGroupResolver — 389-DS has no
// primaryGroupID concept, and the presence of the interface would make
// GetUserGroups try to resolve a non-existent attribute. Go has no static
// "does not implement" assertion; the init-time check below panics if a
// future edit adds the method.
var _ = func() any {
	if _, ok := any(adapters.DS389Adapter{}).(interfaces.PrimaryGroupResolver); ok {
		panic("DS389Adapter must not implement PrimaryGroupResolver")
	}
	return nil
}()
