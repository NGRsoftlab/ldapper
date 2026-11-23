//go:build integration_oud
// +build integration_oud

package ldapper_test

// Oracle Unified Directory (OUD) integration tests.
//
// OUDAdapter is a strict extension of OpenDJAdapter: the two products
// share an LDAP engine (OUD is Oracle's fork of OpenDJ), so the group
// model, user schema and virtual isMemberOf attribute are identical.
//
// For this suite we use the openidentityplatform/opendj image as an
// OUD-compatible proxy. A real Oracle OUD image requires an Oracle
// licence and is not redistributable; the OpenDJ image exercises the
// same wire behaviour that OUDAdapter is written against. The suite
// therefore serves as an OUD contract test even though the binary is
// OpenDJ.
//
// Run with:
//   go test -tags=integration_oud ./...

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
	oudBaseDN   = "dc=example,dc=com"
	oudRootDN   = "cn=Directory Manager"
	oudRootPass = "DirectoryManagerPass1!"

	oudUser1DN   = "uid=user1,ou=People," + oudBaseDN
	oudUser1UID  = "user1"
	oudUser1Pass = "User1Pass1!"

	oudUser2DN   = "uid=user2,ou=People," + oudBaseDN
	oudUser2UID  = "user2"
	oudUser2Pass = "User2Pass2!"

	oudEmptyOUDN = "ou=empty," + oudBaseDN
)

var (
	oudHost      string
	oudPort      uint
	oudContainer testcontainers.Container
	oudAvailable bool
	oudAdpt      = adapters.OUDAdapter{}
)

func TestMain(m *testing.M) {
	ctx := context.Background()

	req := testcontainers.ContainerRequest{
		Image:        "openidentityplatform/opendj:latest",
		ExposedPorts: []string{"1389/tcp"},
		Env: map[string]string{
			"BASE_DN":       oudBaseDN,
			"ROOT_USER_DN":  oudRootDN,
			"ROOT_PASSWORD": oudRootPass,
		},
		WaitingFor: wait.ForListeningPort("1389/tcp").WithStartupTimeout(180 * time.Second),
	}

	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "OUD tests skipped: cannot start container: %v\n", err)
		os.Exit(m.Run())
	}
	oudContainer = container

	oudHost, err = container.Host(ctx)
	if err != nil {
		_ = container.Terminate(ctx)
		fmt.Fprintf(os.Stderr, "OUD tests skipped: cannot resolve host: %v\n", err)
		os.Exit(m.Run())
	}

	mappedPort, err := container.MappedPort(ctx, "1389")
	if err != nil {
		_ = container.Terminate(ctx)
		fmt.Fprintf(os.Stderr, "OUD tests skipped: cannot resolve port: %v\n", err)
		os.Exit(m.Run())
	}
	oudPort = uint(mappedPort.Num())

	if !waitForOUDReady(oudHost, oudPort, 120*time.Second) {
		_ = container.Terminate(ctx)
		fmt.Fprintln(os.Stderr, "OUD tests skipped: LDAP not ready")
		os.Exit(m.Run())
	}

	if err := seedOUD(oudHost, oudPort); err != nil {
		_ = container.Terminate(ctx)
		fmt.Fprintf(os.Stderr, "OUD tests skipped: seed failed: %v\n", err)
		os.Exit(m.Run())
	}

	oudAvailable = true
	code := m.Run()
	_ = container.Terminate(ctx)
	os.Exit(code)
}

func waitForOUDReady(host string, port uint, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		c, err := ldap.DialURL(fmt.Sprintf("ldap://%s:%d", host, port))
		if err == nil {
			err = c.Bind(oudRootDN, oudRootPass)
			_ = c.Close()
			if err == nil {
				return true
			}
		}
		time.Sleep(1 * time.Second)
	}
	return false
}

func seedOUD(host string, port uint) error {
	c, err := ldap.DialURL(fmt.Sprintf("ldap://%s:%d", host, port))
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	defer c.Close()
	if err := c.Bind(oudRootDN, oudRootPass); err != nil {
		return fmt.Errorf("bind: %w", err)
	}

	entries := []struct {
		dn    string
		attrs map[string][]string
	}{
		{"ou=People," + oudBaseDN, map[string][]string{
			"objectClass": {"top", "organizationalUnit"},
			"ou":          {"People"},
		}},
		{oudEmptyOUDN, map[string][]string{
			"objectClass": {"top", "organizationalUnit"},
			"ou":          {"empty"},
		}},
		{"ou=Groups," + oudBaseDN, map[string][]string{
			"objectClass": {"top", "organizationalUnit"},
			"ou":          {"Groups"},
		}},
		{oudUser1DN, map[string][]string{
			"objectClass":   {"top", "inetOrgPerson", "posixAccount"},
			"cn":            {"user1"},
			"sn":            {"User"},
			"uid":           {oudUser1UID},
			"uidNumber":     {"1001"},
			"gidNumber":     {"1001"},
			"homeDirectory": {"/home/user1"},
			"userPassword":  {oudUser1Pass},
			"mail":          {"user1@example.com"},
		}},
		{oudUser2DN, map[string][]string{
			"objectClass":   {"top", "inetOrgPerson", "posixAccount"},
			"cn":            {"user2"},
			"sn":            {"User"},
			"uid":           {oudUser2UID},
			"uidNumber":     {"1002"},
			"gidNumber":     {"1002"},
			"homeDirectory": {"/home/user2"},
			"userPassword":  {oudUser2Pass},
			"mail":          {"user2@example.com"},
		}},
		{"cn=admins,ou=Groups," + oudBaseDN, map[string][]string{
			"objectClass": {"top", "groupOfNames"},
			"cn":          {"admins"},
			"member":      {oudUser1DN},
		}},
		{"cn=readers,ou=Groups," + oudBaseDN, map[string][]string{
			"objectClass": {"top", "posixGroup"},
			"cn":          {"readers"},
			"gidNumber":   {"2001"},
			"memberUid":   {oudUser2UID},
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

func requireOUD(t *testing.T) {
	t.Helper()
	if !oudAvailable {
		t.Skip("OUD not available; test skipped")
	}
}

func newOUDConn(t *testing.T, opts ...ldapper.Option) *ldapper.LDAPper {
	t.Helper()
	requireOUD(t)
	conn, err := ldapper.NewLDAPper(
		context.Background(), []string{oudHost}, oudPort,
		false, true, nil, oudAdpt, opts...,
	)
	require.NoError(t, err)
	t.Cleanup(conn.Close)
	return conn
}

func newOUDAuthConn(t *testing.T, opts ...ldapper.Option) *ldapper.LDAPper {
	t.Helper()
	requireOUD(t)
	conn, err := ldapper.NewAuthenticatedLDAPper(
		context.Background(), oudRootDN, oudRootPass, oudBaseDN,
		[]string{oudHost}, oudPort, false, true, nil, oudAdpt, opts...,
	)
	require.NoError(t, err)
	t.Cleanup(conn.Close)
	return conn
}

// ================== constructor validation ==================

func TestIntegrationOUD_NewConnection_Success(t *testing.T) {
	conn := newOUDConn(t)
	assert.True(t, conn.IsAlive(context.Background()))
}

func TestIntegrationOUD_NewConnection_EmptyHosts(t *testing.T) {
	requireOUD(t)
	_, err := ldapper.NewLDAPper(context.Background(), nil, 1389, false, true, nil, oudAdpt)
	require.Error(t, err)
	assert.ErrorIs(t, err, ldapper.ErrInvalidArgument)
}

func TestIntegrationOUD_NewConnection_TooManyHosts(t *testing.T) {
	requireOUD(t)
	hosts := make([]string, constants.DefaultMaxHostsLength+1)
	for i := range hosts {
		hosts[i] = fmt.Sprintf("host%d", i)
	}
	_, err := ldapper.NewLDAPper(context.Background(), hosts, 1389, false, true, nil, oudAdpt)
	require.Error(t, err)
	assert.ErrorIs(t, err, ldapper.ErrInvalidArgument)
}

func TestIntegrationOUD_NewConnection_NilCatalogAdapter(t *testing.T) {
	requireOUD(t)
	_, err := ldapper.NewLDAPper(context.Background(), []string{oudHost}, oudPort, false, true, nil, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, ldapper.ErrInvalidArgument)
}

func TestIntegrationOUD_NewConnection_UnreachableHost(t *testing.T) {
	requireOUD(t)
	_, err := ldapper.NewLDAPper(context.Background(), []string{"127.0.0.1"}, 1, false, true, nil, oudAdpt)
	require.Error(t, err)
	assert.ErrorIs(t, err, ldapper.ErrUnavailable)
}

func TestIntegrationOUD_NewAuthenticatedConnection_Success(t *testing.T) {
	requireOUD(t)
	conn, err := ldapper.NewAuthenticatedLDAPper(
		context.Background(), oudRootDN, oudRootPass, oudBaseDN,
		[]string{oudHost}, oudPort, false, true, nil, oudAdpt,
	)
	require.NoError(t, err)
	defer conn.Close()
}

func TestIntegrationOUD_NewAuthenticatedConnection_WrongPassword(t *testing.T) {
	requireOUD(t)
	_, err := ldapper.NewAuthenticatedLDAPper(
		context.Background(), oudRootDN, "wrong-password", oudBaseDN,
		[]string{oudHost}, oudPort, false, true, nil, oudAdpt,
	)
	require.Error(t, err)
	assert.ErrorIs(t, err, ldapper.ErrInvalidCredentials)
}

// ================== BindConn / CheckUserCredentials ==================

func TestIntegrationOUD_BindConn_Success(t *testing.T) {
	conn := newOUDConn(t)
	err := conn.BindConn(context.Background(), oudRootDN, oudRootPass, oudBaseDN)
	require.NoError(t, err)
}

func TestIntegrationOUD_BindConn_WrongPassword(t *testing.T) {
	conn := newOUDConn(t)
	err := conn.BindConn(context.Background(), oudRootDN, "bad-password", oudBaseDN)
	require.Error(t, err)
	assert.ErrorIs(t, err, ldapper.ErrInvalidCredentials)
}

func TestIntegrationOUD_CheckUserCredentials_Success(t *testing.T) {
	conn := newOUDAuthConn(t)
	user, err := conn.CheckUserCredentials(context.Background(), oudUser1UID, oudUser1Pass)
	require.NoError(t, err)
	require.NotNil(t, user)
	assert.Equal(t, oudUser1UID, user.GetAttributeValue("uid"))
}

func TestIntegrationOUD_CheckUserCredentials_WrongPassword(t *testing.T) {
	conn := newOUDAuthConn(t)
	user, err := conn.CheckUserCredentials(context.Background(), oudUser1UID, "bad")
	require.Error(t, err)
	assert.ErrorIs(t, err, ldapper.ErrInvalidCredentials)
	assert.Nil(t, user)
}

func TestIntegrationOUD_CheckUserCredentials_NotAuthenticated(t *testing.T) {
	conn := newOUDConn(t)
	_, err := conn.CheckUserCredentials(context.Background(), oudUser1UID, oudUser1Pass)
	require.Error(t, err)
	assert.ErrorIs(t, err, ldapper.ErrNotAuthenticated)
}

// ================== GetUser / GetGroup / GetOU ==================

func TestIntegrationOUD_GetUser_ByUID(t *testing.T) {
	conn := newOUDAuthConn(t)
	user, err := conn.GetUser(context.Background(), oudUser1UID, oudBaseDN)
	require.NoError(t, err)
	assert.Equal(t, oudUser1DN, user.DN)
	assert.Equal(t, "user1", user.GetAttributeValue("uid"))
}

func TestIntegrationOUD_GetUser_NotFound(t *testing.T) {
	conn := newOUDAuthConn(t)
	_, err := conn.GetUser(context.Background(), "does-not-exist", oudBaseDN)
	require.Error(t, err)
	assert.ErrorIs(t, err, ldapper.ErrNotFoundOrNotVisible)
}

func TestIntegrationOUD_GetGroup_Success(t *testing.T) {
	conn := newOUDAuthConn(t)
	group, err := conn.GetGroup(context.Background(), "admins", oudBaseDN)
	require.NoError(t, err)
	require.NotNil(t, group)
	assert.Equal(t, "admins", group.GetAttributeValue("cn"))
}

func TestIntegrationOUD_GetOU_Success(t *testing.T) {
	conn := newOUDAuthConn(t)
	ou, err := conn.GetOU(context.Background(), "People", oudBaseDN)
	require.NoError(t, err)
	require.NotNil(t, ou)
	assert.Equal(t, "People", ou.GetAttributeValue("ou"))
}

// ================== GetUserGroups ==================

func TestIntegrationOUD_GetUserGroups_GroupOfNamesBranch(t *testing.T) {
	conn := newOUDAuthConn(t)
	groups, err := conn.GetUserGroups(context.Background(), oudUser1UID, oudBaseDN)
	require.NoError(t, err)
	assert.True(t, containsDN(groups, "cn=admins"),
		"expected an admins group DN in %v", groups)
}

func TestIntegrationOUD_GetUserGroups_PosixGroupBranch(t *testing.T) {
	conn := newOUDAuthConn(t)
	groups, err := conn.GetUserGroups(context.Background(), oudUser2UID, oudBaseDN)
	require.NoError(t, err)
	assert.True(t, containsDN(groups, "cn=readers"),
		"expected a readers group DN in %v", groups)
}

// ================== GetCatalogTree / GetSubOUs / GetOUUsers ==================

func TestIntegrationOUD_GetCatalogTree_Success(t *testing.T) {
	conn := newOUDAuthConn(t)
	tree, err := conn.GetCatalogTree(context.Background(), oudBaseDN, 0)
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

func TestIntegrationOUD_GetSubOUs_SingleLevel(t *testing.T) {
	conn := newOUDAuthConn(t)
	ous, err := conn.GetSubOUs(context.Background(), oudBaseDN, ldap.ScopeSingleLevel)
	require.NoError(t, err)

	var names []string
	for _, ou := range ous {
		names = append(names, ou.Name)
	}
	assert.Contains(t, names, "People")
	assert.Contains(t, names, "Groups")
	assert.Contains(t, names, "empty")
}

func TestIntegrationOUD_GetOUUsers(t *testing.T) {
	conn := newOUDAuthConn(t)
	users, err := conn.GetOUUsers(context.Background(), "ou=People,"+oudBaseDN)
	require.NoError(t, err)
	require.Len(t, users, 2)

	uids := make([]string, 0, len(users))
	for _, u := range users {
		uids = append(uids, u.GetAttributeValue("uid"))
	}
	assert.ElementsMatch(t, []string{oudUser1UID, oudUser2UID}, uids)
}

// ================== Health checks / Reconnect / Close ==================

func TestIntegrationOUD_IsAlive_AfterClose(t *testing.T) {
	conn := newOUDConn(t)
	conn.Close()
	assert.False(t, conn.IsAlive(context.Background()))
}

func TestIntegrationOUD_Reconnect_PreservesAuthentication(t *testing.T) {
	conn := newOUDAuthConn(t)
	require.NoError(t, conn.Reconnect(context.Background()))
	_, err := conn.CheckUserCredentials(context.Background(), oudUser1UID, oudUser1Pass)
	require.NoError(t, err)
}

func TestIntegrationOUD_EnsureAlive_ClosedClient_ReturnsErrClosed(t *testing.T) {
	conn := newOUDAuthConn(t)
	conn.Close()
	require.False(t, conn.IsAlive(context.Background()))

	err := conn.EnsureAlive(context.Background())
	require.Error(t, err)
	assert.ErrorIs(t, err, ldapper.ErrClosed)
}

// OUDAdapter must NOT implement PrimaryGroupResolver — OUD has no
// primaryGroupID concept, and the presence of the interface would make
// GetUserGroups try to resolve a non-existent attribute. Go has no static
// "does not implement" assertion; the init-time check below panics if a
// future edit adds the method.
var _ = func() any {
	if _, ok := any(adapters.OUDAdapter{}).(interfaces.PrimaryGroupResolver); ok {
		panic("OUDAdapter must not implement PrimaryGroupResolver")
	}
	return nil
}()
