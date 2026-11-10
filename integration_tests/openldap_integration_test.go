//go:build integration_openldap
// +build integration_openldap

package ldapper_test

// OpenLDAP integration tests against a real osixia/openldap container.
//
// OPENLDAPAdapter group filter supports both branches:
//   (|(&(objectClass=groupOfNames)(member=%s))
//     (&(objectClass=posixGroup)(memberUid=%s)))
// args = [user.DN, user.uid]. Both branches exercised below.
//
// Run with:
//   go test -tags=integration_openldap ./...

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

// openldapSeedEntries returns the entries the integration tests depend on.
// Seeding is done from Go (not via osixia's bootstrap-LDIF loader) so the
// timing is deterministic on CI runners, where the entrypoint's
// "slapd starting" is logged before custom LDIFs are fully applied.
func openldapSeedEntries() []struct {
	dn    string
	attrs map[string][]string
} {
	return []struct {
		dn    string
		attrs map[string][]string
	}{
		{"ou=users," + openldapBaseDN, map[string][]string{
			"objectClass": {"organizationalUnit"},
			"ou":          {"users"},
		}},
		{"ou=empty," + openldapBaseDN, map[string][]string{
			"objectClass": {"organizationalUnit"},
			"ou":          {"empty"},
		}},
		{"ou=groups," + openldapBaseDN, map[string][]string{
			"objectClass": {"organizationalUnit"},
			"ou":          {"groups"},
		}},
		{openldapUser1DN, map[string][]string{
			"objectClass":   {"inetOrgPerson", "posixAccount"},
			"cn":            {"user1"},
			"sn":            {"User"},
			"uid":           {"user1"},
			"uidNumber":     {"1001"},
			"gidNumber":     {"1001"},
			"homeDirectory": {"/home/user1"},
			"userPassword":  {openldapUser1Pass},
			"mail":          {"user1@example.org"},
			"displayName":   {"User One"},
		}},
		{openldapUser2DN, map[string][]string{
			"objectClass":   {"inetOrgPerson", "posixAccount"},
			"cn":            {"user2"},
			"sn":            {"User"},
			"uid":           {"user2"},
			"uidNumber":     {"1002"},
			"gidNumber":     {"1002"},
			"homeDirectory": {"/home/user2"},
			"userPassword":  {openldapUser2Pass},
			"mail":          {"user2@example.org"},
			"displayName":   {"User Two"},
		}},
		{"cn=dup1,ou=users," + openldapBaseDN, map[string][]string{
			"objectClass":  {"inetOrgPerson"},
			"cn":           {"dup1"},
			"sn":           {"Dup"},
			"uid":          {"duplicate"},
			"userPassword": {"dup1pass"},
		}},
		{"cn=dup2,ou=users," + openldapBaseDN, map[string][]string{
			"objectClass":  {"inetOrgPerson"},
			"cn":           {"dup2"},
			"sn":           {"Dup"},
			"uid":          {"duplicate"},
			"userPassword": {"dup2pass"},
		}},
		{"cn=admins,ou=groups," + openldapBaseDN, map[string][]string{
			"objectClass": {"groupOfNames"},
			"cn":          {"admins"},
			"member":      {openldapUser1DN},
		}},
		{"cn=readers,ou=groups," + openldapBaseDN, map[string][]string{
			"objectClass": {"posixGroup"},
			"cn":          {"readers"},
			"gidNumber":   {"2001"},
			"memberUid":   {"user2"},
		}},
	}
}

// seedOpenLDAPLDIF creates the LDAP entries required by the integration
// tests. Idempotent: entries that already exist are skipped.
func seedOpenLDAPLDIF(host string, port uint) error {
	c, err := ldap.DialURL(fmt.Sprintf("ldap://%s:%d", host, port))
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	defer c.Close()
	if err := c.Bind(openldapAdminDN, openldapAdminPass); err != nil {
		return fmt.Errorf("bind: %w", err)
	}
	for _, e := range openldapSeedEntries() {
		_, err := c.Search(ldap.NewSearchRequest(
			e.dn, ldap.ScopeBaseObject, ldap.NeverDerefAliases,
			1, 0, false, "(objectClass=*)", []string{"1.1"}, nil))
		if err == nil {
			continue // already present
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

var (
	openldapHost string
	openldapPort uint
	openldapAdpt = adapters.OPENLDAPAdapter{}
)

func TestMain(m *testing.M) {
	ctx := context.Background()

	// No LDIF is mounted: the entrypoint's bootstrap loader is unreliable
	// on CI (double-processing, early "slapd starting", etc.). Instead we
	// seed entries from Go after the container is up — see
	// seedOpenLDAPLDIF. This matches the ALDPro suite's approach.
	req := testcontainers.ContainerRequest{
		Image:        "osixia/openldap:1.5.0",
		ExposedPorts: []string{"389/tcp"},
		Env: map[string]string{
			"LDAP_ORGANISATION":   "Example Org",
			"LDAP_DOMAIN":         "example.org",
			"LDAP_ADMIN_PASSWORD": openldapAdminPass,
			"LDAP_TLS":            "false",
		},
		// Wait for the LDAP port, not for the log line. osixia's entrypoint
		// prints "slapd starting" twice — once for the bootstrap-phase slapd
		// (which only listens on ldapi:/// and writes to a temporary mdb) and
		// once for the final serving slapd (which opens :389 against the
		// persistent mdb). wait.ForLog matches the first occurrence, so tests
		// would start while bootstrap is still in progress and any entries
		// seeded at that moment would be discarded with the temp mdb.
		WaitingFor: wait.ForListeningPort("389/tcp").WithStartupTimeout(120 * time.Second),
	}

	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "cannot start OpenLDAP: %v\n", err)
		os.Exit(1)
	}

	openldapHost, err = container.Host(ctx)
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
	openldapPort = uint(mappedPort.Num())

	if !waitForOpenLDAPReady(openldapHost, openldapPort, 60*time.Second) {
		_ = container.Terminate(ctx)
		fmt.Fprintln(os.Stderr, "OpenLDAP did not become ready")
		os.Exit(1)
	}

	if err := seedOpenLDAPLDIF(openldapHost, openldapPort); err != nil {
		_ = container.Terminate(ctx)
		fmt.Fprintf(os.Stderr, "cannot seed LDAP data: %v\n", err)
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
			bindErr := c.Bind(openldapAdminDN, openldapAdminPass)
			_ = c.Close()
			if bindErr == nil {
				return true
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	return false
}

// containsDN reports whether any element of groups contains needle as a
// case-insensitive substring. GetUserGroups returns DNs, and the case of
// attribute types may vary across servers.
func containsDN(groups []string, needle string) bool {
	needle = strings.ToLower(needle)
	for _, g := range groups {
		if strings.Contains(strings.ToLower(g), needle) {
			return true
		}
	}
	return false
}

func newOpenLDAPConn(t *testing.T, opts ...ldapper.Option) *ldapper.LDAPper {
	t.Helper()
	conn, err := ldapper.NewLDAPper(
		context.Background(),
		[]string{openldapHost}, openldapPort,
		false, true, nil,
		openldapAdpt,
		opts...,
	)
	require.NoError(t, err)
	t.Cleanup(conn.Close)
	return conn
}

func newOpenLDAPAuthConn(t *testing.T, opts ...ldapper.Option) *ldapper.LDAPper {
	t.Helper()
	conn, err := ldapper.NewAuthenticatedLDAPper(
		context.Background(),
		openldapUser1DN, openldapUser1Pass, openldapBaseDN,
		[]string{openldapHost}, openldapPort,
		false, true, nil,
		openldapAdpt,
		opts...,
	)
	require.NoError(t, err)
	t.Cleanup(conn.Close)
	return conn
}

// ================== constructor validation ==================

func TestIntegrationOpenLDAP_NewConnection_Success(t *testing.T) {
	conn := newOpenLDAPConn(t)
	assert.True(t, conn.IsAlive(context.Background()))
}

func TestIntegrationOpenLDAP_NewConnection_EmptyHosts(t *testing.T) {
	_, err := ldapper.NewLDAPper(context.Background(),
		nil, 389, false, true, nil, openldapAdpt)
	require.Error(t, err)
	assert.ErrorIs(t, err, ldapper.ErrInvalidArgument)
}

func TestIntegrationOpenLDAP_NewConnection_TooManyHosts(t *testing.T) {
	hosts := make([]string, constants.DefaultMaxHostsLength+1)
	for i := range hosts {
		hosts[i] = fmt.Sprintf("host%d", i)
	}
	_, err := ldapper.NewLDAPper(context.Background(),
		hosts, 389, false, true, nil, openldapAdpt)
	require.Error(t, err)
	assert.ErrorIs(t, err, ldapper.ErrInvalidArgument)
}

func TestIntegrationOpenLDAP_NewConnection_NilTLSConfigWhenRequired(t *testing.T) {
	_, err := ldapper.NewLDAPper(context.Background(),
		[]string{openldapHost}, openldapPort, false, false, nil, openldapAdpt)
	require.Error(t, err)
	assert.ErrorIs(t, err, ldapper.ErrInvalidArgument)
}

func TestIntegrationOpenLDAP_NewConnection_NilCatalogAdapter(t *testing.T) {
	_, err := ldapper.NewLDAPper(context.Background(),
		[]string{openldapHost}, openldapPort, false, true, nil, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, ldapper.ErrInvalidArgument)
}

func TestIntegrationOpenLDAP_NewConnection_UnreachableHost(t *testing.T) {
	_, err := ldapper.NewLDAPper(context.Background(),
		[]string{"127.0.0.1"}, 1, false, true, nil, openldapAdpt)
	require.Error(t, err)
	assert.ErrorIs(t, err, ldapper.ErrUnavailable)
}

func TestIntegrationOpenLDAP_NewAuthenticatedConnection_Success(t *testing.T) {
	conn, err := ldapper.NewAuthenticatedLDAPper(
		context.Background(),
		openldapUser1DN, openldapUser1Pass, openldapBaseDN,
		[]string{openldapHost}, openldapPort, false, true, nil, openldapAdpt,
	)
	require.NoError(t, err)
	defer conn.Close()
}

func TestIntegrationOpenLDAP_NewAuthenticatedConnection_EmptyCredentials(t *testing.T) {
	_, err := ldapper.NewAuthenticatedLDAPper(
		context.Background(), "", "", openldapBaseDN,
		[]string{openldapHost}, openldapPort, false, true, nil, openldapAdpt,
	)
	require.Error(t, err)
	assert.ErrorIs(t, err, ldapper.ErrInvalidArgument)
}

func TestIntegrationOpenLDAP_NewAuthenticatedConnection_WrongPassword(t *testing.T) {
	_, err := ldapper.NewAuthenticatedLDAPper(
		context.Background(),
		openldapUser1DN, "wrong-password", openldapBaseDN,
		[]string{openldapHost}, openldapPort, false, true, nil, openldapAdpt,
	)
	require.Error(t, err)
	assert.ErrorIs(t, err, ldapper.ErrInvalidCredentials)
}

// ================== BindConn ==================

func TestIntegrationOpenLDAP_BindConn_Success(t *testing.T) {
	conn := newOpenLDAPConn(t)

	err := conn.BindConn(context.Background(),
		openldapUser1DN, openldapUser1Pass, openldapBaseDN)
	require.NoError(t, err)
}

func TestIntegrationOpenLDAP_BindConn_EmptyCredentials(t *testing.T) {
	conn := newOpenLDAPConn(t)
	err := conn.BindConn(context.Background(), "", "", openldapBaseDN)
	require.Error(t, err)
	assert.ErrorIs(t, err, ldapper.ErrInvalidArgument)
}

func TestIntegrationOpenLDAP_BindConn_WrongPassword(t *testing.T) {
	conn := newOpenLDAPConn(t)
	err := conn.BindConn(context.Background(),
		openldapUser1DN, "bad-password", openldapBaseDN)
	require.Error(t, err)
	assert.ErrorIs(t, err, ldapper.ErrInvalidCredentials)
}

func TestIntegrationOpenLDAP_BindConn_NonExistentUser(t *testing.T) {
	conn := newOpenLDAPConn(t)
	err := conn.BindConn(context.Background(),
		"cn=ghost,ou=users,dc=example,dc=org", "whatever", openldapBaseDN)
	require.Error(t, err)
}

// ================== CheckUserCredentials ==================

func TestIntegrationOpenLDAP_CheckUserCredentials_Success(t *testing.T) {
	conn := newOpenLDAPAuthConn(t)

	user, err := conn.CheckUserCredentials(context.Background(), openldapUser2UID, openldapUser2Pass)
	require.NoError(t, err)
	require.NotNil(t, user)
	assert.Equal(t, openldapUser2DN, user.DN)
	assert.Equal(t, openldapUser2UID, user.GetAttributeValue("uid"))
}

func TestIntegrationOpenLDAP_CheckUserCredentials_WrongPassword(t *testing.T) {
	conn := newOpenLDAPAuthConn(t)

	user, err := conn.CheckUserCredentials(context.Background(), openldapUser2UID, "bad")
	require.Error(t, err)
	assert.ErrorIs(t, err, ldapper.ErrInvalidCredentials)
	assert.Nil(t, user)
}

func TestIntegrationOpenLDAP_CheckUserCredentials_NonExistentUser(t *testing.T) {
	conn := newOpenLDAPAuthConn(t)
	user, err := conn.CheckUserCredentials(context.Background(), "ghost-user", "whatever")
	require.Error(t, err)
	assert.ErrorIs(t, err, ldapper.ErrInvalidCredentials)
	assert.Nil(t, user)
}

func TestIntegrationOpenLDAP_CheckUserCredentials_NotAuthenticated(t *testing.T) {
	conn := newOpenLDAPConn(t)
	_, err := conn.CheckUserCredentials(context.Background(), openldapUser2UID, openldapUser2Pass)
	require.Error(t, err)
	assert.ErrorIs(t, err, ldapper.ErrNotAuthenticated)
}

func TestIntegrationOpenLDAP_CheckUserCredentials_EmptyCredentials(t *testing.T) {
	conn := newOpenLDAPAuthConn(t)
	_, err := conn.CheckUserCredentials(context.Background(), "", "")
	require.Error(t, err)
	assert.ErrorIs(t, err, ldapper.ErrInvalidArgument)
}

// ================== IsAlive / Reconnect / EnsureAlive / Close ==================

func TestIntegrationOpenLDAP_IsAlive_ActiveConnection(t *testing.T) {
	conn := newOpenLDAPConn(t)
	assert.True(t, conn.IsAlive(context.Background()))
}

func TestIntegrationOpenLDAP_IsAlive_AfterClose(t *testing.T) {
	conn := newOpenLDAPConn(t)
	conn.Close()
	assert.False(t, conn.IsAlive(context.Background()))
}

func TestIntegrationOpenLDAP_Reconnect_Unauthenticated(t *testing.T) {
	conn := newOpenLDAPConn(t)
	require.True(t, conn.IsAlive(context.Background()))
	require.NoError(t, conn.Reconnect(context.Background()))
	assert.True(t, conn.IsAlive(context.Background()))
}

func TestIntegrationOpenLDAP_Reconnect_PreservesAuthentication(t *testing.T) {
	conn := newOpenLDAPAuthConn(t)
	require.NoError(t, conn.Reconnect(context.Background()))

	_, err := conn.CheckUserCredentials(context.Background(), openldapUser2UID, openldapUser2Pass)
	require.NoError(t, err)
}

func TestIntegrationOpenLDAP_EnsureAlive_NoopWhenAlive(t *testing.T) {
	conn := newOpenLDAPConn(t)
	require.NoError(t, conn.EnsureAlive(context.Background()))
	assert.True(t, conn.IsAlive(context.Background()))
}

// After Close the client is terminal: EnsureAlive reports ErrClosed instead
// of silently reconnecting. That is the documented contract — a closed
// client cannot be revived by EnsureAlive (see ldapper_connection.go).
func TestIntegrationOpenLDAP_EnsureAlive_ClosedClient_ReturnsErrClosed(t *testing.T) {
	conn := newOpenLDAPAuthConn(t)
	conn.Close()
	require.False(t, conn.IsAlive(context.Background()))

	err := conn.EnsureAlive(context.Background())
	require.Error(t, err)
	assert.ErrorIs(t, err, ldapper.ErrClosed)
}

func TestIntegrationOpenLDAP_Close_Idempotent(t *testing.T) {
	conn := newOpenLDAPConn(t)
	conn.Close()
	conn.Close() // must not panic

	_, err := conn.GetUser(context.Background(), openldapUser1UID, openldapBaseDN)
	require.Error(t, err)
	assert.ErrorIs(t, err, ldapper.ErrClosed)
}

// ================== CustomSearch ==================

func TestIntegrationOpenLDAP_CustomSearch_Success(t *testing.T) {
	conn := newOpenLDAPAuthConn(t)

	req := ldap.NewSearchRequest(
		openldapBaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		0, 0, false, "(uid=user1)", []string{"cn", "mail"}, nil,
	)

	res, err := conn.CustomSearch(context.Background(), req)
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
	_, err := conn.CustomSearch(context.Background(), req)
	require.Error(t, err)
	assert.ErrorIs(t, err, ldapper.ErrClosed)
}

// ================== GetUser ==================

func TestIntegrationOpenLDAP_GetUser_ByUID(t *testing.T) {
	conn := newOpenLDAPAuthConn(t)

	user, err := conn.GetUser(context.Background(), openldapUser1UID, openldapBaseDN)
	require.NoError(t, err)
	assert.Equal(t, openldapUser1DN, user.DN)
	assert.Equal(t, "user1", user.GetAttributeValue("uid"))
	assert.Equal(t, "User One", user.GetAttributeValue("displayName"))
}

func TestIntegrationOpenLDAP_GetUser_ByDN(t *testing.T) {
	conn := newOpenLDAPAuthConn(t)

	user, err := conn.GetUser(context.Background(), openldapUser1DN, openldapBaseDN)
	require.NoError(t, err)
	assert.Equal(t, openldapUser1DN, user.DN)
}

func TestIntegrationOpenLDAP_GetUser_NotFound(t *testing.T) {
	conn := newOpenLDAPAuthConn(t)
	_, err := conn.GetUser(context.Background(), "does-not-exist", openldapBaseDN)
	require.Error(t, err)
	// searchSingleEntryLocked returns ErrNotFoundOrNotVisible on 0 entries;
	// ErrNotFound would only appear on a definitive LDAPResultNoSuchObject,
	// which a subtree search with a valid base does not produce.
	assert.ErrorIs(t, err, ldapper.ErrNotFoundOrNotVisible)
}

func TestIntegrationOpenLDAP_GetUser_TooManyEntries(t *testing.T) {
	conn := newOpenLDAPAuthConn(t)
	_, err := conn.GetUser(context.Background(), "duplicate", openldapBaseDN)
	require.Error(t, err)
	assert.ErrorIs(t, err, ldapper.ErrAmbiguousResult)
}

func TestIntegrationOpenLDAP_GetUser_NotInitialized(t *testing.T) {
	conn := newOpenLDAPConn(t)
	conn.Close()

	_, err := conn.GetUser(context.Background(), openldapUser1UID, openldapBaseDN)
	require.Error(t, err)
	assert.ErrorIs(t, err, ldapper.ErrClosed)
}

// ================== GetGroup / GetOU ==================

func TestIntegrationOpenLDAP_GetGroup_Success(t *testing.T) {
	conn := newOpenLDAPAuthConn(t)

	group, err := conn.GetGroup(context.Background(), "admins", openldapBaseDN)
	require.NoError(t, err)
	require.NotNil(t, group)
	assert.Equal(t, "admins", group.GetAttributeValue("cn"))
}

func TestIntegrationOpenLDAP_GetGroup_NotFound(t *testing.T) {
	conn := newOpenLDAPAuthConn(t)
	_, err := conn.GetGroup(context.Background(), "does-not-exist", openldapBaseDN)
	require.Error(t, err)
	assert.ErrorIs(t, err, ldapper.ErrNotFoundOrNotVisible)
}

func TestIntegrationOpenLDAP_GetOU_Success(t *testing.T) {
	conn := newOpenLDAPAuthConn(t)

	ou, err := conn.GetOU(context.Background(), "users", openldapBaseDN)
	require.NoError(t, err)
	require.NotNil(t, ou)
	assert.Equal(t, "users", ou.GetAttributeValue("ou"))
}

func TestIntegrationOpenLDAP_GetOU_NotFound(t *testing.T) {
	conn := newOpenLDAPAuthConn(t)
	_, err := conn.GetOU(context.Background(), "does-not-exist", openldapBaseDN)
	require.Error(t, err)
	assert.ErrorIs(t, err, ldapper.ErrNotFoundOrNotVisible)
}

// ================== GetCatalogTree / GetSubOUs / ListSingleLevelOUs ==================

func TestIntegrationOpenLDAP_GetCatalogTree_Success(t *testing.T) {
	conn := newOpenLDAPAuthConn(t)

	tree, err := conn.GetCatalogTree(context.Background(), openldapBaseDN, 0)
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
	assert.Contains(t, names, "groups")
	assert.Contains(t, names, "empty")
}

func TestIntegrationOpenLDAP_GetCatalogTree_MaxDepth(t *testing.T) {
	conn := newOpenLDAPAuthConn(t)

	tree, err := conn.GetCatalogTree(context.Background(), openldapBaseDN, 1)
	require.NoError(t, err)
	for _, root := range tree.Tree {
		assert.Empty(t, root.Children, "maxDepth=1 must trim children")
	}
}

func TestIntegrationOpenLDAP_GetSubOUs_SingleLevel(t *testing.T) {
	conn := newOpenLDAPAuthConn(t)

	ous, err := conn.GetSubOUs(context.Background(), openldapBaseDN, ldap.ScopeSingleLevel)
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

	ous, err := conn.ListSingleLevelOUs(context.Background(), openldapBaseDN)
	require.NoError(t, err)
	assert.NotEmpty(t, ous)
}

// ================== GetUserGroups ==================

// GetUserGroups returns DNs, not cn values — assertions use containsDN.
func TestIntegrationOpenLDAP_GetUserGroups_GroupOfNamesBranch(t *testing.T) {
	conn := newOpenLDAPAuthConn(t)

	groups, err := conn.GetUserGroups(context.Background(), openldapUser1UID, openldapBaseDN)
	require.NoError(t, err)
	assert.True(t, containsDN(groups, "cn=admins"),
		"expected an admins group DN in %v", groups)
}

func TestIntegrationOpenLDAP_GetUserGroups_PosixGroupBranch(t *testing.T) {
	conn := newOpenLDAPAuthConn(t)

	groups, err := conn.GetUserGroups(context.Background(), openldapUser2UID, openldapBaseDN)
	require.NoError(t, err)
	assert.True(t, containsDN(groups, "cn=readers"),
		"expected a readers group DN in %v", groups)
}

func TestIntegrationOpenLDAP_GetUserGroups_AmbiguousUser(t *testing.T) {
	conn := newOpenLDAPAuthConn(t)

	// "duplicate" resolves to two entries. GetUserGroups first calls
	// GetUser, which fails with ErrAmbiguousResult before any group search.
	_, err := conn.GetUserGroups(context.Background(), "duplicate", openldapBaseDN)
	require.Error(t, err)
	assert.ErrorIs(t, err, ldapper.ErrAmbiguousResult)
}

func TestIntegrationOpenLDAP_GetUserGroups_UserNotFound(t *testing.T) {
	conn := newOpenLDAPAuthConn(t)

	_, err := conn.GetUserGroups(context.Background(), "nobody", openldapBaseDN)
	require.Error(t, err)
	assert.ErrorIs(t, err, ldapper.ErrNotFoundOrNotVisible)
}

// ================== GetOUUsers ==================

func TestIntegrationOpenLDAP_GetOUUsers_Success(t *testing.T) {
	conn := newOpenLDAPAuthConn(t)

	users, err := conn.GetOUUsers(context.Background(), "ou=users,"+openldapBaseDN)
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

	users, err := conn.GetOUUsers(context.Background(), "ou=empty,"+openldapBaseDN)
	require.NoError(t, err)
	assert.Empty(t, users)
}

func TestIntegrationOpenLDAP_GetOUUsers_NotInitialized(t *testing.T) {
	conn := newOpenLDAPConn(t)
	conn.Close()

	_, err := conn.GetOUUsers(context.Background(), "ou=users,"+openldapBaseDN)
	require.Error(t, err)
	assert.ErrorIs(t, err, ldapper.ErrClosed)
}

// ================== SearchLimits / DialTimeout / OperationTimeouts ==================

func TestIntegrationOpenLDAP_SearchLimits_Defaults(t *testing.T) {
	conn := newOpenLDAPConn(t)
	limits := conn.GetSearchLimits()
	assert.Equal(t, 0, limits.SizeLimit)
	assert.Equal(t, 30, limits.TimeLimit)
	assert.True(t, limits.RequirePaging,
		"DefaultSearchLimits enables RequirePaging")
}

func TestIntegrationOpenLDAP_SearchLimits_WithOption(t *testing.T) {
	limits := ldapper.DefaultSearchLimits()
	limits.SizeLimit = 5
	limits.TimeLimit = 10

	conn := newOpenLDAPConn(t, ldapper.WithSearchLimits(limits))

	got := conn.GetSearchLimits()
	assert.Equal(t, 5, got.SizeLimit)
	assert.Equal(t, 10, got.TimeLimit)
	assert.True(t, got.RequirePaging,
		"WithSearchLimits replaces the whole struct; explicit true survives")
}

func TestIntegrationOpenLDAP_SearchLimits_SetAtRuntime(t *testing.T) {
	conn := newOpenLDAPConn(t)

	limits := conn.GetSearchLimits()
	limits.SizeLimit = 7
	limits.TimeLimit = 11
	conn.SetSearchLimits(limits)

	got := conn.GetSearchLimits()
	assert.Equal(t, 7, got.SizeLimit)
	assert.Equal(t, 11, got.TimeLimit)
}

func TestIntegrationOpenLDAP_SearchLimits_NegativeClampedToZero(t *testing.T) {
	conn := newOpenLDAPConn(t)
	conn.SetSearchLimits(ldapper.SearchLimits{SizeLimit: -1, TimeLimit: -5})
	got := conn.GetSearchLimits()
	assert.Equal(t, 0, got.SizeLimit)
	assert.Equal(t, 0, got.TimeLimit)
}

func TestIntegrationOpenLDAP_DialTimeout_Defaults(t *testing.T) {
	conn := newOpenLDAPConn(t)
	// NewLDAPper initialises dialTimeout to constants.DefaultDialTimeout.
	assert.Equal(t, constants.DefaultDialTimeout, conn.GetDialTimeout())
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

func TestIntegrationOpenLDAP_OperationTimeout_WithOption(t *testing.T) {
	conn := newOpenLDAPAuthConn(t, ldapper.WithOperationTimeout(ldapper.OperationTimeouts{
		Bind:   5 * time.Second,
		Search: 5 * time.Second,
	}))

	got := conn.GetOperationTimeout()
	assert.Equal(t, 5*time.Second, got.Bind)
	assert.Equal(t, 5*time.Second, got.Search)

	// Normal operations must still succeed under a healthy timeout.
	_, err := conn.GetUser(context.Background(), openldapUser1UID, openldapBaseDN)
	require.NoError(t, err)
}

// ================== Failure paths ==================

// A failed Bind must invalidate cached auth state (RFC 4513 §4: the session
// transitions to anonymous). Subsequent operations must not silently run
// under the previously-bound principal.
func TestIntegrationOpenLDAP_BindConn_FailedBind_InvalidatesState(t *testing.T) {
	conn := newOpenLDAPConn(t)

	err := conn.BindConn(context.Background(),
		openldapUser1DN, openldapUser1Pass, openldapBaseDN)
	require.NoError(t, err)

	err = conn.BindConn(context.Background(),
		openldapUser1DN, "wrong-password", openldapBaseDN)
	require.Error(t, err)
	assert.ErrorIs(t, err, ldapper.ErrInvalidCredentials)

	_, err = conn.CheckUserCredentials(context.Background(), openldapUser2UID, openldapUser2Pass)
	require.Error(t, err)
	assert.ErrorIs(t, err, ldapper.ErrClosed,
		"post-failed-bind connection is nil; requireConnLocked fires before the auth check")
}

// Breaks user1's password via direct LDAP Modify, then verifies that
// Reconnect — which uses the stale cached password — fails and leaves the
// client unusable (ErrClosed) instead of falling back to anonymous.
func TestIntegrationOpenLDAP_Reconnect_RebindFailure_ClosesConnection(t *testing.T) {
	conn := newOpenLDAPConn(t)
	err := conn.BindConn(context.Background(),
		openldapUser1DN, openldapUser1Pass, openldapBaseDN)
	require.NoError(t, err)

	rawConn, err := ldap.DialURL(fmt.Sprintf("ldap://%s:%d", openldapHost, openldapPort))
	require.NoError(t, err)
	defer rawConn.Close()
	require.NoError(t, rawConn.Bind(openldapAdminDN, openldapAdminPass))

	modify := ldap.NewModifyRequest(openldapUser1DN, nil)
	modify.Replace("userPassword", []string{"new-password-during-test"})
	require.NoError(t, rawConn.Modify(modify))

	t.Cleanup(func() {
		restore := ldap.NewModifyRequest(openldapUser1DN, nil)
		restore.Replace("userPassword", []string{openldapUser1Pass})
		_ = rawConn.Modify(restore)
	})

	err = conn.Reconnect(context.Background())
	require.Error(t, err)
	assert.ErrorIs(t, err, ldapper.ErrInvalidCredentials)

	_, err = conn.GetUser(context.Background(), openldapUser2UID, openldapBaseDN)
	require.Error(t, err)
	assert.ErrorIs(t, err, ldapper.ErrClosed,
		"connection must not be usable after a failed rebind")

	_, err = conn.CheckUserCredentials(context.Background(), openldapUser2UID, openldapUser2Pass)
	require.Error(t, err)
	assert.ErrorIs(t, err, ldapper.ErrClosed,
		"connection is nil after failed rebind; requireConnLocked wins over requireAuthLocked")
}

// Compile-time guard: the file relies on OPENLDAPAdapter implementing
// CatalogAdapter (and not PrimaryGroupResolver — that distinction is
// what makes GetUserGroups return only membership-based groups).
var _ = func() any {
	var c any = adapters.OPENLDAPAdapter{}
	if _, ok := c.(interface {
		ResolvePrimaryGroupDN(context.Context, types.LDAPUser, any) (string, error)
	}); ok {
		panic("OPENLDAPAdapter must not implement PrimaryGroupResolver")
	}
	return nil
}()
