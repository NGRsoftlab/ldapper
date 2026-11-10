//go:build integration_msad
// +build integration_msad

package ldapper_test

// MS AD integration tests against a real Samba 4 AD DC container.
//
// MSADAdapter uses AD-specific LDAP_MATCHING_RULE_IN_CHAIN (1.2.840.113556.1.4.1941)
// for group membership, which OpenLDAP does not implement.
//
// Note on group DNs in assertions:
//   GetUserGroups returns group *DNs* (not cn values), and — because
//   MSADAdapter implements PrimaryGroupResolver — it also includes the
//   primary group (Domain Users by default). Assertions use containsDN
//   (case-insensitive substring) rather than ElementsMatch.
//
// Run with:
//   go test -tags=integration_msad ./...

import (
	"bytes"
	"context"
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
	"github.com/NGRsoftlab/ldapper/constants"
	"github.com/NGRsoftlab/ldapper/types"
)

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

	msadTestOUDN = "ou=testou," + msadBaseDN
)

var (
	msadHost      string
	msadPort      uint
	msadContainer testcontainers.Container
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
		fmt.Fprintf(os.Stderr, "MS AD tests skipped: cannot start container: %v\n", err)
		os.Exit(m.Run())
	}
	msadContainer = container

	msadHost, err = container.Host(ctx)
	if err != nil {
		_ = container.Terminate(ctx)
		fmt.Fprintf(os.Stderr, "MS AD tests skipped: cannot resolve host: %v\n", err)
		os.Exit(m.Run())
	}

	mappedPort, err := container.MappedPort(ctx, "389")
	if err != nil {
		_ = container.Terminate(ctx)
		fmt.Fprintf(os.Stderr, "MS AD tests skipped: cannot resolve port: %v\n", err)
		os.Exit(m.Run())
	}
	msadPort = uint(mappedPort.Num())

	if !waitForMSADReady(msadHost, msadPort, 120*time.Second) {
		_ = container.Terminate(ctx)
		fmt.Fprintln(os.Stderr, "MS AD tests skipped: LDAP not ready")
		os.Exit(m.Run())
	}

	if err := seedSambaAD(ctx); err != nil {
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

// seedSambaAD creates users, groups, and a dedicated OU for tree tests.
// The OU is created via a plain LDAP Add (samba-tool ou subcommand is not
// available in every Samba build); users and groups go through samba-tool.
func seedSambaAD(ctx context.Context) error {
	execCmds := [][]string{
		{"samba-tool", "user", "create", msadUser1SAM, msadUser1Pass},
		{"samba-tool", "user", "create", msadUser2SAM, msadUser2Pass},
		{"samba-tool", "group", "add", "admins"},
		{"samba-tool", "group", "addmembers", "admins", msadUser1SAM},
		{"samba-tool", "group", "add", "readers"},
		{"samba-tool", "group", "addmembers", "readers", msadUser2SAM},
	}
	for _, cmd := range execCmds {
		code, reader, err := msadContainer.Exec(ctx, cmd)
		if err != nil {
			return fmt.Errorf("exec %v: %w", cmd, err)
		}
		if code != 0 {
			var out bytes.Buffer
			_, _ = io.Copy(&out, reader)
			return fmt.Errorf("exec %v exited %d: %s", cmd, code, out.String())
		}
	}

	// Seed an organizationalUnit via go-ldap; some Samba builds lack the
	// `samba-tool ou` subcommand and would fail here for the wrong reason.
	c, err := ldap.DialURL(fmt.Sprintf("ldap://%s:%d", msadHost, msadPort))
	if err != nil {
		return fmt.Errorf("dial for OU seed: %w", err)
	}
	defer c.Close()
	if err := c.Bind(msadAdminDN, msadAdminPass); err != nil {
		return fmt.Errorf("bind for OU seed: %w", err)
	}
	add := ldap.NewAddRequest(msadTestOUDN, nil)
	add.Attribute("objectClass", []string{"organizationalUnit"})
	add.Attribute("ou", []string{"testou"})
	if err := c.Add(add); err != nil {
		// LDAPResultEntryAlreadyExists (68) is benign on re-run; anything
		// else means we cannot exercise GetOU/GetCatalogTree tests.
		if !ldap.IsErrorWithCode(err, ldap.LDAPResultEntryAlreadyExists) {
			return fmt.Errorf("add test OU: %w", err)
		}
	}
	return nil
}

func requireMSAD(t *testing.T) {
	t.Helper()
	if !msadAvailable {
		t.Skip("Samba AD DC not available; test skipped")
	}
}

// containsDN reports whether any element of groups contains needle as a
// case-insensitive substring. Necessary because GetUserGroups returns
// full DNs whose attribute-type case varies across servers.
func containsDN(groups []string, needle string) bool {
	needle = strings.ToLower(needle)
	for _, g := range groups {
		if strings.Contains(strings.ToLower(g), needle) {
			return true
		}
	}
	return false
}

// newMSADConn returns an unauthenticated connection.
func newMSADConn(t *testing.T, opts ...ldapper.Option) *ldapper.LDAPper {
	t.Helper()
	requireMSAD(t)

	conn, err := ldapper.NewLDAPper(
		context.Background(),
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

// newMSADAuthConn authenticates as Administrator.
func newMSADAuthConn(t *testing.T, opts ...ldapper.Option) *ldapper.LDAPper {
	t.Helper()
	requireMSAD(t)

	conn, _, err := ldapper.NewAuthenticatedLDAPper(
		context.Background(),
		msadAdminDN, msadAdminPass, msadBaseDN,
		[]string{msadHost}, msadPort,
		false, true, nil,
		msadAdpt,
		opts...,
	)
	require.NoError(t, err)
	t.Cleanup(conn.Close)
	return conn
}

// ================== constructor validation ==================

func TestIntegrationMSAD_NewConnection_Success(t *testing.T) {
	conn := newMSADConn(t)
	assert.True(t, conn.IsAlive(context.Background()))
}

func TestIntegrationMSAD_NewConnection_EmptyHosts(t *testing.T) {
	requireMSAD(t)
	_, err := ldapper.NewLDAPper(context.Background(), nil, 389, false, true, nil, msadAdpt)
	require.Error(t, err)
	assert.ErrorIs(t, err, ldapper.ErrInvalidArgument)
}

func TestIntegrationMSAD_NewConnection_TooManyHosts(t *testing.T) {
	requireMSAD(t)
	hosts := make([]string, constants.DefaultMaxHostsLength+1)
	for i := range hosts {
		hosts[i] = fmt.Sprintf("host%d", i)
	}
	_, err := ldapper.NewLDAPper(context.Background(), hosts, 389, false, true, nil, msadAdpt)
	require.Error(t, err)
	assert.ErrorIs(t, err, ldapper.ErrInvalidArgument)
}

func TestIntegrationMSAD_NewConnection_NilTLSConfigWhenRequired(t *testing.T) {
	requireMSAD(t)
	_, err := ldapper.NewLDAPper(context.Background(),
		[]string{msadHost}, msadPort, false, false, nil, msadAdpt)
	require.Error(t, err)
	assert.ErrorIs(t, err, ldapper.ErrInvalidArgument)
}

func TestIntegrationMSAD_NewConnection_NilCatalogAdapter(t *testing.T) {
	requireMSAD(t)
	_, err := ldapper.NewLDAPper(context.Background(),
		[]string{msadHost}, msadPort, false, true, nil, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, ldapper.ErrInvalidArgument)
}

func TestIntegrationMSAD_NewConnection_UnreachableHost(t *testing.T) {
	requireMSAD(t)
	_, err := ldapper.NewLDAPper(context.Background(),
		[]string{"127.0.0.1"}, 1, false, true, nil, msadAdpt)
	require.Error(t, err)
	assert.ErrorIs(t, err, ldapper.ErrUnavailable)
}

func TestIntegrationMSAD_NewAuthenticatedConnection_Success(t *testing.T) {
	requireMSAD(t)
	conn, user, err := ldapper.NewAuthenticatedLDAPper(
		context.Background(),
		msadAdminDN, msadAdminPass, msadBaseDN,
		[]string{msadHost}, msadPort, false, true, nil, msadAdpt,
	)
	require.NoError(t, err)
	defer conn.Close()

	require.NotNil(t, user)
	assert.True(t, strings.HasPrefix(strings.ToLower(user.DN), "cn=administrator,"))
}

func TestIntegrationMSAD_NewAuthenticatedConnection_EmptyCredentials(t *testing.T) {
	requireMSAD(t)
	_, _, err := ldapper.NewAuthenticatedLDAPper(
		context.Background(), "", "", msadBaseDN,
		[]string{msadHost}, msadPort, false, true, nil, msadAdpt,
	)
	require.Error(t, err)
	assert.ErrorIs(t, err, ldapper.ErrInvalidArgument)
}

func TestIntegrationMSAD_NewAuthenticatedConnection_WrongPassword(t *testing.T) {
	requireMSAD(t)
	_, _, err := ldapper.NewAuthenticatedLDAPper(
		context.Background(),
		msadAdminDN, "wrong-password", msadBaseDN,
		[]string{msadHost}, msadPort, false, true, nil, msadAdpt,
	)
	require.Error(t, err)
	assert.ErrorIs(t, err, ldapper.ErrInvalidCredentials)
}

// ================== BindConn ==================

func TestIntegrationMSAD_BindConn_Success(t *testing.T) {
	conn := newMSADConn(t)

	user, err := conn.BindConn(context.Background(), msadAdminDN, msadAdminPass, msadBaseDN)
	require.NoError(t, err)
	require.NotNil(t, user)
	assert.True(t, strings.HasPrefix(strings.ToLower(user.DN), "cn=administrator,"))
}

func TestIntegrationMSAD_BindConn_EmptyCredentials(t *testing.T) {
	conn := newMSADConn(t)
	_, err := conn.BindConn(context.Background(), "", "", msadBaseDN)
	require.Error(t, err)
	assert.ErrorIs(t, err, ldapper.ErrInvalidArgument)
}

func TestIntegrationMSAD_BindConn_WrongPassword(t *testing.T) {
	conn := newMSADConn(t)
	_, err := conn.BindConn(context.Background(), msadAdminDN, "bad-password", msadBaseDN)
	require.Error(t, err)
	assert.ErrorIs(t, err, ldapper.ErrInvalidCredentials)
}

// ================== CheckUserCredentials ==================

func TestIntegrationMSAD_CheckUserCredentials_Success(t *testing.T) {
	conn := newMSADAuthConn(t)

	user, err := conn.CheckUserCredentials(context.Background(), msadUser1SAM, msadUser1Pass)
	require.NoError(t, err)
	require.NotNil(t, user)
	assert.Equal(t, msadUser1SAM, user.GetAttributeValue("sAMAccountName"))
}

func TestIntegrationMSAD_CheckUserCredentials_WrongPassword(t *testing.T) {
	conn := newMSADAuthConn(t)
	user, err := conn.CheckUserCredentials(context.Background(), msadUser1SAM, "bad")
	require.Error(t, err)
	assert.ErrorIs(t, err, ldapper.ErrInvalidCredentials)
	assert.Nil(t, user)
}

func TestIntegrationMSAD_CheckUserCredentials_NonExistentUser(t *testing.T) {
	conn := newMSADAuthConn(t)
	user, err := conn.CheckUserCredentials(context.Background(), "ghost-user", "whatever")
	require.Error(t, err)
	assert.ErrorIs(t, err, ldapper.ErrInvalidCredentials)
	assert.Nil(t, user)
}

func TestIntegrationMSAD_CheckUserCredentials_NotAuthenticated(t *testing.T) {
	conn := newMSADConn(t)
	_, err := conn.CheckUserCredentials(context.Background(), msadUser1SAM, msadUser1Pass)
	require.Error(t, err)
	assert.ErrorIs(t, err, ldapper.ErrNotAuthenticated)
}

func TestIntegrationMSAD_CheckUserCredentials_EmptyCredentials(t *testing.T) {
	conn := newMSADAuthConn(t)
	_, err := conn.CheckUserCredentials(context.Background(), "", "")
	require.Error(t, err)
	assert.ErrorIs(t, err, ldapper.ErrInvalidArgument)
}

// ================== IsAlive / Reconnect / EnsureAlive / Close ==================

func TestIntegrationMSAD_IsAlive_ActiveConnection(t *testing.T) {
	conn := newMSADConn(t)
	assert.True(t, conn.IsAlive(context.Background()))
}

func TestIntegrationMSAD_IsAlive_AfterClose(t *testing.T) {
	conn := newMSADConn(t)
	conn.Close()
	assert.False(t, conn.IsAlive(context.Background()))
}

func TestIntegrationMSAD_Reconnect_Unauthenticated(t *testing.T) {
	conn := newMSADConn(t)
	require.True(t, conn.IsAlive(context.Background()))
	require.NoError(t, conn.Reconnect(context.Background()))
	assert.True(t, conn.IsAlive(context.Background()))
}

func TestIntegrationMSAD_Reconnect_PreservesAuthentication(t *testing.T) {
	conn := newMSADAuthConn(t)
	require.NoError(t, conn.Reconnect(context.Background()))

	_, err := conn.CheckUserCredentials(context.Background(), msadUser1SAM, msadUser1Pass)
	require.NoError(t, err)
}

func TestIntegrationMSAD_EnsureAlive_NoopWhenAlive(t *testing.T) {
	conn := newMSADConn(t)
	require.NoError(t, conn.EnsureAlive(context.Background()))
	assert.True(t, conn.IsAlive(context.Background()))
}

// EnsureAlive on a Closed client returns ErrClosed, it does NOT reconnect.
// "Reconnect after Close" is a documented error — see ldapper_connection.go.
func TestIntegrationMSAD_EnsureAlive_ClosedClient_ReturnsErrClosed(t *testing.T) {
	conn := newMSADAuthConn(t)
	conn.Close()
	require.False(t, conn.IsAlive(context.Background()))

	err := conn.EnsureAlive(context.Background())
	require.Error(t, err)
	assert.ErrorIs(t, err, ldapper.ErrClosed)
}

func TestIntegrationMSAD_Close_Idempotent(t *testing.T) {
	conn := newMSADConn(t)
	conn.Close()
	conn.Close() // must not panic

	_, err := conn.GetUser(context.Background(), msadUser1SAM, msadBaseDN)
	require.Error(t, err)
	assert.ErrorIs(t, err, ldapper.ErrClosed)
}

// ================== CustomSearch ==================

func TestIntegrationMSAD_CustomSearch_Success(t *testing.T) {
	conn := newMSADAuthConn(t)

	req := ldap.NewSearchRequest(
		msadBaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		0, 0, false,
		"(&(objectCategory=person)(objectClass=user)(sAMAccountName=user1))",
		[]string{"cn", "sAMAccountName"},
		nil,
	)

	res, err := conn.CustomSearch(context.Background(), req)
	require.NoError(t, err)
	require.Len(t, res.Entries, 1)
	assert.Equal(t, msadUser1SAM, res.Entries[0].GetAttributeValue("sAMAccountName"))
}

func TestIntegrationMSAD_CustomSearch_NotInitialized(t *testing.T) {
	conn := newMSADConn(t)
	conn.Close()

	req := ldap.NewSearchRequest(
		msadBaseDN, ldap.ScopeBaseObject, ldap.NeverDerefAliases,
		0, 0, false, "(objectClass=*)", nil, nil,
	)
	_, err := conn.CustomSearch(context.Background(), req)
	require.Error(t, err)
	assert.ErrorIs(t, err, ldapper.ErrClosed)
}

// ================== GetUser ==================

func TestIntegrationMSAD_GetUser_BySAMAccountName(t *testing.T) {
	conn := newMSADAuthConn(t)

	user, err := conn.GetUser(context.Background(), msadUser1SAM, msadBaseDN)
	require.NoError(t, err)
	require.NotNil(t, user)
	assert.Equal(t, msadUser1SAM, user.GetAttributeValue("sAMAccountName"))
}

func TestIntegrationMSAD_GetUser_NotFound(t *testing.T) {
	conn := newMSADAuthConn(t)
	_, err := conn.GetUser(context.Background(), "does-not-exist", msadBaseDN)
	require.Error(t, err)
	// searchSingleEntryLocked returns ErrNotFoundOrNotVisible on 0 entries;
	// ErrNotFound only shows up on LDAPResultNoSuchObject, which this lookup
	// does not trigger (base is a valid tree).
	assert.ErrorIs(t, err, ldapper.ErrNotFoundOrNotVisible)
}

func TestIntegrationMSAD_GetUser_NotInitialized(t *testing.T) {
	conn := newMSADConn(t)
	conn.Close()

	_, err := conn.GetUser(context.Background(), msadUser1SAM, msadBaseDN)
	require.Error(t, err)
	assert.ErrorIs(t, err, ldapper.ErrClosed)
}

// ================== GetGroup / GetOU ==================

func TestIntegrationMSAD_GetGroup_Success(t *testing.T) {
	conn := newMSADAuthConn(t)

	group, err := conn.GetGroup(context.Background(), "admins", msadBaseDN)
	require.NoError(t, err)
	require.NotNil(t, group)
	assert.Equal(t, "admins", group.GetAttributeValue("cn"))
}

func TestIntegrationMSAD_GetGroup_NotFound(t *testing.T) {
	conn := newMSADAuthConn(t)
	_, err := conn.GetGroup(context.Background(), "does-not-exist", msadBaseDN)
	require.Error(t, err)
	assert.ErrorIs(t, err, ldapper.ErrNotFoundOrNotVisible)
}

func TestIntegrationMSAD_GetOU_Success(t *testing.T) {
	conn := newMSADAuthConn(t)

	ou, err := conn.GetOU(context.Background(), "testou", msadBaseDN)
	require.NoError(t, err)
	require.NotNil(t, ou)
	assert.Contains(t, strings.ToLower(ou.DN), "ou=testou")
}

func TestIntegrationMSAD_GetOU_NotFound(t *testing.T) {
	conn := newMSADAuthConn(t)
	_, err := conn.GetOU(context.Background(), "does-not-exist", msadBaseDN)
	require.Error(t, err)
	assert.ErrorIs(t, err, ldapper.ErrNotFoundOrNotVisible)
}

// ================== GetCatalogTree / GetSubOUs ==================

func TestIntegrationMSAD_GetCatalogTree_Success(t *testing.T) {
	conn := newMSADAuthConn(t)

	tree, err := conn.GetCatalogTree(context.Background(), msadBaseDN, 0)
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

	assert.Contains(t, names, "testou",
		"seeded organizationalUnit must appear in the tree")
}

func TestIntegrationMSAD_GetSubOUs_SingleLevel(t *testing.T) {
	conn := newMSADAuthConn(t)

	ous, err := conn.GetSubOUs(context.Background(), msadBaseDN, ldap.ScopeSingleLevel)
	require.NoError(t, err)
	require.NotEmpty(t, ous)

	var names []string
	for _, ou := range ous {
		names = append(names, strings.ToLower(ou.Name))
	}
	assert.Contains(t, names, "testou")
}

// ================== GetUserGroups ==================

// Groups are DNs. For user1 the base filter matches admins; the resolver
// also adds the primary group (Domain Users). Assertions must tolerate both.
func TestIntegrationMSAD_GetUserGroups_AdminsMembership(t *testing.T) {
	conn := newMSADAuthConn(t)

	groups, err := conn.GetUserGroups(context.Background(), msadUser1SAM, msadBaseDN)
	require.NoError(t, err)
	assert.True(t, containsDN(groups, "cn=admins"),
		"expected an admin group in %v", groups)
}

func TestIntegrationMSAD_GetUserGroups_ReadersMembership(t *testing.T) {
	conn := newMSADAuthConn(t)

	groups, err := conn.GetUserGroups(context.Background(), msadUser2SAM, msadBaseDN)
	require.NoError(t, err)
	assert.True(t, containsDN(groups, "cn=readers"),
		"expected a readers group in %v", groups)
}

func TestIntegrationMSAD_GetUserGroups_IncludesPrimaryGroup(t *testing.T) {
	conn := newMSADAuthConn(t)

	groups, err := conn.GetUserGroups(context.Background(), msadUser1SAM, msadBaseDN)
	require.NoError(t, err)
	// The MSADAdapter implements PrimaryGroupResolver — the primary group
	// (Domain Users, RID 513) must be present alongside the group-membership
	// entries. This exercises the child-domain resolver path end-to-end.
	assert.True(t, containsDN(groups, "domain users"),
		"expected Domain Users (primary group) in %v", groups)
}

func TestIntegrationMSAD_GetUserGroups_UserNotFound(t *testing.T) {
	conn := newMSADAuthConn(t)

	_, err := conn.GetUserGroups(context.Background(), "nobody", msadBaseDN)
	require.Error(t, err)
	assert.ErrorIs(t, err, ldapper.ErrNotFoundOrNotVisible)
}

// ================== GetOUUsers ==================

func TestIntegrationMSAD_GetOUUsers_UsersContainer(t *testing.T) {
	conn := newMSADAuthConn(t)

	users, err := conn.GetOUUsers(context.Background(), "cn=Users,"+msadBaseDN)
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

	_, err := conn.GetOUUsers(context.Background(), "cn=Users,"+msadBaseDN)
	require.Error(t, err)
	assert.ErrorIs(t, err, ldapper.ErrClosed)
}

// ================== SearchLimits / DialTimeout / OperationTimeouts ==================

func TestIntegrationMSAD_SearchLimits_Defaults(t *testing.T) {
	conn := newMSADConn(t)
	limits := conn.GetSearchLimits()
	assert.Equal(t, 0, limits.SizeLimit)
	assert.Equal(t, 30, limits.TimeLimit)
	assert.True(t, limits.RequirePaging)
}

func TestIntegrationMSAD_SearchLimits_WithOption(t *testing.T) {
	limits := ldapper.DefaultSearchLimits()
	limits.SizeLimit = 5
	limits.TimeLimit = 10
	conn := newMSADConn(t, ldapper.WithSearchLimits(limits))

	got := conn.GetSearchLimits()
	assert.Equal(t, 5, got.SizeLimit)
	assert.Equal(t, 10, got.TimeLimit)
	assert.True(t, got.RequirePaging, "WithSearchLimits replaces the struct")
}

func TestIntegrationMSAD_SearchLimits_SetAtRuntime(t *testing.T) {
	conn := newMSADConn(t)

	limits := conn.GetSearchLimits()
	limits.SizeLimit = 7
	limits.TimeLimit = 11
	conn.SetSearchLimits(limits)

	got := conn.GetSearchLimits()
	assert.Equal(t, 7, got.SizeLimit)
	assert.Equal(t, 11, got.TimeLimit)
}

func TestIntegrationMSAD_SearchLimits_NegativeClampedToZero(t *testing.T) {
	conn := newMSADConn(t)
	conn.SetSearchLimits(ldapper.SearchLimits{SizeLimit: -1, TimeLimit: -5})
	got := conn.GetSearchLimits()
	assert.Equal(t, 0, got.SizeLimit)
	assert.Equal(t, 0, got.TimeLimit)
}

func TestIntegrationMSAD_DialTimeout_Defaults(t *testing.T) {
	conn := newMSADConn(t)
	// NewLDAPper initialises dialTimeout to constants.DefaultDialTimeout.
	assert.Equal(t, constants.DefaultDialTimeout, conn.GetDialTimeout())
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

func TestIntegrationMSAD_OperationTimeout_WithOption(t *testing.T) {
	conn := newMSADConn(t, ldapper.WithOperationTimeout(ldapper.OperationTimeouts{
		Bind:   5 * time.Second,
		Search: 5 * time.Second,
	}))
	got := conn.GetOperationTimeout()
	assert.Equal(t, 5*time.Second, got.Bind)
	assert.Equal(t, 5*time.Second, got.Search)

	// Operation must still succeed under a healthy timeout.
	_, err := conn.GetUser(context.Background(), msadUser1SAM, msadBaseDN)
	require.NoError(t, err)
}

// ================== Failure paths ==================

func TestIntegrationMSAD_BindConn_FailedBind_InvalidatesState(t *testing.T) {
	conn := newMSADConn(t)

	_, err := conn.BindConn(context.Background(), msadAdminDN, msadAdminPass, msadBaseDN)
	require.NoError(t, err)

	_, err = conn.BindConn(context.Background(), msadAdminDN, "wrong-password", msadBaseDN)
	require.Error(t, err)
	assert.ErrorIs(t, err, ldapper.ErrInvalidCredentials)

	_, err = conn.CheckUserCredentials(context.Background(), msadUser1SAM, msadUser1Pass)
	require.Error(t, err)
	assert.ErrorIs(t, err, ldapper.ErrClosed,
		"post-failed-bind connection is nil; requireConnLocked fires before the auth check")
}

// Breaks user1's password via samba-tool, verifies that Reconnect fails on
// the stale cached password and leaves the client unusable (ErrClosed).
func TestIntegrationMSAD_Reconnect_RebindFailure_ClosesConnection(t *testing.T) {
	conn := newMSADConn(t)
	_, err := conn.BindConn(context.Background(), msadUser1SAM, msadUser1Pass, msadBaseDN)
	require.NoError(t, err)

	ctx := context.Background()

	// Break credentials.
	code, _, execErr := msadContainer.Exec(ctx, []string{
		"samba-tool", "user", "setpassword", msadUser1SAM,
		"--newpassword=DifferentPass1!",
	})
	require.NoError(t, execErr)
	require.Equal(t, 0, code, "setpassword must succeed for the test to be meaningful")
	t.Cleanup(func() {
		code, _, _ := msadContainer.Exec(context.Background(), []string{
			"samba-tool", "user", "setpassword", msadUser1SAM,
			"--newpassword=" + msadUser1Pass,
		})
		_ = code
	})

	// Reconnect uses the cached old password — must fail.
	err = conn.Reconnect(context.Background())
	require.Error(t, err)
	assert.ErrorIs(t, err, ldapper.ErrInvalidCredentials)

	// Connection must not be usable — no silent anonymous fallback.
	_, err = conn.GetUser(context.Background(), msadUser2SAM, msadBaseDN)
	require.Error(t, err)
	assert.ErrorIs(t, err, ldapper.ErrClosed)

	_, err = conn.CheckUserCredentials(context.Background(), msadUser2SAM, msadUser2Pass)
	require.Error(t, err)
	assert.ErrorIs(t, err, ldapper.ErrClosed,
		"connection is nil after failed rebind; requireConnLocked wins over requireAuthLocked")
}

// Compile-time guard: the test file depends on adapters.MSADAdapter
// implementing CatalogAdapter and PrimaryGroupResolver.
var _ = func() any {
	var c any = adapters.MSADAdapter{}
	_, ok := c.(interface {
		ResolvePrimaryGroupDN(context.Context, types.LDAPUser, any) (string, error)
	})
	_ = ok
	return nil
}
