//go:build integration_samba
// +build integration_samba

package ldapper_test

// Samba 4 AD DC integration tests.
//
// SAMBAAdapter is a strict extension of MSADAdapter: the Samba 4 AD DC
// schema is AD-compatible (sAMAccountName, userPrincipalName, objectSid,
// primaryGroupID, objectCategory, LDAP_MATCHING_RULE_IN_CHAIN). Every
// assertion here is therefore the Samba-flavoured version of the MSAD
// suite — the adapter code is shared, but the container, image and
// seed bootstrap are different, so the suite is exercised end-to-end
// against a real Samba DC.
//
// Run with:
//   go test -tags=integration_samba ./...

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
	"github.com/NGRsoftlab/ldapper/interfaces"
	"github.com/NGRsoftlab/ldapper/types"
)

const (
	sambaRealm     = "SAMBA.EXAMPLE"
	sambaDomain    = "SAMBA"
	sambaAdminPass = "P@ssw0rd123!"

	sambaBaseDN  = "dc=samba,dc=example"
	sambaAdminDN = "cn=Administrator,cn=Users," + sambaBaseDN

	sambaUser1SAM  = "user1"
	sambaUser1Pass = "Password1!"
	sambaUser2SAM  = "user2"
	sambaUser2Pass = "Password2!"

	sambaTestOUDN = "ou=testou," + sambaBaseDN
)

var (
	sambaHost      string
	sambaPort      uint
	sambaContainer testcontainers.Container
	sambaAvailable bool
	sambaAdpt      = adapters.SAMBAAdapter{}
)

func TestMain(m *testing.M) {
	ctx := context.Background()

	req := testcontainers.ContainerRequest{
		Image:        "nowszy/samba-ad-dc:latest",
		ExposedPorts: []string{"389/tcp"},
		Privileged:   true,
		Hostname:     "samba.samba.example",
		Env: map[string]string{
			"REALM":          sambaRealm,
			"DOMAIN":         sambaDomain,
			"ADMIN_PASSWORD": sambaAdminPass,
			"DNS_FORWARDER":  "8.8.8.8",
		},
		WaitingFor: wait.ForListeningPort("389/tcp").WithStartupTimeout(180 * time.Second),
	}

	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Samba tests skipped: cannot start container: %v\n", err)
		os.Exit(m.Run())
	}
	sambaContainer = container

	sambaHost, err = container.Host(ctx)
	if err != nil {
		_ = container.Terminate(ctx)
		fmt.Fprintf(os.Stderr, "Samba tests skipped: cannot resolve host: %v\n", err)
		os.Exit(m.Run())
	}

	mappedPort, err := container.MappedPort(ctx, "389")
	if err != nil {
		_ = container.Terminate(ctx)
		fmt.Fprintf(os.Stderr, "Samba tests skipped: cannot resolve port: %v\n", err)
		os.Exit(m.Run())
	}
	sambaPort = uint(mappedPort.Num())

	if !waitForSambaReady(sambaHost, sambaPort, 120*time.Second) {
		_ = container.Terminate(ctx)
		fmt.Fprintln(os.Stderr, "Samba tests skipped: LDAP not ready")
		os.Exit(m.Run())
	}

	if err := seedSamba(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "Samba tests skipped: seed failed: %v\n", err)
		_ = container.Terminate(ctx)
		os.Exit(m.Run())
	}

	sambaAvailable = true
	code := m.Run()
	_ = container.Terminate(ctx)
	os.Exit(code)
}

func waitForSambaReady(host string, port uint, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		c, err := ldap.DialURL(fmt.Sprintf("ldap://%s:%d", host, port))
		if err == nil {
			err = c.Bind(sambaAdminDN, sambaAdminPass)
			_ = c.Close()
			if err == nil {
				return true
			}
		}
		time.Sleep(1 * time.Second)
	}
	return false
}

func seedSamba(ctx context.Context) error {
	execCmds := [][]string{
		{"samba-tool", "user", "create", sambaUser1SAM, sambaUser1Pass},
		{"samba-tool", "user", "create", sambaUser2SAM, sambaUser2Pass},
		{"samba-tool", "group", "add", "admins"},
		{"samba-tool", "group", "addmembers", "admins", sambaUser1SAM},
		{"samba-tool", "group", "add", "readers"},
		{"samba-tool", "group", "addmembers", "readers", sambaUser2SAM},
	}
	for _, cmd := range execCmds {
		code, reader, err := sambaContainer.Exec(ctx, cmd)
		if err != nil {
			return fmt.Errorf("exec %v: %w", cmd, err)
		}
		if code != 0 {
			var out bytes.Buffer
			_, _ = io.Copy(&out, reader)
			return fmt.Errorf("exec %v exited %d: %s", cmd, code, out.String())
		}
	}

	c, err := ldap.DialURL(fmt.Sprintf("ldap://%s:%d", sambaHost, sambaPort))
	if err != nil {
		return fmt.Errorf("dial for OU seed: %w", err)
	}
	defer c.Close()
	if err := c.Bind(sambaAdminDN, sambaAdminPass); err != nil {
		return fmt.Errorf("bind for OU seed: %w", err)
	}
	add := ldap.NewAddRequest(sambaTestOUDN, nil)
	add.Attribute("objectClass", []string{"organizationalUnit"})
	add.Attribute("ou", []string{"testou"})
	if err := c.Add(add); err != nil {
		if !ldap.IsErrorWithCode(err, ldap.LDAPResultEntryAlreadyExists) {
			return fmt.Errorf("add test OU: %w", err)
		}
	}
	return nil
}

func requireSamba(t *testing.T) {
	t.Helper()
	if !sambaAvailable {
		t.Skip("Samba AD DC not available; test skipped")
	}
}

func newSambaConn(t *testing.T, opts ...ldapper.Option) *ldapper.LDAPper {
	t.Helper()
	requireSamba(t)
	conn, err := ldapper.NewLDAPper(
		context.Background(), []string{sambaHost}, sambaPort,
		false, true, nil, sambaAdpt, opts...,
	)
	require.NoError(t, err)
	t.Cleanup(conn.Close)
	return conn
}

func newSambaAuthConn(t *testing.T, opts ...ldapper.Option) *ldapper.LDAPper {
	t.Helper()
	requireSamba(t)
	conn, err := ldapper.NewAuthenticatedLDAPper(
		context.Background(), sambaAdminDN, sambaAdminPass, sambaBaseDN,
		[]string{sambaHost}, sambaPort, false, true, nil, sambaAdpt, opts...,
	)
	require.NoError(t, err)
	t.Cleanup(conn.Close)
	return conn
}

// ================== constructor validation ==================

func TestIntegrationSamba_NewConnection_Success(t *testing.T) {
	conn := newSambaConn(t)
	assert.True(t, conn.IsAlive(context.Background()))
}

func TestIntegrationSamba_NewConnection_EmptyHosts(t *testing.T) {
	requireSamba(t)
	_, err := ldapper.NewLDAPper(context.Background(), nil, 389, false, true, nil, sambaAdpt)
	require.Error(t, err)
	assert.ErrorIs(t, err, ldapper.ErrInvalidArgument)
}

func TestIntegrationSamba_NewConnection_TooManyHosts(t *testing.T) {
	requireSamba(t)
	hosts := make([]string, constants.DefaultMaxHostsLength+1)
	for i := range hosts {
		hosts[i] = fmt.Sprintf("host%d", i)
	}
	_, err := ldapper.NewLDAPper(context.Background(), hosts, 389, false, true, nil, sambaAdpt)
	require.Error(t, err)
	assert.ErrorIs(t, err, ldapper.ErrInvalidArgument)
}

func TestIntegrationSamba_NewConnection_NilCatalogAdapter(t *testing.T) {
	requireSamba(t)
	_, err := ldapper.NewLDAPper(context.Background(), []string{sambaHost}, sambaPort, false, true, nil, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, ldapper.ErrInvalidArgument)
}

func TestIntegrationSamba_NewConnection_UnreachableHost(t *testing.T) {
	requireSamba(t)
	_, err := ldapper.NewLDAPper(context.Background(), []string{"127.0.0.1"}, 1, false, true, nil, sambaAdpt)
	require.Error(t, err)
	assert.ErrorIs(t, err, ldapper.ErrUnavailable)
}

func TestIntegrationSamba_NewAuthenticatedConnection_Success(t *testing.T) {
	requireSamba(t)
	conn, err := ldapper.NewAuthenticatedLDAPper(
		context.Background(), sambaAdminDN, sambaAdminPass, sambaBaseDN,
		[]string{sambaHost}, sambaPort, false, true, nil, sambaAdpt,
	)
	require.NoError(t, err)
	defer conn.Close()
}

func TestIntegrationSamba_NewAuthenticatedConnection_WrongPassword(t *testing.T) {
	requireSamba(t)
	_, err := ldapper.NewAuthenticatedLDAPper(
		context.Background(), sambaAdminDN, "wrong-password", sambaBaseDN,
		[]string{sambaHost}, sambaPort, false, true, nil, sambaAdpt,
	)
	require.Error(t, err)
	assert.ErrorIs(t, err, ldapper.ErrInvalidCredentials)
}

// ================== BindConn / CheckUserCredentials ==================

func TestIntegrationSamba_BindConn_Success(t *testing.T) {
	conn := newSambaConn(t)
	err := conn.BindConn(context.Background(), sambaAdminDN, sambaAdminPass, sambaBaseDN)
	require.NoError(t, err)
}

func TestIntegrationSamba_BindConn_WrongPassword(t *testing.T) {
	conn := newSambaConn(t)
	err := conn.BindConn(context.Background(), sambaAdminDN, "bad-password", sambaBaseDN)
	require.Error(t, err)
	assert.ErrorIs(t, err, ldapper.ErrInvalidCredentials)
}

func TestIntegrationSamba_CheckUserCredentials_Success(t *testing.T) {
	conn := newSambaAuthConn(t)
	user, err := conn.CheckUserCredentials(context.Background(), sambaUser1SAM, sambaUser1Pass)
	require.NoError(t, err)
	require.NotNil(t, user)
	assert.Equal(t, sambaUser1SAM, user.GetAttributeValue("sAMAccountName"))
}

func TestIntegrationSamba_CheckUserCredentials_WrongPassword(t *testing.T) {
	conn := newSambaAuthConn(t)
	user, err := conn.CheckUserCredentials(context.Background(), sambaUser1SAM, "bad")
	require.Error(t, err)
	assert.ErrorIs(t, err, ldapper.ErrInvalidCredentials)
	assert.Nil(t, user)
}

func TestIntegrationSamba_CheckUserCredentials_NotAuthenticated(t *testing.T) {
	conn := newSambaConn(t)
	_, err := conn.CheckUserCredentials(context.Background(), sambaUser1SAM, sambaUser1Pass)
	require.Error(t, err)
	assert.ErrorIs(t, err, ldapper.ErrNotAuthenticated)
}

// ================== GetUser / GetGroup / GetOU ==================

func TestIntegrationSamba_GetUser_BySAMAccountName(t *testing.T) {
	conn := newSambaAuthConn(t)
	user, err := conn.GetUser(context.Background(), sambaUser1SAM, sambaBaseDN)
	require.NoError(t, err)
	require.NotNil(t, user)
	assert.Equal(t, sambaUser1SAM, user.GetAttributeValue("sAMAccountName"))
}

func TestIntegrationSamba_GetUser_NotFound(t *testing.T) {
	conn := newSambaAuthConn(t)
	_, err := conn.GetUser(context.Background(), "does-not-exist", sambaBaseDN)
	require.Error(t, err)
	assert.ErrorIs(t, err, ldapper.ErrNotFoundOrNotVisible)
}

func TestIntegrationSamba_GetGroup_Success(t *testing.T) {
	conn := newSambaAuthConn(t)
	group, err := conn.GetGroup(context.Background(), "admins", sambaBaseDN)
	require.NoError(t, err)
	require.NotNil(t, group)
	assert.Equal(t, "admins", group.GetAttributeValue("cn"))
}

func TestIntegrationSamba_GetOU_Success(t *testing.T) {
	conn := newSambaAuthConn(t)
	ou, err := conn.GetOU(context.Background(), "testou", sambaBaseDN)
	require.NoError(t, err)
	require.NotNil(t, ou)
	assert.Contains(t, strings.ToLower(ou.DN), "ou=testou")
}

// ================== GetUserGroups / PrimaryGroupResolver ==================

func TestIntegrationSamba_GetUserGroups_AdminsMembership(t *testing.T) {
	conn := newSambaAuthConn(t)
	groups, err := conn.GetUserGroups(context.Background(), sambaUser1SAM, sambaBaseDN)
	require.NoError(t, err)
	assert.True(t, containsDN(groups, "cn=admins"),
		"expected an admins group DN in %v", groups)
}

func TestIntegrationSamba_GetUserGroups_IncludesPrimaryGroup(t *testing.T) {
	conn := newSambaAuthConn(t)
	groups, err := conn.GetUserGroups(context.Background(), sambaUser1SAM, sambaBaseDN)
	require.NoError(t, err)

	// Resolve the expected primary-group DN via primaryGroupToken (RID 513),
	// which is locale-independent — "Domain Users" only works in English
	// Samba builds.
	req := ldap.NewSearchRequest(
		sambaBaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		0, 0, false, "(primaryGroupToken=513)",
		[]string{"distinguishedName"}, nil,
	)
	res, err := conn.CustomSearch(context.Background(), req)
	require.NoError(t, err)
	require.Len(t, res.Entries, 1,
		"expected exactly one group with primaryGroupToken=513")

	assert.True(t, containsDN(groups, res.Entries[0].DN),
		"expected primary group %q in %v", res.Entries[0].DN, groups)
}

// ================== GetCatalogTree / GetSubOUs ==================

func TestIntegrationSamba_GetCatalogTree_Success(t *testing.T) {
	conn := newSambaAuthConn(t)
	tree, err := conn.GetCatalogTree(context.Background(), sambaBaseDN, 0)
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

func TestIntegrationSamba_GetOUUsers(t *testing.T) {
	conn := newSambaAuthConn(t)
	users, err := conn.GetOUUsers(context.Background(), "cn=Users,"+sambaBaseDN)
	require.NoError(t, err)
	require.NotEmpty(t, users)

	sams := make([]string, 0, len(users))
	for _, u := range users {
		sams = append(sams, u.GetAttributeValue("sAMAccountName"))
	}
	assert.Contains(t, sams, sambaUser1SAM)
	assert.Contains(t, sams, sambaUser2SAM)
}

// ================== Health checks / Reconnect / Close ==================

func TestIntegrationSamba_IsAlive_AfterClose(t *testing.T) {
	conn := newSambaConn(t)
	conn.Close()
	assert.False(t, conn.IsAlive(context.Background()))
}

func TestIntegrationSamba_Reconnect_PreservesAuthentication(t *testing.T) {
	conn := newSambaAuthConn(t)
	require.NoError(t, conn.Reconnect(context.Background()))
	_, err := conn.CheckUserCredentials(context.Background(), sambaUser1SAM, sambaUser1Pass)
	require.NoError(t, err)
}

func TestIntegrationSamba_EnsureAlive_ClosedClient_ReturnsErrClosed(t *testing.T) {
	conn := newSambaAuthConn(t)
	conn.Close()
	require.False(t, conn.IsAlive(context.Background()))

	err := conn.EnsureAlive(context.Background())
	require.Error(t, err)
	assert.ErrorIs(t, err, ldapper.ErrClosed)
}

// SAMBAAdapter MUST implement PrimaryGroupResolver: GetUserGroups relies on
// the type assertion to inject the primary group into the result. This is
// a true compile-time assertion.
var _ interfaces.PrimaryGroupResolver = adapters.SAMBAAdapter{}
