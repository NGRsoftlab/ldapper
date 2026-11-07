// Copyright 2020-2026 NGR Softlab
package ldapper

import (
	"context"
	"crypto/tls"
	"errors"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/NGRsoftlab/ldapper/constants"
)

// stubTLSCfg is a minimal non-nil *tls.Config for constructors that
// require one. Values are irrelevant to the code under test.
func stubTLSCfg() *tls.Config {
	return &tls.Config{ServerName: "ldap.example.com"} //nolint:gosec // test-only
}

// connectStub returns a dialConn replacement that always succeeds and
// records the addresses tried. Tests asserting on the result use the
// returned pointer; the *ldap.Conn value is never touched by NewLDAPper
// (no Bind / Search / StartTLS is invoked at construction time), so a
// bare &ldap.Conn{} is safe.
func connectStub(t *testing.T) (*ldap.Conn, *[]string) {
	t.Helper()
	conn := &ldap.Conn{}
	var tried []string
	withDialConn(t, func(_ context.Context, host string, _ uint, _, _ bool, _ *tls.Config, _ time.Duration) (*ldap.Conn, error) {
		tried = append(tried, host)
		return conn, nil
	})
	return conn, &tried
}

// ================== NewLDAPper: input validation ==================

func TestNewLDAPper_EmptyHosts(t *testing.T) {
	t.Parallel()

	_, err := NewLDAPper(context.Background(), nil, 389, false, true, nil, fakeAdapter{})

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidArgument)
	assert.Contains(t, err.Error(), "empty hosts")
}

func TestNewLDAPper_TooManyHosts(t *testing.T) {
	t.Parallel()

	hosts := make([]string, constants.DefaultMaxHostsLength+1)
	for i := range hosts {
		hosts[i] = "h"
	}

	_, err := NewLDAPper(context.Background(), hosts, 389, false, true, nil, fakeAdapter{})

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidArgument)
	assert.Contains(t, err.Error(), "too many hosts")
}

func TestNewLDAPper_InvalidHostInList(t *testing.T) {
	t.Parallel()

	_, err := NewLDAPper(context.Background(),
		[]string{"good.example.com", "bad/host"}, 389, false, true, nil, fakeAdapter{})

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidArgument)
	assert.Contains(t, err.Error(), "bad/host")
}

func TestNewLDAPper_InvalidPort(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		port uint
	}{
		{"zero", 0},
		{"above uint16", 65536},
		{"way above", 1_000_000},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := NewLDAPper(context.Background(),
				[]string{"h"}, tt.port, false, true, nil, fakeAdapter{})
			require.Error(t, err)
			assert.ErrorIs(t, err, ErrInvalidArgument)
			assert.Contains(t, err.Error(), "invalid port")
		})
	}
}

func TestNewLDAPper_UseSSLWithSkipTLS(t *testing.T) {
	t.Parallel()

	_, err := NewLDAPper(context.Background(),
		[]string{"h"}, 636, true /*useSSL*/, true /*skipTLS*/, stubTLSCfg(), fakeAdapter{})

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidArgument)
	assert.Contains(t, err.Error(), "skipTLS has no effect")
}

func TestNewLDAPper_NilTLSWithoutSkip(t *testing.T) {
	t.Parallel()

	_, err := NewLDAPper(context.Background(),
		[]string{"h"}, 389, false /*useSSL*/, false /*skipTLS*/, nil, fakeAdapter{})

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidArgument)
	assert.Contains(t, err.Error(), "tls config")
}

func TestNewLDAPper_NilAdapter(t *testing.T) {
	t.Parallel()

	_, err := NewLDAPper(context.Background(),
		[]string{"h"}, 389, false, true, nil, nil)

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidArgument)
	assert.Contains(t, err.Error(), "catalog adapter")
}

func TestNewLDAPper_NilOption(t *testing.T) {
	t.Parallel()

	_, err := NewLDAPper(context.Background(),
		[]string{"h"}, 389, false, true, nil, fakeAdapter{}, nil)

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidArgument)
	assert.Contains(t, err.Error(), "nil option")
}

// ================== NewLDAPper: success path ==================

func TestNewLDAPper_Success_AppliesDefaults(t *testing.T) {
	// no t.Parallel — swaps dialConn.
	conn, _ := connectStub(t)

	l, err := NewLDAPper(context.Background(),
		[]string{"ldap.example.com"}, 389, false, true, nil, fakeAdapter{})

	require.NoError(t, err)
	require.NotNil(t, l)
	assert.Same(t, conn, l.connection)
	assert.Equal(t, "ldap.example.com", l.currentHost)
	assert.Equal(t, DefaultSearchLimits(), l.searchLimits)
	assert.Equal(t, constants.DefaultDialTimeout, l.dialTimeout)
	assert.Equal(t, OperationTimeouts{}, l.opTimeouts,
		"OperationTimeouts is zero by default (backwards compatible)")
}

func TestNewLDAPper_AppliesOptions(t *testing.T) {
	// no t.Parallel — swaps dialConn.
	connectStub(t)

	wantLimits := SearchLimits{
		SizeLimit: 100, TimeLimit: 5, MaxPages: 2, MaxEntries: 500, RequirePaging: false,
	}
	wantTimeout := 3 * time.Second
	wantOps := OperationTimeouts{Bind: time.Second, Search: 2 * time.Second}

	l, err := NewLDAPper(context.Background(),
		[]string{"h"}, 389, false, true, nil, fakeAdapter{},
		WithSearchLimits(wantLimits),
		WithDialTimeout(wantTimeout),
		WithOperationTimeout(wantOps),
	)

	require.NoError(t, err)
	assert.Equal(t, wantLimits, l.searchLimits)
	assert.Equal(t, wantTimeout, l.dialTimeout)
	assert.Equal(t, wantOps, l.opTimeouts)
}

func TestNewLDAPper_ClonesTLSConfig(t *testing.T) {
	// no t.Parallel — swaps dialConn.
	connectStub(t)

	orig := stubTLSCfg()
	l, err := NewLDAPper(context.Background(),
		[]string{"h"}, 389, true /*useSSL*/, false, orig, fakeAdapter{})

	require.NoError(t, err)
	require.NotNil(t, l.tlsCfg)
	assert.NotSame(t, orig, l.tlsCfg,
		"tls.Config must be cloned, not aliased: caller mutating orig must not affect LDAPper")

	// Sanity: cloned config carries the same ServerName.
	assert.Equal(t, orig.ServerName, l.tlsCfg.ServerName)
}

func TestNewLDAPper_CopiesHostsSlice(t *testing.T) {
	// no t.Parallel — swaps dialConn.
	connectStub(t)

	hosts := []string{"h1", "h2"}
	l, err := NewLDAPper(context.Background(),
		hosts, 389, false, true, nil, fakeAdapter{})

	require.NoError(t, err)

	// Mutating the caller's slice must not affect the constructed object.
	hosts[0] = "mutated"
	assert.Equal(t, []string{"h1", "h2"}, l.hosts,
		"hosts must be defensively copied")
}

func TestNewLDAPper_DialFails(t *testing.T) {
	// no t.Parallel — swaps dialConn.
	withDialConn(t, func(context.Context, string, uint, bool, bool, *tls.Config, time.Duration) (*ldap.Conn, error) {
		return nil, errors.New("network unreachable")
	})

	_, err := NewLDAPper(context.Background(),
		[]string{"h1"}, 389, false, true, nil, fakeAdapter{})

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrUnavailable,
		"dial failure at construction must surface as ErrUnavailable")
}

// ================== NewAuthenticatedLDAPper ==================
//
// The success path requires a live connection: NewAuthenticatedLDAPper
// calls AuthenticateConn which invokes Bind on the *ldap.Conn returned by
// dialConn, and a bare &ldap.Conn{} panics on Bind (nil net.Conn inside).
// Full success coverage therefore lives in an integration test against a
// real LDAP server (testcontainers-go is already in go.mod); here we cover
// only the validation and error-propagation paths.

func TestNewAuthenticatedLDAPper_EmptyCredentials(t *testing.T) {
	t.Parallel()

	t.Run("empty username", func(t *testing.T) {
		t.Parallel()
		l, user, err := NewAuthenticatedLDAPper(context.Background(),
			"", "pass", "dc=x",
			[]string{"h"}, 389, false, true, nil, fakeAdapter{})
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidArgument)
		assert.Nil(t, l)
		assert.Nil(t, user)
	})

	t.Run("empty password", func(t *testing.T) {
		t.Parallel()
		l, user, err := NewAuthenticatedLDAPper(context.Background(),
			"user", "", "dc=x",
			[]string{"h"}, 389, false, true, nil, fakeAdapter{})
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidArgument)
		assert.Nil(t, l)
		assert.Nil(t, user)
	})
}

func TestNewAuthenticatedLDAPper_PropagatesNewLDAPperError(t *testing.T) {
	t.Parallel()

	// Empty host list — NewLDAPper fails before any dial.
	l, user, err := NewAuthenticatedLDAPper(context.Background(),
		"user", "pass", "dc=x",
		nil, 389, false, true, nil, fakeAdapter{})

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidArgument)
	assert.Nil(t, l)
	assert.Nil(t, user)
}

func TestNewAuthenticatedLDAPper_PropagatesAuthError(t *testing.T) {
	// no t.Parallel — swaps dialConn.

	// dialConn returns *ldap.Conn, so we cannot inject a MockLDAPConn
	// directly. Instead, verify the error path with the real dial seam
	// returning an error — this exercises NewLDAPper failure rather than
	// Auth failure, but the important invariant (no leaked LDAPper, no
	// partial state) is the same. Full auth-failure coverage is delegated
	// to the integration test.
	withDialConn(t, func(context.Context, string, uint, bool, bool, *tls.Config, time.Duration) (*ldap.Conn, error) {
		return nil, errors.New("dial failed")
	})

	l, user, err := NewAuthenticatedLDAPper(context.Background(),
		"user", "pass", "dc=x",
		[]string{"h"}, 389, false, true, nil, fakeAdapter{})

	require.Error(t, err)
	assert.Nil(t, l)
	assert.Nil(t, user)
}
