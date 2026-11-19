// Copyright 2020-2026 NGR Softlab
package mocks

import (
	"crypto/tls"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-ldap/ldap/v3"
)

// NB: update this mock if the interface gains new methods.
type MockLDAPConn struct {
	BindFunc       func(username, password string) error
	SearchFunc     func(req *ldap.SearchRequest) (*ldap.SearchResult, error)
	SetTimeoutFunc func(d time.Duration)
	CloseFunc      func() error
	IsClosingFunc  func() bool
	StartTLSFunc   func(config *tls.Config) error
	closeOnce      sync.Once
	closeErr       error
	closed         atomic.Bool
}

func (m *MockLDAPConn) SetTimeout(d time.Duration) {
	if m.SetTimeoutFunc != nil {
		m.SetTimeoutFunc(d)
	}
}

func (m *MockLDAPConn) Bind(u, p string) error {
	if m.BindFunc != nil {
		return m.BindFunc(u, p)
	}
	return nil
}

func (m *MockLDAPConn) Search(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
	if m.SearchFunc != nil {
		return m.SearchFunc(req)
	}
	return &ldap.SearchResult{}, nil
}

// Close is idempotent: CloseFunc fires at most once. A panic inside
// CloseFunc is recovered and surfaced as a non-nil error so that a broken
// test hook is visible to the caller — before this change, sync.Once
// silently swallowed the panic, closed=true was already set, and CloseFunc
// was never invoked again, hiding the failure.
func (m *MockLDAPConn) Close() error {
	m.closeOnce.Do(func() {
		m.closed.Store(true)
		if m.CloseFunc == nil {
			return
		}
		defer func() {
			if r := recover(); r != nil {
				m.closeErr = fmt.Errorf("MockLDAPConn.CloseFunc panicked: %v", r)
			}
		}()
		m.closeErr = m.CloseFunc()
	})
	return m.closeErr
}

func (m *MockLDAPConn) IsClosing() bool {
	if m.IsClosingFunc != nil {
		return m.IsClosingFunc()
	}
	return m.closed.Load()
}

func (m *MockLDAPConn) StartTLS(c *tls.Config) error {
	if m.StartTLSFunc != nil {
		return m.StartTLSFunc(c)
	}
	return nil
}
