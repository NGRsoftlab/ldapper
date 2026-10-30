// Copyright 2020-2026 NGR Softlab
package mocks

import (
	"crypto/tls"

	"github.com/go-ldap/ldap/v3"
)

// NB: update this mock if the interface gains new methods.
type MockLDAPConn struct {
	BindFunc      func(username, password string) error
	SearchFunc    func(req *ldap.SearchRequest) (*ldap.SearchResult, error)
	CloseFunc     func() error
	IsClosingFunc func() bool
	StartTLSFunc  func(config *tls.Config) error
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

func (m *MockLDAPConn) Close() error {
	if m.CloseFunc != nil {
		return m.CloseFunc()
	}
	return nil
}

func (m *MockLDAPConn) IsClosing() bool {
	if m.IsClosingFunc != nil {
		return m.IsClosingFunc()
	}
	return false
}

func (m *MockLDAPConn) StartTLS(c *tls.Config) error {
	if m.StartTLSFunc != nil {
		return m.StartTLSFunc(c)
	}
	return nil
}
