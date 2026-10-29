// Copyright 2020-2026 NGR Softlab
package ldapper

import (
	"crypto/tls"

	"github.com/go-ldap/ldap/v3"
	"github.com/stretchr/testify/mock"
)

type MockLDAPConn struct {
	mock.Mock
}

func (m *MockLDAPConn) StartTLS(config *tls.Config) error {
	args := m.Called(config)
	return args.Error(0)
}

func (m *MockLDAPConn) Bind(username, password string) error {
	args := m.Called(username, password)
	return args.Error(0)
}

func (m *MockLDAPConn) Search(request *ldap.SearchRequest) (*ldap.SearchResult, error) {
	args := m.Called(request)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*ldap.SearchResult), args.Error(1)
}

func (m *MockLDAPConn) Close() error {
	args := m.Called()
	return args.Error(0)
}
