// Copyright 2020-2026 NGR Softlab
package mocks

import (
	"github.com/go-ldap/ldap/v3"
	"github.com/stretchr/testify/mock"

	"github.com/NGRsoftlab/ldapper/types"
)

// MockCatalogAdapter — мок для CatalogAdapter.
type MockCatalogAdapter struct {
	mock.Mock
}

func (m *MockCatalogAdapter) GetNormalizedUserInfo(ldapUser types.LDAPUser) *types.UserNormalizedInfo {
	args := m.Called(ldapUser)
	return args.Get(0).(*types.UserNormalizedInfo)
}

func (m *MockCatalogAdapter) OUInfoFromEntry(entry ldap.Entry) *types.OUInfo {
	args := m.Called(entry)
	return args.Get(0).(*types.OUInfo)
}

func (m *MockCatalogAdapter) UserObjectFilter() string {
	args := m.Called()
	return args.String(0)
}
func (m *MockCatalogAdapter) GroupObjectFilter() string {
	args := m.Called()
	return args.String(0)
}
func (m *MockCatalogAdapter) OUObjectFilter() string {
	args := m.Called()
	return args.String(0)
}

func (m *MockCatalogAdapter) SearchUserFilterTemplate() string {
	args := m.Called()
	return args.String(0)
}
func (m *MockCatalogAdapter) SearchUserGroupsFilterTemplate() string {
	args := m.Called()
	return args.String(0)
}
func (m *MockCatalogAdapter) SearchUserGroupsFilterTemplateArgs(ldapUser types.LDAPUser) []any {
	args := m.Called(ldapUser)
	return args.Get(0).([]any)
}
func (m *MockCatalogAdapter) SearchOUFilterTemplate() string {
	args := m.Called()
	return args.String(0)
}
func (m *MockCatalogAdapter) SearchGroupFilterTemplate() string {
	args := m.Called()
	return args.String(0)
}

func (m *MockCatalogAdapter) UserAttrs() []string {
	args := m.Called()
	return args.Get(0).([]string)
}
func (m *MockCatalogAdapter) OUAttrs() []string {
	args := m.Called()
	return args.Get(0).([]string)
}
func (m *MockCatalogAdapter) ShortUserAttrs() []string {
	args := m.Called()
	return args.Get(0).([]string)
}
func (m *MockCatalogAdapter) GroupAttrs() []string {
	args := m.Called()
	return args.Get(0).([]string)
}
