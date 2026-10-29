// Copyright 2020-2026 NGR Softlab
package ldapper

import (
	"errors"
	"testing"

	"github.com/go-ldap/ldap/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/NGRsoftlab/ldapper/constants"
	"github.com/NGRsoftlab/ldapper/mocks"
)

// ---------- CustomSearch ----------

func TestCustomSearch_Success(t *testing.T) {
	request := ldap.NewSearchRequest(
		"dc=example,dc=com",
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=*)", []string{"dn"}, nil,
	)
	expected := &ldap.SearchResult{Entries: []*ldap.Entry{{DN: "dc=example,dc=com"}}}

	connMock := new(mocks.MockLDAPConn)
	connMock.On("Search", request).Return(expected, nil).Once()

	conn := &LDAPConnection{connection: connMock}
	result, err := conn.CustomSearch(request)

	assert.NoError(t, err)
	assert.Equal(t, expected, result)
	connMock.AssertExpectations(t)
}

func TestCustomSearch_NilConnection(t *testing.T) {
	conn := &LDAPConnection{}
	result, err := conn.CustomSearch(ldap.NewSearchRequest(
		"dc=example,dc=com",
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=*)", nil, nil,
	))

	assert.Nil(t, result)
	assert.EqualError(t, err, "connection not initialized")
}

func TestCustomSearch_ReturnsRawError(t *testing.T) {
	originalErr := errors.New("raw ldap error")
	connMock := new(mocks.MockLDAPConn)
	connMock.On("Search", mock.Anything).Return(nil, originalErr).Once()

	conn := &LDAPConnection{connection: connMock}
	_, err := conn.CustomSearch(ldap.NewSearchRequest(
		"dc=example,dc=com",
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=*)", nil, nil,
	))

	assert.ErrorIs(t, err, originalErr, "CustomSearch must not wrap the error")
	connMock.AssertExpectations(t)
}

// ---------- GetUser ----------

func TestGetUser_Success(t *testing.T) {
	adapter := new(mocks.MockCatalogAdapter)
	adapter.On("SearchUserFilterTemplate").Return("(uid=%s)")
	adapter.On("UserAttrs").Return([]string{"cn", "mail"})

	connMock := new(mocks.MockLDAPConn)
	connMock.On("Search", mock.Anything).Return(&ldap.SearchResult{Entries: []*ldap.Entry{
		newLDAPEntry("uid=jdoe,dc=example,dc=com", map[string][]string{
			"cn":   {"John Doe"},
			"mail": {"jdoe@example.com"},
		}),
	}}, nil).Once()

	conn := newTestConnection(adapter, connMock)
	user, err := conn.GetUser("jdoe", "dc=example,dc=com")

	assert.NoError(t, err)
	assert.NotNil(t, user)
	assert.Equal(t, "uid=jdoe,dc=example,dc=com", user.DN)
	assert.Equal(t, []string{"John Doe"}, user.Attributes["cn"])
	assert.Equal(t, []string{"jdoe@example.com"}, user.Attributes["mail"])
}

func TestGetUser_NilConnection(t *testing.T) {
	conn := &LDAPConnection{catalogAdapter: new(mocks.MockCatalogAdapter)}
	user, err := conn.GetUser("jdoe", "dc=example,dc=com")

	assert.Nil(t, user)
	assert.EqualError(t, err, "connection not initialized")
}

func TestGetUser_NoUser(t *testing.T) {
	adapter := new(mocks.MockCatalogAdapter)
	adapter.On("SearchUserFilterTemplate").Return("(uid=%s)")
	adapter.On("UserAttrs").Return([]string{"cn"})

	connMock := new(mocks.MockLDAPConn)
	connMock.On("Search", mock.Anything).
		Return(&ldap.SearchResult{Entries: []*ldap.Entry{}}, nil).Once()

	conn := newTestConnection(adapter, connMock)
	user, err := conn.GetUser("nobody", "dc=example,dc=com")

	assert.Nil(t, user)
	assert.EqualError(t, err, "user does not exist")
}

func TestGetUser_TooManyEntries(t *testing.T) {
	adapter := new(mocks.MockCatalogAdapter)
	adapter.On("SearchUserFilterTemplate").Return("(uid=%s)")
	adapter.On("UserAttrs").Return([]string{"cn"})

	connMock := new(mocks.MockLDAPConn)
	connMock.On("Search", mock.Anything).Return(&ldap.SearchResult{Entries: []*ldap.Entry{
		newLDAPEntry("uid=u1,dc=example,dc=com", nil),
		newLDAPEntry("uid=u2,dc=example,dc=com", nil),
	}}, nil).Once()

	conn := newTestConnection(adapter, connMock)
	user, err := conn.GetUser("dup", "dc=example,dc=com")

	assert.Nil(t, user)
	assert.EqualError(t, err, "too many entries returned")
}

func TestGetUser_SearchError(t *testing.T) {
	adapter := new(mocks.MockCatalogAdapter)
	adapter.On("SearchUserFilterTemplate").Return("(uid=%s)")
	adapter.On("UserAttrs").Return([]string{"cn"})

	connMock := new(mocks.MockLDAPConn)
	connMock.On("Search", mock.Anything).Return(nil, errors.New("search failed")).Once()

	conn := newTestConnection(adapter, connMock)
	user, err := conn.GetUser("jdoe", "dc=example,dc=com")

	assert.Nil(t, user)
	assert.EqualError(t, err, "unsuccessful user search: search failed")
}

func TestGetUser_VerifiesSearchRequest(t *testing.T) {
	adapter := new(mocks.MockCatalogAdapter)
	adapter.On("SearchUserFilterTemplate").Return("(uid=%s)")
	adapter.On("UserAttrs").Return([]string{"cn", "mail"})

	connMock := new(mocks.MockLDAPConn)
	connMock.On("Search", mock.MatchedBy(func(req *ldap.SearchRequest) bool {
		return req.BaseDN == "dc=example,dc=com" &&
			req.Filter == "(uid=jdoe)" &&
			req.Scope == ldap.ScopeWholeSubtree &&
			req.TimeLimit == constants.DefaultSearchTimeLimit &&
			len(req.Attributes) == 2
	})).Return(&ldap.SearchResult{Entries: []*ldap.Entry{
		newLDAPEntry("uid=jdoe,dc=example,dc=com", nil),
	}}, nil).Once()

	conn := newTestConnection(adapter, connMock)
	_, err := conn.GetUser("jdoe", "dc=example,dc=com")
	assert.NoError(t, err)
	connMock.AssertExpectations(t)
}

// ---------- GetUserGroups ----------

func TestGetUserGroups_Success(t *testing.T) {
	adapter := new(mocks.MockCatalogAdapter)
	adapter.On("SearchUserFilterTemplate").Return("(uid=%s)")
	adapter.On("UserAttrs").Return([]string{"cn"})
	adapter.On("SearchUserGroupsFilterTemplate").Return("(&(objectClass=group)(member=%s))")
	adapter.On("SearchUserGroupsFilterTemplateArgs", mock.Anything).
		Return([]any{"uid=jdoe,dc=example,dc=com"})

	connMock := new(mocks.MockLDAPConn)
	connMock.On("Search", mock.Anything).Return(&ldap.SearchResult{Entries: []*ldap.Entry{
		newLDAPEntry("uid=jdoe,dc=example,dc=com", nil),
	}}, nil).Once()
	connMock.On("Search", mock.Anything).Return(&ldap.SearchResult{Entries: []*ldap.Entry{
		newLDAPEntry("cn=admins,dc=example,dc=com", map[string][]string{"cn": {"admins"}}),
		newLDAPEntry("cn=users,dc=example,dc=com", map[string][]string{"cn": {"users"}}),
	}}, nil).Once()

	conn := newTestConnection(adapter, connMock)
	groups, err := conn.GetUserGroups("jdoe", "dc=example,dc=com")

	assert.NoError(t, err)
	assert.ElementsMatch(t, []string{"admins", "users"}, groups)
	connMock.AssertNumberOfCalls(t, "Search", 2)
}

func TestGetUserGroups_NilConnection(t *testing.T) {
	conn := &LDAPConnection{catalogAdapter: new(mocks.MockCatalogAdapter)}
	groups, err := conn.GetUserGroups("jdoe", "dc=example,dc=com")

	assert.Nil(t, groups)
	assert.EqualError(t, err, "connection not initialized")
}

func TestGetUserGroups_EmptyGroups(t *testing.T) {
	adapter := new(mocks.MockCatalogAdapter)
	adapter.On("SearchUserFilterTemplate").Return("(uid=%s)")
	adapter.On("UserAttrs").Return([]string{"cn"})
	adapter.On("SearchUserGroupsFilterTemplate").Return("(&(objectClass=group)(member=%s))")
	adapter.On("SearchUserGroupsFilterTemplateArgs", mock.Anything).
		Return([]any{"uid=jdoe,dc=example,dc=com"})

	connMock := new(mocks.MockLDAPConn)
	connMock.On("Search", mock.Anything).Return(&ldap.SearchResult{Entries: []*ldap.Entry{
		newLDAPEntry("uid=jdoe,dc=example,dc=com", nil),
	}}, nil).Once()
	connMock.On("Search", mock.Anything).
		Return(&ldap.SearchResult{Entries: []*ldap.Entry{}}, nil).Once()

	conn := newTestConnection(adapter, connMock)
	groups, err := conn.GetUserGroups("jdoe", "dc=example,dc=com")

	assert.NoError(t, err)
	assert.NotNil(t, groups)
	assert.Empty(t, groups)
}

func TestGetUserGroups_GetUserError(t *testing.T) {
	adapter := new(mocks.MockCatalogAdapter)
	adapter.On("SearchUserFilterTemplate").Return("(uid=%s)")
	adapter.On("UserAttrs").Return([]string{"cn"})

	connMock := new(mocks.MockLDAPConn)
	connMock.On("Search", mock.Anything).
		Return(&ldap.SearchResult{Entries: []*ldap.Entry{}}, nil).Once()

	conn := newTestConnection(adapter, connMock)
	groups, err := conn.GetUserGroups("nobody", "dc=example,dc=com")

	assert.Nil(t, groups)
	assert.EqualError(t, err, "user does not exist")
	connMock.AssertNumberOfCalls(t, "Search", 1)
	adapter.AssertNotCalled(t, "SearchUserGroupsFilterTemplate")
}

func TestGetUserGroups_SearchGroupsError(t *testing.T) {
	adapter := new(mocks.MockCatalogAdapter)
	adapter.On("SearchUserFilterTemplate").Return("(uid=%s)")
	adapter.On("UserAttrs").Return([]string{"cn"})
	adapter.On("SearchUserGroupsFilterTemplate").Return("(&(objectClass=group)(member=%s))")
	adapter.On("SearchUserGroupsFilterTemplateArgs", mock.Anything).
		Return([]any{"uid=jdoe,dc=example,dc=com"})

	connMock := new(mocks.MockLDAPConn)
	connMock.On("Search", mock.Anything).Return(&ldap.SearchResult{Entries: []*ldap.Entry{
		newLDAPEntry("uid=jdoe,dc=example,dc=com", nil),
	}}, nil).Once()
	connMock.On("Search", mock.Anything).
		Return(nil, errors.New("groups lookup failed")).Once()

	conn := newTestConnection(adapter, connMock)
	groups, err := conn.GetUserGroups("jdoe", "dc=example,dc=com")

	assert.Nil(t, groups)
	assert.EqualError(t, err, "unsuccessful user groups search: groups lookup failed")
}

func TestGetUserGroups_VerifiesGroupFilterRequest(t *testing.T) {
	adapter := new(mocks.MockCatalogAdapter)
	adapter.On("SearchUserFilterTemplate").Return("(uid=%s)")
	adapter.On("UserAttrs").Return([]string{"cn"})
	adapter.On("SearchUserGroupsFilterTemplate").Return("(&(objectClass=group)(member=%s))")
	adapter.On("SearchUserGroupsFilterTemplateArgs", mock.Anything).
		Return([]any{"uid=jdoe,dc=example,dc=com"})

	connMock := new(mocks.MockLDAPConn)
	connMock.On("Search", mock.Anything).Return(&ldap.SearchResult{Entries: []*ldap.Entry{
		newLDAPEntry("uid=jdoe,dc=example,dc=com", nil),
	}}, nil).Once()
	connMock.On("Search", mock.MatchedBy(func(req *ldap.SearchRequest) bool {
		return req.BaseDN == "dc=example,dc=com" &&
			req.Filter == "(&(objectClass=group)(member=uid=jdoe,dc=example,dc=com))" &&
			req.Scope == ldap.ScopeWholeSubtree &&
			req.TimeLimit == constants.DefaultSearchTimeLimit &&
			len(req.Attributes) == 1 && req.Attributes[0] == "cn"
	})).Return(&ldap.SearchResult{Entries: []*ldap.Entry{}}, nil).Once()

	conn := newTestConnection(adapter, connMock)
	_, err := conn.GetUserGroups("jdoe", "dc=example,dc=com")
	assert.NoError(t, err)
	connMock.AssertExpectations(t)
}

// ---------- GetOUUsers ----------

func TestGetOUUsers_Success(t *testing.T) {
	adapter := new(mocks.MockCatalogAdapter)
	adapter.On("UserObjectFilter").Return("(objectClass=user)")
	adapter.On("UserAttrs").Return([]string{"cn", "mail"})

	connMock := new(mocks.MockLDAPConn)
	connMock.On("Search", mock.Anything).Return(&ldap.SearchResult{Entries: []*ldap.Entry{
		newLDAPEntry("cn=u1,ou=people,dc=example,dc=com", map[string][]string{
			"cn":   {"User One"},
			"mail": {"u1@example.com"},
		}),
		newLDAPEntry("cn=u2,ou=people,dc=example,dc=com", map[string][]string{
			"cn":   {"User Two"},
			"mail": {"u2@example.com"},
		}),
	}}, nil).Once()

	conn := newTestConnection(adapter, connMock)
	users, err := conn.GetOUUsers("ou=people,dc=example,dc=com")

	assert.NoError(t, err)
	assert.Len(t, users, 2)
	assert.Equal(t, "cn=u1,ou=people,dc=example,dc=com", users[0].DN)
	assert.Equal(t, "cn=u2,ou=people,dc=example,dc=com", users[1].DN)
}

func TestGetOUUsers_NilConnection(t *testing.T) {
	conn := &LDAPConnection{catalogAdapter: new(mocks.MockCatalogAdapter)}
	users, err := conn.GetOUUsers("ou=people,dc=example,dc=com")

	assert.Nil(t, users)
	assert.EqualError(t, err, "connection not initialized")
}

func TestGetOUUsers_EmptyOU(t *testing.T) {
	adapter := new(mocks.MockCatalogAdapter)
	adapter.On("UserObjectFilter").Return("(objectClass=user)")
	adapter.On("UserAttrs").Return([]string{"cn"})

	connMock := new(mocks.MockLDAPConn)
	connMock.On("Search", mock.Anything).
		Return(&ldap.SearchResult{Entries: []*ldap.Entry{}}, nil).Once()

	conn := newTestConnection(adapter, connMock)
	users, err := conn.GetOUUsers("ou=empty,dc=example,dc=com")

	assert.NoError(t, err)
	assert.NotNil(t, users)
	assert.Empty(t, users)
}

func TestGetOUUsers_SearchError(t *testing.T) {
	adapter := new(mocks.MockCatalogAdapter)
	adapter.On("UserObjectFilter").Return("(objectClass=user)")
	adapter.On("UserAttrs").Return([]string{"cn"})

	connMock := new(mocks.MockLDAPConn)
	connMock.On("Search", mock.Anything).
		Return(nil, errors.New("ou search failed")).Once()

	conn := newTestConnection(adapter, connMock)
	users, err := conn.GetOUUsers("ou=people,dc=example,dc=com")

	assert.Nil(t, users)
	assert.EqualError(t, err, "unsuccessful ou users search: ou search failed")
}

func TestGetOUUsers_VerifiesSearchRequest(t *testing.T) {
	adapter := new(mocks.MockCatalogAdapter)
	adapter.On("UserObjectFilter").Return("(objectClass=user)")
	adapter.On("UserAttrs").Return([]string{"cn", "mail"})

	connMock := new(mocks.MockLDAPConn)
	connMock.On("Search", mock.MatchedBy(func(req *ldap.SearchRequest) bool {
		return req.BaseDN == "ou=people,dc=example,dc=com" &&
			req.Filter == "(objectClass=user)" &&
			req.Scope == ldap.ScopeWholeSubtree &&
			req.TimeLimit == constants.DefaultSearchTimeLimit &&
			len(req.Attributes) == 2
	})).Return(&ldap.SearchResult{Entries: []*ldap.Entry{}}, nil).Once()

	conn := newTestConnection(adapter, connMock)
	_, err := conn.GetOUUsers("ou=people,dc=example,dc=com")
	assert.NoError(t, err)
	connMock.AssertExpectations(t)
}
