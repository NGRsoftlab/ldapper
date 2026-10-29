// Copyright 2020-2026 NGR Softlab
package ldapper

import (
	"errors"
	"fmt"

	"github.com/go-ldap/ldap/v3"

	"github.com/NGRsoftlab/ldapper/constants"
	"github.com/NGRsoftlab/ldapper/types"
)

// SEARCH METHODS

func (conn *LDAPConnection) CustomSearch(searchRequest *ldap.SearchRequest) (*ldap.SearchResult, error) {
	if conn.connection == nil {
		return nil, errors.New("connection not initialized")
	}

	return conn.connection.Search(searchRequest)
}

func (conn *LDAPConnection) GetUser(username, baseDN string) (*types.LDAPUser, error) {
	if conn.connection == nil {
		return nil, errors.New("connection not initialized")
	}

	filter := fmt.Sprintf(conn.catalogAdapter.SearchUserFilterTemplate(), username)
	attributes := conn.catalogAdapter.UserAttrs()

	// TODO: think about limits (search size and timeout)
	searchRequest := ldap.NewSearchRequest(
		baseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, constants.DefaultSearchTimeLimit, false,
		filter,
		attributes,
		nil,
	)

	searchResult, err := conn.connection.Search(searchRequest)
	if err != nil {
		return nil, fmt.Errorf("unsuccessful user search: %s", err.Error())
	}

	if len(searchResult.Entries) < 1 {
		return nil, errors.New("user does not exist")
	}

	if len(searchResult.Entries) > 1 {
		return nil, errors.New("too many entries returned")
	}

	user := &types.LDAPUser{
		DN:         searchResult.Entries[0].DN,
		Attributes: map[string][]string{},
	}

	for _, attr := range conn.catalogAdapter.UserAttrs() {
		user.Attributes[attr] = searchResult.Entries[0].GetAttributeValues(attr)
	}

	return user, nil
}

func (conn *LDAPConnection) GetUserGroups(username, baseDN string) ([]string, error) {
	if conn.connection == nil {
		return nil, errors.New("connection not initialized")
	}

	user, err := conn.GetUser(username, baseDN)
	if err != nil {
		return nil, err
	}

	// TODO: think about limits (search size and timeout)
	searchRequest := ldap.NewSearchRequest(
		baseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, constants.DefaultSearchTimeLimit, false,
		fmt.Sprintf(conn.catalogAdapter.SearchUserGroupsFilterTemplate(), conn.catalogAdapter.SearchUserGroupsFilterTemplateArgs(*user)...),
		[]string{"cn"},
		nil,
	)

	searchResult, err := conn.connection.Search(searchRequest)
	if err != nil {
		return nil, fmt.Errorf("unsuccessful user groups search: %s", err.Error())
	}

	groups := make([]string, 0)
	for _, entry := range searchResult.Entries {
		groups = append(groups, entry.GetAttributeValues("cn")...)
	}

	return groups, nil
}

func (conn *LDAPConnection) GetOUUsers(ou string) ([]*types.LDAPUser, error) {
	if conn.connection == nil {
		return nil, errors.New("connection not initialized")
	}

	res := make([]*types.LDAPUser, 0)

	filter := conn.catalogAdapter.UserObjectFilter()
	attributes := conn.catalogAdapter.UserAttrs()

	// TODO: think about limits (search size and timeout)
	searchRequest := ldap.NewSearchRequest(
		ou,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, constants.DefaultSearchTimeLimit, false,
		filter,
		attributes,
		nil,
	)

	searchResult, err := conn.connection.Search(searchRequest)
	if err != nil {
		return nil, fmt.Errorf("unsuccessful ou users search: %s", err.Error())
	}

	for _, entry := range searchResult.Entries {
		user := &types.LDAPUser{
			DN:         entry.DN,
			Attributes: map[string][]string{},
		}

		for _, attr := range conn.catalogAdapter.UserAttrs() {
			user.Attributes[attr] = entry.GetAttributeValues(attr)
		}

		res = append(res, user)
	}

	return res, err
}
