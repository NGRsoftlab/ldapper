// Copyright 2020-2026 NGR Softlab
package ldapper

import (
	"crypto/tls"
	"errors"
	"fmt"
	"strings"

	"github.com/go-ldap/ldap/v3"
)

type LDAPConn interface {
	StartTLS(config *tls.Config) error
	Bind(username, password string) error
	Search(request *ldap.SearchRequest) (*ldap.SearchResult, error)
	Close() error
}

type LDAPConnection struct {
	catalogAdapter  CatalogAdapter
	connection      LDAPConn
	isAuthenticated bool
	bindUser        string
	bindPassword    string
}

// TODO: add many hosts support
func NewConnection(
	host string,
	port uint,
	useSSL bool,
	skipTLS bool,
	tlsCfg *tls.Config,
	catalogAdapter CatalogAdapter) (*LDAPConnection, error) {

	var connection *ldap.Conn
	var err error

	if tlsCfg == nil && (!skipTLS || useSSL) {
		return nil, errors.New("nil tls config passed")
	}

	if catalogAdapter == nil {
		return nil, errors.New("nil catalog adapter passed")
	}

	if !useSSL {
		connection, err = ldap.DialURL(fmt.Sprintf(ldapURITemplate, host, port))
		if err != nil {
			return nil, fmt.Errorf("unsuccessful dial: %s", err.Error())
		}

		if !skipTLS {
			err = connection.StartTLS(tlsCfg)
			if err != nil {
				_ = connection.Close()
				return nil, fmt.Errorf("unsuccessful start tls: %s", err.Error())
			}
		}
	} else {
		connection, err = ldap.DialURL(fmt.Sprintf(ldapsURITemplate, host, port), ldap.DialWithTLSConfig(tlsCfg))
		if err != nil {
			return nil, fmt.Errorf("unsuccessful dial: %s", err.Error())
		}
	}

	return &LDAPConnection{
		catalogAdapter: catalogAdapter,
		connection:     connection,
	}, nil
}

// TODO: add many hosts support
// NB: if you need connection for futher catalog reading - pass read access granted user credentials here
func NewAuthenticatedConnection(
	username, password, baseDN string,
	host string,
	port uint,
	useSSL bool,
	skipTLS bool,
	tlsCfg *tls.Config,
	catalogAdapter CatalogAdapter) (*LDAPConnection, *LDAPUser, error) {

	if username == "" || password == "" {
		return nil, nil, errors.New("empty username/password passed")
	}

	connection, err := NewConnection(host, port, useSSL, skipTLS, tlsCfg, catalogAdapter)
	if err != nil {
		return nil, nil, err
	}

	user, err := connection.AuthenticateConn(username, password, baseDN)
	if err != nil {
		return nil, nil, err
	}

	return connection, user, nil
}

// NB: if you need connection for futher catalog reading - pass read access granted user credentials here
func (conn *LDAPConnection) AuthenticateConn(username, password, baseDN string) (*LDAPUser, error) {
	if conn.connection == nil {
		return nil, errors.New("connection not initialized")
	}

	// user is ok check
	user, err := conn.GetUser(username, baseDN)
	if err != nil {
		return nil, err
	}

	// bind check
	err = conn.connection.Bind(user.DN, password)
	if err != nil {
		// NB: no err value return - it can contain sensitive data
		return user, errors.New("unsuccessful bind with passed bind credentials")
	}

	conn.isAuthenticated = true
	conn.bindUser = user.DN
	conn.bindPassword = password

	return user, nil
}

// NB: can not be used with non-authenticated conn or with non-read-access-granted bindUser in conn cfg
func (conn *LDAPConnection) AuthenticatedUser(username, password, baseDN string) (*LDAPUser, error) {
	if conn.connection == nil {
		return nil, errors.New("connection not initialized")
	}

	if !conn.isAuthenticated {
		return nil, errors.New("connection not authenticated")
	}

	// user is ok check
	user, err := conn.GetUser(username, baseDN)
	if err != nil {
		return nil, err
	}

	// bind check
	err = conn.connection.Bind(user.DN, password)
	if err != nil {
		// NB: no err value return - it can contain sensitive data
		return user, errors.New("unsuccessful bind with passed user credentials")
	}

	// rebind onto read access granted bind user
	err = conn.connection.Bind(conn.bindUser, conn.bindPassword)
	if err != nil {
		// NB: no err value return - it can contain sensitive data
		return user, errors.New("unsuccessful rebind with bind-config credentials")
	}

	return user, nil
}

func (conn *LDAPConnection) Close() {
	if conn.connection != nil {
		err := conn.connection.Close()
		conn.connection = nil
		if err != nil {
			return
		}
	}
}

// SEARCH METHODS

func (conn *LDAPConnection) CustomSearch(searchRequest *ldap.SearchRequest) (*ldap.SearchResult, error) {
	if conn.connection == nil {
		return nil, errors.New("connection not initialized")
	}

	return conn.connection.Search(searchRequest)
}

func (conn *LDAPConnection) GetUser(username, baseDN string) (*LDAPUser, error) {
	if conn.connection == nil {
		return nil, errors.New("connection not initialized")
	}

	filter := fmt.Sprintf(conn.catalogAdapter.SearchUserFilterTemplate(), username)
	attributes := conn.catalogAdapter.UserAttrs()

	// TODO: think about limits
	searchRequest := ldap.NewSearchRequest(
		baseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, defaultSearchTimeLimit, false,
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

	user := &LDAPUser{
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

	// TODO: think about limits
	searchRequest := ldap.NewSearchRequest(
		baseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, defaultSearchTimeLimit, false,
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

func (conn *LDAPConnection) GetOUUsers(ou string) ([]*LDAPUser, error) {
	if conn.connection == nil {
		return nil, errors.New("connection not initialized")
	}

	res := make([]*LDAPUser, 0)

	filter := conn.catalogAdapter.UserObjectFilter()
	attributes := conn.catalogAdapter.UserAttrs()

	// TODO: think about limits
	searchRequest := ldap.NewSearchRequest(
		ou,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, defaultSearchTimeLimit, false,
		filter,
		attributes,
		nil,
	)

	searchResult, err := conn.connection.Search(searchRequest)
	if err != nil {
		return nil, fmt.Errorf("unsuccessful ou users search: %s", err.Error())
	}

	for _, entry := range searchResult.Entries {
		user := &LDAPUser{
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

// CATALOG TREE DISCOVERY METHODS

// TODO: make controlable depth
// GetCatalogTree read catalog tree (with depth 2)
func (conn *LDAPConnection) GetCatalogTree(baseDn string) (CatalogTree, error) {
	res := CatalogTree{Tree: make([]*OUInfo, 0)}

	firstLevel, err := conn.GetRootOUs(baseDn)
	if err != nil {
		return res, err
	}

	if firstLevel != nil {
		_ = conn.GetRecursiveOUSearchResult(&firstLevel, 2)
		res.Tree = firstLevel
	}

	return res, nil
}

func (conn *LDAPConnection) GetRootOUs(rootDN string) ([]*OUInfo, error) {
	res := make([]*OUInfo, 0)

	filter := conn.catalogAdapter.OUObjectFilter()
	attributes := conn.catalogAdapter.OUAttrs()

	// TODO: think about limits
	searchRequest := ldap.NewSearchRequest(
		rootDN,
		ldap.ScopeSingleLevel, ldap.NeverDerefAliases, 0, defaultSearchTimeLimit, false,
		filter,
		attributes,
		nil,
	)

	searchResult, err := conn.connection.Search(searchRequest)
	if err != nil {
		return res, fmt.Errorf("unsuccessful ou search: %s", err.Error())
	}

	for _, entry := range searchResult.Entries {
		res = append(res, conn.catalogAdapter.OUInfoFromEntry(*entry))
	}

	return res, nil
}

// TODO: make controlable search depth
func (conn *LDAPConnection) GetRecursiveOUSearchResult(prevLevel *[]*OUInfo, level int) *[]*OUInfo {
	nextLevel := make([]*OUInfo, 0)

	for k, v := range *prevLevel {
		nextLevel, _ := conn.GetSubOUs(v.DN, ldap.ScopeSingleLevel)
		if nextLevel != nil {
			if level < defaultSearchDepth {
				conn.GetRecursiveOUSearchResult(&nextLevel, level+1)
			}
			(*prevLevel)[k].Children = nextLevel
		}
	}
	return &nextLevel
}

func (conn *LDAPConnection) GetSubOUs(group string, level int) (res []*OUInfo, err error) {
	res = make([]*OUInfo, 0)

	filter := conn.catalogAdapter.OUObjectFilter()
	attributes := conn.catalogAdapter.OUAttrs()

	// TODO: think about limits
	searchRequest := ldap.NewSearchRequest(
		group,
		level, ldap.NeverDerefAliases, 0, defaultSearchTimeLimit, false,
		filter,
		attributes,
		nil,
	)

	searchResult, err := conn.connection.Search(searchRequest)
	if err != nil {
		return res, fmt.Errorf("unsuccessful sub ou search: %s", err.Error())
	}

	for _, entry := range searchResult.Entries {
		info := conn.catalogAdapter.OUInfoFromEntry(*entry)

		info.Children = make([]*OUInfo, 0)

		if strings.HasSuffix(info.DN, ","+group) && info.DN != group {
			res = append(res, info)
		}
	}

	return res, nil
}
