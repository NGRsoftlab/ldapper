// Copyright 2020-2026 NGR Softlab
package interfaces

import (
	"crypto/tls"

	"github.com/go-ldap/ldap/v3"
)

type LDAPConn interface {
	StartTLS(config *tls.Config) error
	Bind(username, password string) error
	Search(request *ldap.SearchRequest) (*ldap.SearchResult, error)
	Close() error
}
