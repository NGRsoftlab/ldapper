// Copyright 2020-2026 NGR Softlab
package ldapper

import (
	"fmt"

	"github.com/go-ldap/ldap/v3"

	"github.com/NGRsoftlab/ldapper/constants"
)

// SEARCH METHODS

// lookupKind names the entity being looked up — used only for error messages.
type lookupKind string

const (
	kindUser  lookupKind = "user"
	kindGroup lookupKind = "group"
	kindOU    lookupKind = "ou"
)

// searchSingleEntryLocked performs a "single object by unique key" lookup:
// validates inputs, builds the filter from the adapter template, and enforces
// the 0 / 1 / >1 contract using SizeLimit=2. Caller must hold opMu.
func (ldapper *LDAPper) searchSingleEntryLocked(
	kind lookupKind,
	name, baseDN, filterTemplate string,
	attributes []string,
) (*ldap.Entry, error) {

	if err := ldapper.requireConnLocked(); err != nil {
		return nil, err
	}
	if err := validateBaseDN(baseDN); err != nil {
		return nil, err
	}
	if name == "" {
		return nil, fmt.Errorf("%w: empty %s name", ErrInvalidArgument, kind)
	}

	filter := fmt.Sprintf(filterTemplate, ldap.EscapeFilter(name))

	// NB: SizeLimit=2 is enough to detect duplicates without over-fetching,
	// and is independent of user-configured searchLimits.
	req := ldap.NewSearchRequest(
		baseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		2, ldapper.searchLimits.TimeLimit, false, filter, attributes, nil,
	)

	// searchSingleEntryLocked — around the Search call:
	res, err := ldapper.withTimeoutResult(ldapper.opTimeouts.Search, func() (*ldap.SearchResult, error) {
		return ldapper.connection.Search(req)
	})
	if err != nil {
		return nil, fmt.Errorf("%s search: %w", kind, classifyLDAPError(err))
	}

	switch {
	case len(res.Entries) == 0:
		return nil, fmt.Errorf("%w: %s %q does not exist", ErrNotFound, kind, name)
	case len(res.Entries) > 1:
		return nil, fmt.Errorf("%w: too many entries for %s %q", ErrAmbiguousResult, kind, name)
	}
	return res.Entries[0], nil
}

// newSearchRequest builds a search request using connection-level limits.
// All search methods should use it instead of calling ldap.NewSearchRequest directly.
func (ldapper *LDAPper) newSearchRequest(
	baseDN string,
	scope int,
	derefAliases int,
	typesOnly bool,
	filter string,
	attributes []string,
	controls []ldap.Control,
) *ldap.SearchRequest {
	return ldap.NewSearchRequest(
		baseDN,
		scope,
		derefAliases,
		ldapper.searchLimits.SizeLimit,
		ldapper.searchLimits.TimeLimit,
		typesOnly,
		filter,
		attributes,
		controls,
	)
}

// searchPaged executes a search and follows the paging control until all
// pages have been retrieved. If the server does not honor paging, the
// behavior depends on SearchLimits.RequirePaging: when false, the first
// page is returned as-is (backward compatible); when true, ErrPartialResult
// is returned because the result may have been truncated by the server.
//
// Caller must hold opMu. The lock is held across all pages because the
// paging cookie is bound to the current connection and interleaving with
// other operations would corrupt the protocol stream.
//
// Budgets:
//   - MaxPages        bounds the number of successful Search calls.
//   - MaxEntries      bounds the total accumulated entries.
//   - RequirePaging   makes a missing paging control fatal (ErrPartialResult).
//   - Repeated non-empty cookies are treated as a runaway server.
func (ldapper *LDAPper) searchPaged(
	baseDN string,
	scope int,
	derefAliases int,
	typesOnly bool,
	filter string,
	attributes []string,
	controls []ldap.Control,
) ([]*ldap.Entry, error) {

	if err := ldapper.requireConnLocked(); err != nil {
		return nil, err
	}

	if err := validateBaseDN(baseDN); err != nil {
		return nil, err
	}

	pagingControl := ldap.NewControlPaging(constants.DefaultCatalogSearchPageSize)

	// Preserve caller-provided controls and add the paging control on top.
	pageControls := make([]ldap.Control, 0, len(controls)+1)
	pageControls = append(pageControls, controls...)
	pageControls = append(pageControls, pagingControl)

	var (
		allEntries  []*ldap.Entry
		pageCount   int
		seenCookies = make(map[string]struct{})
	)

	for {
		pageCount++
		if maximum := ldapper.searchLimits.MaxPages; maximum > 0 && pageCount > maximum {
			return allEntries, fmt.Errorf("%w: page budget exceeded (%d pages)",
				ErrPartialResult, pageCount-1)
		}

		req := ldapper.newSearchRequest(baseDN, scope, derefAliases, typesOnly,
			filter, attributes, pageControls)

		result, err := ldapper.withTimeoutResult(ldapper.opTimeouts.Search, func() (*ldap.SearchResult, error) {
			return ldapper.connection.Search(req)
		})
		if err != nil {
			// NB: paging is honored by most servers; when it is not and the
			// server returns a size-limit error, preserve what we already
			// fetched so callers can decide how to proceed.
			if ldap.IsErrorWithCode(err, ldap.LDAPResultSizeLimitExceeded) {
				if len(allEntries) > 0 {
					return allEntries, fmt.Errorf("%w: %w", ErrPartialResult, err)
				}
				return nil, fmt.Errorf("%w: %w", ErrPartialResult, err)
			}
			return nil, err
		}

		allEntries = append(allEntries, result.Entries...)

		if maximum := ldapper.searchLimits.MaxEntries; maximum > 0 && len(allEntries) > maximum {
			// Truncate to the budget and signal the loss. The caller can
			// still inspect the partial slice; the server-side cursor is
			// abandoned with the connection (no rollback required).
			return allEntries[:maximum], fmt.Errorf(
				"%w: entry budget exceeded (%d > %d)",
				ErrPartialResult, len(allEntries), maximum)
		}

		ctrl := ldap.FindControl(result.Controls, ldap.ControlTypePaging)
		if ctrl == nil {
			// Server did not honor paging. If the caller requires paging, the
			// result may be truncated by the server's own size limit — signal it
			// rather than silently returning a potentially incomplete slice.
			if ldapper.searchLimits.RequirePaging {
				return allEntries, fmt.Errorf(
					"%w: server did not honor paging; result may be incomplete",
					ErrPartialResult)
			}
			break
		}

		next, ok := ctrl.(*ldap.ControlPaging)
		if !ok {
			break // unexpected control type: stop rather than loop forever
		}

		if len(next.Cookie) == 0 {
			break // empty cookie = last page
		}

		// NB: a repeated non-empty cookie means the server is not making
		// progress. Treat it as a runaway response and return what we have.
		key := string(next.Cookie)
		if _, dup := seenCookies[key]; dup {
			return allEntries, fmt.Errorf(
				"%w: paging server returned a repeated cookie", ErrPartialResult)
		}
		seenCookies[key] = struct{}{}

		pagingControl.SetCookie(next.Cookie)
	}

	return allEntries, nil
}

// CustomSearchPaged is a public proxy for searchPaged that accepts a
// pre-built ldap.SearchRequest. Automatic paging is applied on top of the
// request's controls.
// NB: just public proxy-method for ldapper.searchPaged call with *ldap.SearchRequest param, automatic paging
func (ldapper *LDAPper) CustomSearchPaged(searchRequest *ldap.SearchRequest) ([]*ldap.Entry, error) {
	if searchRequest == nil {
		return nil, fmt.Errorf("%w: nil search request", ErrInvalidArgument)
	}

	ldapper.opMu.Lock()
	defer ldapper.opMu.Unlock()

	return ldapper.searchPaged(
		searchRequest.BaseDN,
		searchRequest.Scope,
		searchRequest.DerefAliases,
		searchRequest.TypesOnly,
		searchRequest.Filter,
		searchRequest.Attributes,
		searchRequest.Controls)
}

// CustomSearch executes the given search request as-is.
// No paging, no search-limit overrides, no DN validation are applied —
// the caller is responsible for the request semantics.
// Use CustomSearchPaged if you want automatic paging.
func (ldapper *LDAPper) CustomSearch(searchRequest *ldap.SearchRequest) (*ldap.SearchResult, error) {
	ldapper.opMu.Lock()
	defer ldapper.opMu.Unlock()

	if err := ldapper.requireConnLocked(); err != nil {
		return nil, err
	}

	if searchRequest == nil {
		return nil, fmt.Errorf("%w: nil search request", ErrInvalidArgument)
	}

	res, err := ldapper.withTimeoutResult(ldapper.opTimeouts.Search, func() (*ldap.SearchResult, error) {
		return ldapper.connection.Search(searchRequest)
	})
	if err != nil {
		return nil, fmt.Errorf("custom search: %w", classifyLDAPError(err))
	}

	return res, nil
}
