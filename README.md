# LDAPper

[![Go Reference](https://pkg.go.dev/badge/github.com/NGRsoftlab/ldapper.svg)](https://pkg.go.dev/github.com/NGRsoftlab/ldapper)

A lightweight, adapter-based LDAP client for Go. LDAPper wraps
[`go-ldap/ldap`](https://github.com/go-ldap/ldap) with:

- **Multi-host failover** and transparent reconnection.
- **Pluggable catalog adapters** so the same API works against Microsoft
  Active Directory, OpenLDAP, ALD Pro, FreeIPA, and any other directory you
  write an adapter for.
- **Connection-level search limits** so callers don't pass `SizeLimit` /
  `TimeLimit` on every query.
- **Efficient catalog tree discovery** — a single paged subtree search,
  assembled into an `OU` tree on the client, with optional depth trimming.
- **End-to-end integration tests** for every shipped adapter, running
  against real directory servers in Docker (OpenLDAP, Samba 4 AD DC,
  FreeIPA, and OpenLDAP-with-ALDPro-schema).

---

## Table of contents

- [Installation](#installation)
- [Quick start](#quick-start)
- [Architecture](#architecture)
- [Core concepts](#core-concepts)
  - [Connections](#connections)
  - [Adapters](#adapters)
  - [Search limits](#search-limits)
- [Shipped adapters](#shipped-adapters)
- [API overview](#api-overview)
  - [Authentication](#authentication)
  - [Searching](#searching)
  - [Catalog tree discovery](#catalog-tree-discovery)
  - [Health checks & reconnection](#health-checks--reconnection)
- [Writing your own adapter](#writing-your-own-adapter)
- [Configuration & tuning](#configuration--tuning)
- [Testing](#testing)
- [License](#license)

---

## Installation

```bash
go get github.com/NGRsoftlab/ldapper
```

Requires Go 1.21+ (module tested against Go 1.26). Depends on
`github.com/go-ldap/ldap/v3`. Integration tests additionally require
`github.com/testcontainers/testcontainers-go` and a running Docker daemon.

---

## Quick start

```go
package main

import (
	"crypto/tls"
	"log"

	"github.com/NGRsoftlab/ldapper"
	"github.com/NGRsoftlab/ldapper/adapters"
)

func main() {
	adapter := adapters.MSADAdapter{}

	conn, user, err := ldapper.NewAuthenticatedConnection(
		"svc-reader@corp.example.com", "secret", // bind credentials
		"DC=corp,DC=example,DC=com",             // base DN for user search
		[]string{"dc1.corp.example.com", "dc2.corp.example.com"}, // hosts
		636,        // port
		true,       // useSSL (LDAPS)
		false,      // skipTLS (irrelevant when useSSL is true)
		&tls.Config{MinVersion: tls.VersionTLS12},
		adapter,
		ldapper.WithSearchLimits(0, 30), // no size limit, 30s time limit
	)
	if err != nil {
		log.Fatalf("connect: %v", err)
	}
	defer conn.Close()

	log.Printf("authenticated as %s", user.DN)

	// Fetch a user by sAMAccountName.
	u, err := conn.GetUser("jdoe", "DC=corp,DC=example,DC=com")
	if err != nil {
		log.Fatalf("get user: %v", err)
	}

	info := adapter.GetNormalizedUserInfo(*u)
	log.Printf("%s <%s>", info.CommonName, info.Mail)
}
```

---

## Architecture

LDAPper is intentionally small and layered. Only two things are pluggable
(`interfaces.LDAPConn` and `interfaces.CatalogAdapter`); everything else is
plain structs and functions.

### Layers

```
┌──────────────────────────────────────────────────────────────────┐
│  User code                                                       │
│    conn, _ := ldapper.NewAuthenticatedConnection(...)            │
│    conn.GetUser(...)  /  conn.GetCatalogTree(...)  /  ...        │
└──────────────────────────────┬───────────────────────────────────┘
                               │
┌──────────────────────────────▼───────────────────────────────────┐
│  LDAPper — public API                                            │
│                                                                  │
│  ldapper.go                        connection lifecycle:        │
│                                    dial / failover, auth,        │
│                                    IsAlive / Reconnect / Close   │
│  ldapper_search.go                 user / group / OU-user search │
│  ldapper_search_params.go          SearchLimits + newSearchRequest│
│  ldapper_catalog_tree_discovery.go paged subtree + tree builder  │
└──────────────┬───────────────────────────────────┬───────────────┘
               │                                   │
     uses      │                                   │  uses
               ▼                                   ▼
┌──────────────────────────────┐    ┌──────────────────────────────┐
│  interfaces.LDAPConn         │    │  interfaces.CatalogAdapter   │
│  (thin subset of go-ldap)    │    │  (schema-specific glue)      │
│                              │    │                              │
│  StartTLS / Bind / Search /  │    │  Filters / Attrs / Casts     │
│  IsClosing / Close           │    │                              │
└──────────────┬───────────────┘    └──────────────┬───────────────┘
               │                                   │
   prod: *ldap.Conn                  prod: adapters.{MSAD, OPENLDAP,
   test: mocks.MockLDAPConn                ALDRPO, FREEIPA}Adapter
                                     test: testCatalogAdapter
                                           (see test_catalog_adapter_test.go)

                               │
┌──────────────────────────────▼───────────────────────────────────┐
│  go-ldap/ldap/v3                                                 │
└──────────────────────────────┬───────────────────────────────────┘
                               │
                          LDAP server
```

The two interfaces are the only seams:

- **`interfaces.LDAPConn`** is a 5-method subset of `*ldap.Conn`. Production
  uses the real `*ldap.Conn`; tests inject `mocks.MockLDAPConn`.
- **`interfaces.CatalogAdapter`** is the *only* place LDAPper knows anything
  about directory schema. All filters, attribute lists, and value casts go
  through it.

### `LDAPper` struct

```
LDAPper
├── catalogAdapter  interfaces.CatalogAdapter   schema-specific behavior
├── connection      interfaces.LDAPConn         active network connection
│
├── isAuthenticated bool                        set by AuthenticateConn
├── bindUser        string                      stored for re-bind on
├── bindPassword    string                        Reconnect / AuthenticateUser
├── bindDN          string                      base DN stored by
│                                                 AuthenticateConn, used
│                                                 internally by AuthenticateUser
│
├── hosts           []string                    failover list (≤ 50)
├── currentHost     string                      host of the active connection
├── port            uint
│
├── useSSL          bool                        LDAPS vs plain LDAP
├── skipTLS         bool                        disable StartTLS upgrade
├── tlsCfg          *tls.Config
│
└── searchLimits    SearchLimits                injected via newSearchRequest
```

Every search method goes through `newSearchRequest(...)`, which injects
`searchLimits`. Changing limits at runtime (`SetSearchLimits`) is therefore
a single assignment with no plumbing.

`bindDN` is a subtle but useful field: `AuthenticateConn` records the
`baseDN` argument so that later calls to `AuthenticateUser(username, password)`
can look the user up without the caller having to pass the base DN again.

### Search flow (`GetUser` as example)

```
conn.GetUser("jdoe", baseDN)
        │
        ├── catalogAdapter.SearchUserFilterTemplate()
        │       → "(uid=%s)" → fmt.Sprintf → "(uid=jdoe)"
        ├── catalogAdapter.UserAttrs()
        │       → []string{"cn", "mail", ...}
        │
        ▼
   newSearchRequest(baseDN, WholeSubtree, NeverDerefAliases,
                    false, filter, attrs, nil)
        │
        │  injects conn.searchLimits.{SizeLimit, TimeLimit}
        ▼
   conn.connection.Search(req)  ─────►  LDAP server
        │
        ▼
   0 entries   → error "user does not exist"
   1 entry     → build types.LDAPUser{DN, Attributes}
   >1 entries  → error "too many entries returned"
```

### Catalog tree flow (`GetCatalogTree`)

```
conn.GetCatalogTree(baseDN, maxDepth)
        │
        ▼
   loop:
     Search(baseDN, WholeSubtree, paging=1000)
       │
       ├── server echoes ControlPaging  →  read cookie
       │
       ▼
     next request with cookie  …  until empty cookie
        │
        ▼
   allEntries []*ldap.Entry
        │
        ▼
   for each entry:
       catalogAdapter.OUInfoFromEntry(entry)
       drop if !baseDN.AncestorOf(entry.DN)
       byDN[info.DN] = info
        │
        ▼
   attach each node to parentDNOf(info.DN)  →  tree roots
        │
        ▼
   if maxDepth > 0:  trimDepth(tree, maxDepth)
        │
        ▼
   types.CatalogTree{Tree: [...]}
```

This is the whole reason `GetCatalogTree` is O(1) round-trips instead of
O(N): the server streams pages of the subtree, and the parent-child wiring
is done locally in `O(N)` with a single `map[DN]*OUInfo`.

---

## Core concepts

### Connections

`LDAPper` is created with one of two constructors:

```go
// Unauthenticated: no bind performed, suitable for directories that allow
// anonymous reads or when you only need to dial.
NewConnection(hosts []string, port uint, useSSL, skipTLS bool,
              tlsCfg *tls.Config, adapter interfaces.CatalogAdapter,
              opts ...Option) (*LDAPper, error)

// Authenticated: dials, then binds as `username` and looks the user up
// via the adapter's user filter to confirm the credentials.
NewAuthenticatedConnection(username, password, baseDN string,
                           hosts []string, port uint,
                           useSSL, skipTLS bool, tlsCfg *tls.Config,
                           adapter interfaces.CatalogAdapter,
                           opts ...Option) (*LDAPper, *types.LDAPUser, error)
```

Highlights:

- **Host failover** — hosts are tried in order until one accepts the
  connection. The maximum list length is `constants.DefaultMaxHostsLength`
  (50) — a guard against accidentally passing a million hosts.
- **TLS** — either native LDAPS (`useSSL = true`) or StartTLS
  (`skipTLS = false`). A non-nil `*tls.Config` is required whenever TLS is
  used.
- **`dialURL` is a package-level variable** (`ldap.DialURL`) so tests can
  swap it out via `withMockDialURL(...)` without touching production code.

### Adapters

All directory-specific behavior lives in an adapter — a value that
implements `interfaces.CatalogAdapter`:

```go
type CatalogAdapter interface {
    // Cast / convert
    GetNormalizedUserInfo(ldapUser types.LDAPUser) *types.UserNormalizedInfo
    OUInfoFromEntry(entry ldap.Entry) *types.OUInfo

    // Object-class filters
    UserObjectFilter()  string
    GroupObjectFilter() string
    OUObjectFilter()    string

    // Search filter templates
    SearchUserFilterTemplate()       string
    SearchUserGroupsFilterTemplate() string
    SearchUserGroupsFilterTemplateArgs(ldapUser types.LDAPUser) []any
    SearchOUFilterTemplate()    string
    SearchGroupFilterTemplate() string

    // Attribute lists
    UserAttrs()  []string
    OUAttrs()    []string
    GroupAttrs() []string
}
```

The adapter is the only place LDAPper assumes anything about schema. See
[Shipped adapters](#shipped-adapters) for the four adapters that ship with
the library.

### Search limits

Every search request is built by a single helper that applies
**connection-level** `SearchLimits{SizeLimit, TimeLimit}`. Callers never
pass these per call:

```go
conn, _ := ldapper.NewConnection(..., ldapper.WithSearchLimits(500, 30))

// Later, temporarily raise limits for one heavy pass:
old := conn.GetSearchLimits()
conn.SetSearchLimits(0, 120)
tree, _ := conn.GetCatalogTree("DC=corp,DC=example,DC=com", 0)
conn.SetSearchLimits(old.SizeLimit, old.TimeLimit)
```

- `SizeLimit == 0` means "server default / no client limit".
- `TimeLimit == 0` means "server default / no client limit".
- Negative values are clamped to `0`.
- `SetSearchLimits` is **not concurrency-safe** — do not call it while
  searches are in flight.

---

## Shipped adapters

| Adapter                     | Directory                          | Notes |
|-----------------------------|------------------------------------|-------|
| `adapters.MSADAdapter`      | Microsoft Active Directory         | Uses `objectCategory`-based filters; recursive group search via the `LDAP_MATCHING_RULE_IN_CHAIN` OID (`1.2.840.113556.1.4.1941`); prefers `thumbnailPhoto` over `jpegPhoto`. |
| `adapters.OPENLDAPAdapter`  | OpenLDAP (and most RFC-4519 dialects) | Handles both `groupOfNames` (via `member`) and `posixGroup` (via `memberUid`); user search keyed by `uid` **or** `entryDN` (single indexed placeholder); address mapped from `postalAddress`. |
| `adapters.ALDRPOAdapter`    | ALD Pro                            | Recognizes `rbta-org-unit` alongside `organizationalUnit`; department mapped from `rbtadp`; two-branch group filter — `member` (DN) for `groupOfNames`/`ipausergroup` **and** `memberUid` (uid) for `posixGroup`. |
| `adapters.FREEIPAAdapter`   | FreeIPA                            | Recognizes `nsContainer` alongside `organizationalUnit`; department intentionally **not** mapped; group lookup matches DN-valued `member`, which `ipa group-add-member` populates on `ipausergroup`/`posixGroup`; FreeIPA-specific attrs `nsAccountLock` and `ipaUniqueID`. |

### Adapter-specific gotchas

- **`MSADAdapter`** — the base DN for search must be a valid AD naming
  context. `GetUser` matches on `sAMAccountName`; the bind DN in
  `NewAuthenticatedConnection` can be a UPN (`user@domain`), not necessarily
  a full DN. Group search uses `LDAP_MATCHING_RULE_IN_CHAIN`, which
  **Samba 4 AD DC** and Microsoft AD both support — OpenLDAP and FreeIPA do
  **not**.
- **`OPENLDAPAdapter`** — the user filter uses the indexed format
  placeholder `%[1]s` so the same argument is substituted into both `uid=`
  and `entryDN=`, allowing lookup by either short name or full DN. Computer
  objects are explicitly excluded. The user-groups filter is a union of two
  branches:
  ```
  (|(&(objectClass=groupOfNames)(member=%s))
    (&(objectClass=posixGroup)(memberUid=%s)))
  ```
  with args `[user.DN, user.uid]`.
- **`ALDRPOAdapter`** — the user-groups filter mirrors OpenLDAP but also
  recognizes `ipausergroup` on the `member` branch:
  ```
  (|(&(|(objectClass=groupOfNames)(objectClass=ipausergroup)(objectClass=posixGroup))(member=%s))
    (&(objectClass=posixGroup)(memberUid=%s)))
  ```
  with args `[user.DN, user.uid]`. Both `groupOfNames`-style (DN-valued
  `member`) and `posixGroup`-style (`memberUid`) memberships are
  discovered end-to-end.
- **`FREEIPAAdapter`** — the user-groups filter is
  ```
  (&(|(objectClass=groupOfNames)(objectClass=posixGroup)(objectClass=ipausergroup))(member=%s))
  ```
  with args `[user.DN]`. FreeIPA's `ipa group-add-member` populates `member`
  (DN-valued) on `ipausergroup`/`posixGroup` entries, so DN-based matching
  works.

All four adapters are stateless and safe to reuse across connections.

### Attribute mapping in `GetNormalizedUserInfo`

Each adapter maps the same `UserNormalizedInfo` fields from different LDAP
attributes. `—` means the field is **hardcoded to empty** in that adapter
(the attribute is not read even if present).

| `UserNormalizedInfo` field | MSAD                     | OpenLDAP           | ALD Pro           | FreeIPA      |
|----------------------------|--------------------------|--------------------|-------------------|--------------|
| `DistinguishedName`        | `distinguishedName`      | `dn`               | `dn`              | `dn`         |
| `CommonName`               | `cn`                     | `cn`               | `cn`              | `cn`         |
| `Mobile`                   | `mobile`                 | `mobile`           | `mobile`          | `mobile`     |
| `Phone`                    | `telephoneNumber`        | `telephoneNumber`  | `telephoneNumber` | `telephoneNumber` |
| `Mail`                     | `mail`                   | `mail`             | `mail`            | `mail`       |
| `Department`               | `department`             | `departmentNumber` | `rbtadp`          | —            |
| `Title`                    | `title`                  | `title`            | `title`           | `title`      |
| `Manager`                  | `manager`                | `manager`          | `manager`         | `manager`    |
| `Photo`                    | `thumbnailPhoto` → `jpegPhoto` | `jpegPhoto`  | `jpegPhoto`       | `jpegPhoto`  |
| `Company`                  | `company`                | —                  | —                 | —            |
| `Country`                  | `co`                     | —                  | `co`              | `co`         |
| `Address`                  | `streetAddress`          | `postalAddress`    | `streetAddress`   | `street`     |
| `City`                     | `l`                      | —                  | `l`               | `l`          |
| `Index`                    | `postalCode`             | —                  | `postalCode`      | `postalCode` |

Key differences to keep in mind when picking an adapter:

- **`DistinguishedName`** — MSAD reads it from the `distinguishedName`
  attribute, all other adapters read it from `dn`.
- **`Department`** — four different sources (`department`,
  `departmentNumber`, `rbtadp`, or none). FreeIPA simply does not map it.
- **`Address`** — MSAD and ALD Pro use `streetAddress`, OpenLDAP uses
  `postalAddress`, FreeIPA uses `street`.
- **`Photo`** — only MSAD falls back from `thumbnailPhoto` to `jpegPhoto`;
  the other three adapters read `jpegPhoto` only and do **not** consult
  `thumbnailPhoto`.
- **`Company` / `Country` / `City` / `Index`** — OpenLDAP hardcodes
  `Company`, `Country`, `City` and `Index` to empty regardless of the entry's
  attributes. If you need them populated against OpenLDAP, write a custom
  adapter that overrides `GetNormalizedUserInfo`.

---

## API overview

### Authentication

```go
// Bind as `username` and store the credentials and base DN for later use.
user, err := conn.AuthenticateConn(username, password, baseDN)

// Check a user's password against an already-authenticated connection,
// then rebind back to the service account.
user, err := conn.AuthenticateUser(username, password)
```

Notes:

- `AuthenticateConn` stores `username`, `password` **and** `baseDN` on the
  connection. The stored `baseDN` (kept in the private `bindDN` field) is
  what `AuthenticateUser` uses internally to look users up — the caller
  does **not** repeat the base DN.
- `AuthenticateUser` requires the connection to have been created via
  `NewAuthenticatedConnection` (or a prior `AuthenticateConn`). The
  connection must have *read* access to look the user up before binding
  as them.
- Error messages intentionally do **not** echo the underlying LDAP error
  text, to avoid leaking credentials in logs.

### Searching

```go
// Escape hatch: build any *ldap.SearchRequest yourself.
res, err := conn.CustomSearch(&ldap.SearchRequest{...})

// Fetch a single user by the adapter's user filter template.
user, err := conn.GetUser("jdoe", baseDN)

// Fetch the CNs of all groups a user belongs to.
groups, err := conn.GetUserGroups("jdoe", baseDN)

// Fetch every user under an OU (subtree search, adapter user filter).
users, err := conn.GetOUUsers("OU=Staff,DC=corp,DC=example,DC=com")
```

`GetUser` returns an error when the filter matches zero or more than one
entry — user lookups are assumed to be unique.

`GetUserGroups` internally calls `GetUser` first, then applies
`catalogAdapter.SearchUserGroupsFilterTemplate()` with
`SearchUserGroupsFilterTemplateArgs(*user)`. Each adapter supplies the right
combination of values (DN for `member`-based schemas, uid for
`memberUid`-based schemas, or both) — callers never need to know the
details.

### Catalog tree discovery

```go
tree, err := conn.GetCatalogTree("DC=corp,DC=example,DC=com", 2)
```

- Performs **one paged subtree search** (`ControlPaging`) and builds the
  `OU` tree on the client, instead of issuing one round-trip per level.
- Filters out entries that are not strict descendants of `baseDn`
  (via `ldap.DN.AncestorOf`) — misbehaving servers and cross-tree
  referrals can't leak foreign entries into the result.
- Skips malformed DNs returned by the server rather than aborting.
- `maxDepth` trims the resulting tree: `0` = no limit, `1` = roots only,
  `2` = roots + first level, etc.

```go
// Only root-level OUs (single-level scope, one round-trip):
roots, err := conn.GetRootOUs("DC=corp,DC=example,DC=com")

// Direct children of an OU:
children, err := conn.GetSubOUs("OU=Staff,DC=corp,DC=example,DC=com",
                                ldap.ScopeSingleLevel)
```

`GetCatalogTree` is the recommended path for large catalogs: it round-trips
once per page, streams results page-by-page, and assembles the tree in
`O(N)` using a `map[DN]*OUInfo` + parent-DN walk.

### Health checks & reconnection

```go
if !conn.IsAlive() {
    _ = conn.Reconnect()
}

// Or the combined form, suitable as a pre-flight check:
if err := conn.EnsureAlive(); err != nil {
    return err
}
```

- `IsAlive` checks the local connection state (`IsClosing`) and issues a
  cheap root-DSE search with hard-coded `SizeLimit=1, TimeLimit=1`. It is
  intentionally independent of the user-configured search limits.
- `Reconnect` closes the current connection, dials any host in
  `hosts` again, and — if the connection was authenticated — re-binds with
  the stored credentials. `bindDN` is preserved, so `AuthenticateUser`
  continues to work after a reconnect.
- `Close` is idempotent and swallows `Close` errors (best-effort).

---

## Writing your own adapter

Implement `interfaces.CatalogAdapter` for your directory. The adapter is
stateless and safe to reuse across connections. Example skeleton:

```go
type MyAdapter struct{}

func (MyAdapter) GetNormalizedUserInfo(u types.LDAPUser) *types.UserNormalizedInfo {
    return &types.UserNormalizedInfo{
        DistinguishedName: u.DN,
        CommonName:        u.GetAttributeValue("cn"),
        Mail:              u.GetAttributeValue("mail"),
    }
}

func (MyAdapter) OUInfoFromEntry(e ldap.Entry) *types.OUInfo {
    return &types.OUInfo{
        DN:       e.DN,
        Name:     e.GetAttributeValue("ou"),
        Children: make([]*types.OUInfo, 0),
    }
}

func (MyAdapter) UserObjectFilter() string { return "(&(objectClass=inetOrgPerson))" }
func (MyAdapter) UserAttrs() []string      { return []string{"cn", "mail"} }
// ... remaining methods
```

Rule of thumb for `SearchUserGroupsFilterTemplate`:

- If your schema stores membership in `member` as **DN** values, use
  `(member=%s)` and return `[user.DN]` from
  `SearchUserGroupsFilterTemplateArgs`.
- If your schema stores membership in `memberUid` as **short uid** values,
  use `(memberUid=%s)` and return `[user.GetAttributeValue("uid")]`.
- If you need to handle both (like `OPENLDAPAdapter` and `ALDRPOAdapter`),
  use a union filter with two placeholders and return both values in order.

See `adapters/msad_adapter.go`, `adapters/openldap_adapter.go`,
`adapters/aldpro_adapter.go` and `adapters/freeipa_adapter.go` for
complete, production-quality examples.

---

## Configuration & tuning

Defaults live in `constants/constants.go`:

| Constant                       | Default | Meaning |
|--------------------------------|---------|---------|
| `LDAPURITemplate`              | `"ldap://%s:%d"`  | Used for plain / StartTLS dials |
| `LDAPSURITemplate`             | `"ldaps://%s:%d"` | Used for LDAPS dials |
| `DefaultSearchSizeLimit`       | `0`     | `0` = no client-side size limit |
| `DefaultSearchTimeLimit`       | `30`    | Seconds |
| `DefaultMaxHostsLength`        | `50`    | Upper bound on the `hosts` slice |
| `DefaultCatalogTreePageSize`   | `1000`  | Paging control size for `GetCatalogTree` |

Options:

| Option                        | Effect |
|-------------------------------|--------|
| `WithSearchLimits(size, time)`| Overrides the connection-level search limits |
| `SetSearchLimits(size, time)` | Runtime override (not concurrency-safe) |
| `GetSearchLimits()`           | Reads current limits |

---

## Testing

The package is designed for testability at every layer.

### Unit tests

Unit tests run without any network access and cover:

- `LDAPper` core (`ldapper_test.go`): dial, failover, auth, `IsAlive`,
  `Reconnect`, `EnsureAlive`, `Close`.
- Search methods (`ldapper_search_test.go`): `GetUser`,
  `GetUserGroups`, `GetOUUsers`, `CustomSearch`.
- Search limits (`ldapper_seach_params_test.go`): normalization,
  option/`Set`/`Get`, `newSearchRequest` propagation.
- Catalog tree (`ldapper_catalog_tree_discovery_test.go`): `parentDNOf`,
  `trimDepth`, `GetCatalogTree`, `GetRootOUs`, `GetSubOUs`, paging,
  request-shape contract.
- Each shipped adapter (`adapters/*_adapter_test.go`): user-info mapping,
  OU mapping, filter templates (parsed by `ldap.CompileFilter`),
  args ordering, attribute lists, and distinguishing-attribute guards.

```bash
go test ./...
go test -race ./...
```

Helpers:

- `withMockDialURL(t, fn)` swaps the package-level `dialURL` variable for
  one test.
- `mocks.MockLDAPConn` (in `mocks/ldap_native_conn_mock.go`) provides
  function-field substitutes for `Bind`, `Search`, `Close`, `IsClosing`,
  `StartTLS`.
- `testCatalogAdapter` (in `test_catalog_adapter_test.go`) is a compact
  `CatalogAdapter` test double used by core tests.
- `newLDAPUser` (in `adapters/helpers_test.go`) builds `types.LDAPUser`
  fixtures for adapter tests.

> Tip: `StartTLS` on a zero-value `*ldap.Conn` returned by a mocked
> `dialURL` blocks on a `nil` channel. When mocking `dialURL`, always set
> `skipTLS = true` or `useSSL = true` on the `LDAPper` under test (see
> `newDialableLDAPper` in `helpers_test.go`).

### Integration tests

End-to-end tests spin up real directories via
[testcontainers-go](https://golang.testcontainers.org/) and require a
running Docker daemon. Each suite lives in a separate file behind its own
build tag, because Go allows **only one `TestMain` per package** — the
tags keep the suites from compiling together.

| File                              | Build tag                | Container                          |
|-----------------------------------|--------------------------|------------------------------------|
| `openldap_integration_test.go`    | `integration_openldap`   | `osixia/openldap:1.5.0`            |
| `msad_integration_test.go`        | `integration_msad`       | `nowszy/samba-ad-dc` (Samba 4 AD)  |
| `freeipa_integration_test.go`     | `integration_freeipa`    | `freeipa/freeipa-server:rocky-9`   |
| `aldpro_integration_test.go`      | `integration_aldpro`     | `osixia/openldap` + ALDPro schema  |

Run one suite at a time:

```bash
go test -tags=integration_openldap ./...
go test -tags=integration_msad     ./...
go test -tags=integration_freeipa  ./...
go test -tags=integration_aldpro   ./...
```

What each suite exercises:

- **OpenLDAP** — full end-to-end coverage of `ldapper.go` +
  `ldapper_search.go` against `OPENLDAPAdapter`; both branches of the
  `member` / `memberUid` group filter are positively asserted.
- **MS AD** — real Samba 4 AD DC, exercising the AD-only
  `LDAP_MATCHING_RULE_IN_CHAIN` group expansion. Gracefully skips if the
  container cannot be started.
- **FreeIPA** — real FreeIPA container, verifying that
  `ipa group-add-member` populates DN-valued `member`, and cross-checking
  `GetUserGroups` against an independent `CustomSearch` with the same
  filter.
- **ALDPro** — stock OpenLDAP augmented with a custom schema mirroring
  the ALDPro-specific `rbta-org-unit` objectClass and `rbtadp` attribute,
  exercising both `member` (groupOfNames) and `memberUid` (posixGroup)
  branches of the dual-branch filter.

FreeIPA and MS AD suites skip gracefully on machines without the
appropriate container support, so `go test -tags=integration_*` is safe
to run anywhere Docker is available.

---

## License

Copyright © 2020–2026 NGR Softlab. See the `LICENSE` file in the
repository root for the full license text.