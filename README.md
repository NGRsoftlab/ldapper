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
`github.com/go-ldap/ldap/v3`.

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
                                     test: mocks.MockCatalogAdapter
                                           or testCatalogAdapter

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
├── bindUser        string                      stored for Reconnect re-bind
├── bindPassword    string
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

### Repository layout

```
ldapper/
├── ldapper.go                        constructors + connection lifecycle
├── ldapper_search.go                 CustomSearch / GetUser / GetUserGroups / GetOUUsers
├── ldapper_search_params.go          SearchLimits + newSearchRequest
├── ldapper_catalog_tree_discovery.go GetCatalogTree / GetRootOUs / GetSubOUs
│
├── interfaces/
│   ├── catalog_adapter_interface.go  interfaces.CatalogAdapter
│   └── ldap_native_conn_interface.go interfaces.LDAPConn
│
├── adapters/
│   ├── msad_adapter.go               Microsoft Active Directory
│   ├── openldap_adapter.go           OpenLDAP / RFC-4519
│   ├── aldpro_adapter.go             ALD Pro
│   └── freeipa_adapter.go            FreeIPA
│
├── types/
│   ├── ldap_user_type.go             LDAPUser + attribute helpers
│   ├── ldap_catalog_structure_type.go OUInfo / CatalogTree
│   └── normalized_user_type.go       UserNormalizedInfo
│
├── constants/constants.go            all defaults in one place
│
└── mocks/
    ├── ldap_native_conn_mock.go      MockLDAPConn (function-field style)
    └── catalog_adapter_mock.go       MockCatalogAdapter (testify)
```

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
| `adapters.OPENLDAPAdapter`  | OpenLDAP (and most RFC-4519 dialects) | Handles both `groupOfNames` and `posixGroup`; user search keyed by `uid` **or** `cn`; address mapped from `postalAddress`. |
| `adapters.ALDRPOAdapter`    | ALD Pro                            | Recognizes `rbta-org-unit` alongside `organizationalUnit`; department mapped from `rbtadp`; supports `groupOfNames`, `posixGroup`, `ipausergroup`. |
| `adapters.FREEIPAAdapter`   | FreeIPA                            | Recognizes `nsContainer` alongside `organizationalUnit`; department intentionally **not** mapped (FreeIPA schemas vary); uses FreeIPA-specific attrs `nsAccountLock` and `ipaUniqueID`. |

### Adapter-specific gotchas

- **`MSADAdapter`** — the base DN for search must be a valid AD naming
  context. `GetUser` matches on `sAMAccountName`; the bind DN in
  `NewAuthenticatedConnection` can be a UPN (`user@domain`), not necessarily
  a full DN.
- **`OPENLDAPAdapter`** — the user filter uses the indexed format
  placeholder `%[1]s` so the same argument is substituted into both `uid=`
  and `cn=`. Computer objects are explicitly excluded.
- **`ALDRPOAdapter`** / **`FREEIPAAdapter`** — the user-groups filter
  template is `member=uid=%s`, which expects the short `uid` (not a DN).
  `SearchUserGroupsFilterTemplateArgs` returns exactly one argument to match
  the single placeholder. If your directory stores full DNs in `member`,
  override `SearchUserGroupsFilterTemplate` in a custom adapter.

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
// Bind as `username` and store the credentials for later re-binds.
user, err := conn.AuthenticateConn(username, password, baseDN)

// Check a user's password against an already-authenticated connection,
// then rebind back to the service account.
user, err := conn.AuthenticateUser(username, password, baseDN)
```

Notes:

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
  the stored credentials.
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

The package is designed for testability:

- `dialURL` is a package-level `var` — tests can substitute it with
  `withMockDialURL(t, fn)` (see `helpers_test.go`).
- `interfaces.LDAPConn` and `interfaces.CatalogAdapter` can both be mocked.
  Ready-made fakes live in `mocks/`:
  - `mocks.MockLDAPConn` — `BindFunc`, `SearchFunc`, `CloseFunc`,
    `IsClosingFunc`, `StartTLSFunc` fields.
  - `mocks.MockCatalogAdapter` — testify-based catalog adapter.
- Integration tests against an in-memory directory are kept behind
  `//go:build integration` (see `ldapper_integration_test.go`) and can be
  run with:

  ```bash
  go test -tags=integration ./...
  ```

Run the unit tests:

```bash
go test ./...
```

Run with the race detector:

```bash
go test -race ./...
```

> Tip: `StartTLS` on a zero-value `*ldap.Conn` returned by a mocked
> `dialURL` blocks on a `nil` channel. When mocking `dialURL`, always set
> `skipTLS = true` or `useSSL = true` on the `LDAPper` under test (see
> `newDialableLDAPper` in `helpers_test.go`).

---

## License

Copyright © 2020–2026 NGR Softlab. See the `LICENSE` file in the
repository root for the full license text.
