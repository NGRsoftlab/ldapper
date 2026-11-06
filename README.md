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
- **Sentinel errors** (`ErrNotFound`, `ErrUnavailable`, `ErrInvalidCredentials`, …)
  designed for `errors.Is` / `errors.As`.
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
  - [Dial timeout](#dial-timeout)
- [Shipped adapters](#shipped-adapters)
- [API overview](#api-overview)
  - [Authentication](#authentication)
  - [Searching](#searching)
  - [Catalog tree discovery](#catalog-tree-discovery)
  - [Health checks & reconnection](#health-checks--reconnection)
- [Errors](#errors)
- [Writing your own adapter](#writing-your-own-adapter)
- [Configuration & tuning](#configuration--tuning)
- [Testing](#testing)
- [License](#license)

---

## Installation

```bash
go get github.com/NGRsoftlab/ldapper
```

Requires Go 1.26 or newer (see `go.mod`). Depends on
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

    conn, user, err := ldapper.NewAuthenticatedLDAPper(
        "svc-reader@corp.example.com", "secret",            // bind credentials
        "DC=corp,DC=example,DC=com",                        // base DN for user lookup
        []string{"dc1.corp.example.com", "dc2.corp.example.com"},
        636,        // port
        true,       // useSSL (LDAPS)
        false,      // skipTLS (must be false when useSSL is true)
        &tls.Config{MinVersion: tls.VersionTLS12},
        adapter,
        ldapper.WithSearchLimits(0, 30),   // no size limit, 30s time limit
        ldapper.WithDialTimeout(5*time.Second),
    )
    if err != nil {
        log.Fatalf("connect: %v", err)
    }
    defer conn.Close()

    log.Printf("authenticated as %s", user.DN)

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
┌────────────────────────────────────────────────────────────────────┐
│  User code                                                         │
│    conn, _ := ldapper.NewAuthenticatedLDAPper(...)                 │
│    conn.GetUser(...)  /  conn.GetCatalogTree(...)  /  ...          │
└──────────────────────────────────┬─────────────────────────────────┘
                                   │
┌──────────────────────────────────▼─────────────────────────────────┐
│  LDAPper — public API                                              │
│                                                                    │
│  ldapper.go                        constructors + LDAPper struct   │
│  ldapper_connection.go             dial / failover / IsAlive /     │
│                                    Reconnect / EnsureAlive / Close │
│  ldapper_auth.go                   AuthenticateConn,               │
│                                    CheckUserCredentials            │
│  ldapper_search.go                 searchPaged,                    │
│                                    searchSingleEntryLocked,        │
│                                    newSearchRequest, CustomSearch, │
│                                    CustomSearchPaged               │
│  ldapper_user_ops.go               GetUser, GetUserGroups,         │
│                                    GetOUUsers                      │
│  ldapper_group_ops.go              GetGroup                        │
│  ldapper_ou_ops.go                 GetOU                           │
│  ldapper_catalog_tree_discovery.go GetCatalogTree, GetSubOUs,      │
│                                    ListSingleLevelOUs              │
│  ldapper_options.go                Option, SearchLimits, With/Set/ │
│                                    GetSearchLimits, With/Set/Get   │
│                                    DialTimeout                     │
│  ldapper_errors.go                 sentinel errors + classifiers    │
│  helpers.go                        attrsToMap, escapeFilterArgs,   │
│                                    parentDNOf, trimDepth           │
│  validators.go                     validateDN / validateBaseDN /   │
│                                    validateHost / formatHost       │
└──────────────┬────────────────────────────────────┬────────────────┘
               │                                    │
     uses      │                                    │  uses
               ▼                                    ▼
┌──────────────────────────────┐    ┌───────────────────────────────┐
│  interfaces.LDAPConn         │    │  interfaces.CatalogAdapter    │
│  (thin subset of go-ldap)    │    │  (schema-specific glue)       │
│                              │    │                               │
│  StartTLS / Bind / Search /  │    │  Filters / Attrs / Casts      │
│  IsClosing / Close           │    │                               │
└──────────────┬───────────────┘    └──────────────┬────────────────┘
               │                                   │
   prod: *ldap.Conn                  prod: adapters.{MSAD, OPENLDAP,
   test: mocks.MockLDAPConn                ALDPRO, FREEIPA}Adapter
                                     test: ldapper.fakeAdapter
                                     (fake_adapter_test.go)

                               │
┌──────────────────────────────▼─────────────────────────────────────┐
│  go-ldap/ldap/v3                                                   │
└──────────────────────────────┬─────────────────────────────────────┘
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
├── opMu            sync.Mutex                      serializes all ops
│
├── catalogAdapter  interfaces.CatalogAdapter       schema-specific behavior
├── connection      interfaces.LDAPConn             active network connection
│
├── isAuthenticated bool                            set by AuthenticateConn
├── bindUser        string                          cached for re-bind on
├── bindPassword    string                            Reconnect /
├── bindDN          string                            CheckUserCredentials
│                                                   (base DN used by
│                                                    CheckUserCredentials)
│
├── hosts           []string                        failover list (≤ 50)
├── currentHost     string                          host of the active conn
├── port            uint
│
├── useSSL          bool                            LDAPS vs plain LDAP
├── skipTLS         bool                            disable StartTLS upgrade
├── tlsCfg          *tls.Config
│
├── searchLimits    SearchLimits                    injected via newSearchRequest
└── dialTimeout     time.Duration                   used by dialHost
```

Every search method funnels through `newSearchRequest(...)`, which injects
`searchLimits`. Changing limits at runtime (`SetSearchLimits`) is therefore
a single assignment with no plumbing.

`bindDN` is a subtle but useful field: `AuthenticateConn(username, password,
baseDN)` records `baseDN` so that later calls to
`CheckUserCredentials(username, password)` can look users up under the same
base DN without the caller repeating it.

`dialTimeout == 0` means "no explicit timeout; use the Go default". Both the
initial dial and the `StartTLS` handshake honour it (the timeout is
re-applied during the TLS handshake and reset afterwards so it does not
cap regular operations).

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
   searchSingleEntryLocked(kindUser, "jdoe", baseDN, template, attrs)
        │
        │   SizeLimit is hardcoded to 2 (ambiguity probe);
        │   TimeLimit comes from conn.searchLimits.
        ▼
   conn.connection.Search(req)  ─────────▶  LDAP server
        │
        ▼
   0 entries   → ErrNotFound   ("user \"jdoe\" does not exist")
   1 entry     → types.LDAPUser{DN, Attributes}
   >1 entries  → ErrAmbiguousResult ("too many entries for user ...")
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
       catalogAdapter.GetNormalizedOUInfoFromEntry(entry)
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
is done locally in `O(N)` with a single `map[DN]*OUNormalizedInfo`.

---

## Core concepts

### Connections

`LDAPper` is created with one of two constructors:

```go
// Unauthenticated: dials a host but performs no bind. Suitable for
// directories that allow anonymous reads.
func NewLDAPper(
    hosts []string,
    port uint,
    useSSL, skipTLS bool,
    tlsCfg *tls.Config,
    catalogAdapter interfaces.CatalogAdapter,
    opts ...Option,
) (*LDAPper, error)

// Authenticated: dials, then binds as `username` and looks the user up
// via the adapter's user filter to confirm the credentials. The same
// `username` and `baseDN` are cached for later CheckUserCredentials calls.
func NewAuthenticatedLDAPper(
    username, password, baseDN string,
    hosts []string,
    port uint,
    useSSL, skipTLS bool,
    tlsCfg *tls.Config,
    catalogAdapter interfaces.CatalogAdapter,
    opts ...Option,
) (*LDAPper, *types.LDAPUser, error)
```

TLS matrix — `useSSL` and `skipTLS` together select the transport:

| `useSSL` | `skipTLS` | `tlsCfg` | Result                                          |
|----------|-----------|----------|-------------------------------------------------|
| `true`   | `false`   | required | LDAPS — TLS from the first byte                 |
| `true`   | `true`    | —        | **rejected** (`ErrInvalidArgument`)             |
| `false`  | `false`   | required | Plain dial followed by `StartTLS`               |
| `false`  | `true`    | ignored  | Plaintext LDAP (no TLS)                         |

Other constructor rules:

- **Host failover** — hosts are tried in order until one accepts the
  connection. The list is capped at `constants.DefaultMaxHostsLength`
  (50) to guard against accidentally passing a million hosts.
- **Port** — must be in `[1, 65535]`.
- **Host strings** — validated against URL-special characters; IPv6
  literals are accepted without brackets (they are bracketed for the URI
  internally).
- **`dialURL` is a package-level variable** (`ldap.DialURL`) so tests can
  swap it out via `withMockDialURL(...)` without touching production code.

### Adapters

All directory-specific behavior lives in an adapter — a value that
implements `interfaces.CatalogAdapter`:

```go
type CatalogAdapter interface {
    // Cast / convert
    GetNormalizedUserInfo(ldapUser types.LDAPUser) *types.UserNormalizedInfo
    GetNormalizedOUInfoFromEntry(entry ldap.Entry) *types.OUNormalizedInfo

    // Object-class filters
    UserObjectFilter()  string
    GroupObjectFilter() string
    OUObjectFilter()    string

    // Search filter templates
    //
    // Contract: templates use fmt-style verbs (%s or %[N]s). All arguments
    // are escaped with ldap.EscapeFilter by LDAPper before substitution,
    // so implementers must return raw (unescaped) attribute values.
    SearchUserFilterTemplate()       string  // 1 arg
    SearchUserGroupsFilterTemplate() string  // N args, use with the args helper
    SearchUserGroupsFilterTemplateArgs(ldapUser types.LDAPUser) []any
    SearchOUFilterTemplate()    string       // 1 arg
    SearchGroupFilterTemplate() string       // 1 arg

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
conn, _ := ldapper.NewLDAPper(
    hosts, 636, true, false, tlsCfg, adapter,
    ldapper.WithSearchLimits(500, 30),
)

// Later, temporarily raise limits for one heavy pass:
old := conn.GetSearchLimits()
conn.SetSearchLimits(0, 120)
tree, _ := conn.GetCatalogTree("DC=corp,DC=example,DC=com", 0)
conn.SetSearchLimits(old.SizeLimit, old.TimeLimit)
```

- `SizeLimit == 0` — no client-side size limit (server default).
- `TimeLimit == 0` — no client-side time limit (server default).
- With automatic paging (`GetCatalogTree`, `GetOUUsers`, `GetUserGroups`),
  `SizeLimit` is the total across the **entire paged operation** per
  RFC 2696 / server behaviour — not per page.
- Negative values are clamped to `0`.
- `SetSearchLimits` takes `opMu`, so it is safe to call concurrently with
  searches — but the value change takes effect on the **next** request.

### Dial timeout

```go
conn, _ := ldapper.NewLDAPper(
    hosts, 389, false, true, nil, adapter,
    ldapper.WithDialTimeout(5*time.Second),
)

// At runtime:
conn.SetDialTimeout(10 * time.Second)
fmt.Println(conn.GetDialTimeout())  // 10s
```

- `dialTimeout == 0` — no explicit timeout; Go's default applies.
- Negative values are clamped to `0`.
- During the initial dial, `net.Dialer.Timeout` is set; for the StartTLS
  branch, the same timeout is re-applied during the handshake and reset
  afterwards to avoid capping regular operations.
- `Reconnect` and `EnsureAlive` use the same dial timeout.

---

## Shipped adapters

| Adapter                     | Directory                          | Notes |
|-----------------------------|------------------------------------|-------|
| `adapters.MSADAdapter`      | Microsoft Active Directory         | Uses `objectCategory`-based filters; recursive group search via the `LDAP_MATCHING_RULE_IN_CHAIN` OID (`1.2.840.113556.1.4.1941`); prefers `thumbnailPhoto` over `jpegPhoto`. |
| `adapters.OPENLDAPAdapter`  | OpenLDAP (and most RFC-4519 dialects) | Handles both `groupOfNames` (via `member`) and `posixGroup` (via `memberUid`); user search keyed by `uid` **or** `entryDN` (single indexed placeholder `%[1]s`); address mapped from `postalAddress`. |
| `adapters.ALDPROAdapter`    | ALD Pro                            | Recognizes `rbta-org-unit` alongside `organizationalUnit`; department mapped from `rbtadp`; two-branch group filter — `member` (DN) for `groupOfNames`/`ipausergroup` **and** `memberUid` (uid) for `posixGroup`. |
| `adapters.FREEIPAAdapter`   | FreeIPA                            | Recognizes `nsContainer` alongside `organizationalUnit`; department is intentionally **not** mapped; group lookup matches DN-valued `member`, which `ipa group-add-member` populates on `ipausergroup`/`posixGroup`; FreeIPA-specific attrs `nsAccountLock` and `ipaUniqueID`. |

### Adapter-specific gotchas

- **`MSADAdapter`** — `GetUser` matches on `sAMAccountName`; the value passed
  to `NewAuthenticatedLDAPper` must therefore match a `sAMAccountName`
  (a plain `user@domain` UPN typically will **not** match — it will fail the
  post-bind user lookup with `ErrNotFound`). Group search uses
  `LDAP_MATCHING_RULE_IN_CHAIN`, which **Samba 4 AD DC** and Microsoft AD
  both support — OpenLDAP and FreeIPA do **not**.
- **`OPENLDAPAdapter`** — the user filter uses the indexed placeholder
  `%[1]s` so the same argument is substituted into both `uid=` and
  `entryDN=`, allowing lookup by either short name or full DN. Computer
  objects are excluded with `(!(objectClass=computer))`. The user-groups
  filter is a union of two branches:
  ```
  (|(&(objectClass=groupOfNames)(member=%s))
    (&(objectClass=posixGroup)(memberUid=%s)))
  ```
  with args `[user.DN, user.uid]`.
- **`ALDPROAdapter`** — the user-groups filter mirrors OpenLDAP and also
  recognizes `ipausergroup` on the `member` branch:
  ```
  (|(&(|(objectClass=groupOfNames)(objectClass=ipausergroup)(objectClass=posixGroup))(member=%s))
    (&(objectClass=posixGroup)(memberUid=%s)))
  ```
  with args `[user.DN, user.uid]`.
- **`FREEIPAAdapter`** — the user-groups filter:
  ```
  (&(|(objectClass=groupOfNames)(objectClass=posixGroup)(objectClass=ipausergroup))(member=%s))
  ```
  with args `[user.DN]`. FreeIPA's `ipa group-add-member` populates
  `member` (DN-valued) on `ipausergroup`/`posixGroup` entries.
- **`GetNormalizedOUInfoFromEntry.Name`** — all shipped adapters derive
  `Name` from the **first RDN** of `entry.DN` (via the shared helper
  `ouNameFromDN`), not from the `name`/`ou` attribute. Malformed DNs fall
  back to the whole string instead of crashing.
- **`GetNormalizedOUInfoFromEntry.OU`** — MSAD sets `OU` to the **full
  entry DN**; the other three adapters read the `ou` attribute.

All four adapters are stateless and safe to reuse across connections.

### Attribute mapping in `GetNormalizedUserInfo`

`DistinguishedName` is always taken from the `LDAPUser.DN` **struct field**,
never from an attribute. Every adapter reads the remaining fields from LDAP
attributes; `—` means "hardcoded to empty" (attribute not read even if
present).

| `UserNormalizedInfo` field | MSAD                     | OpenLDAP           | ALD Pro           | FreeIPA      |
|----------------------------|--------------------------|--------------------|-------------------|--------------|
| `DistinguishedName`        | struct `DN`              | struct `DN`        | struct `DN`       | struct `DN`  |
| `CommonName`               | `cn`                     | `cn`               | `cn`              | `cn`         |
| `Mobile`                   | `mobile`                 | `mobile`           | `mobile`          | `mobile`     |
| `Phone`                    | `telephoneNumber`        | `telephoneNumber`  | `telephoneNumber` | `telephoneNumber` |
| `Mail`                     | `mail`                   | `mail`             | `mail`            | `mail`       |
| `Department`               | `department`             | `departmentNumber` | `rbtadp`          | —            |
| `Title`                    | `title`                  | `title`            | `title`           | `title`      |
| `Manager`                  | `manager`                | `manager`          | `manager`         | `manager`    |
| `Photo`                    | `thumbnailPhoto` → `jpegPhoto` | `jpegPhoto`  | `jpegPhoto`       | `jpegPhoto`  |
| `Company`                  | `company`                | `o`                | `o`               | `o`          |
| `Country`                  | `co`                     | —                  | `co`              | `co`         |
| `Address`                  | `streetAddress`          | `postalAddress`    | `streetAddress`   | `street`     |
| `City`                     | `l`                      | —                  | `l`               | `l`          |
| `Index`                    | `postalCode`             | —                  | `postalCode`      | `postalCode` |

Key differences to keep in mind:

- **`Department`** — four different sources (`department`,
  `departmentNumber`, `rbtadp`, or none). FreeIPA simply does not map it.
- **`Address`** — MSAD and ALD Pro use `streetAddress`, OpenLDAP uses
  `postalAddress`, FreeIPA uses `street`.
- **`Company`** — MSAD uses the `company` attribute, the other three use
  `o`.
- **`Photo`** — only MSAD falls back from `thumbnailPhoto` to `jpegPhoto`;
  the other three read `jpegPhoto` only and do **not** consult
  `thumbnailPhoto`.
- **`Country` / `City` / `Index`** — OpenLDAP hardcodes these to empty
  regardless of the entry's attributes. If you need them populated against
  OpenLDAP, write a custom adapter that overrides `GetNormalizedUserInfo`.

---

## API overview

### Authentication

```go
// Bind as `username` and store the credentials + base DN for later use.
user, err := conn.AuthenticateConn(username, password, baseDN)

// Verify a user's password against an already-authenticated connection,
// then rebind back to the service account.
user, err := conn.CheckUserCredentials(username, password)
```

`AuthenticateConn`:

- Stores `username`, `password` and `baseDN` on the connection.
- Performs the bind **first**, then looks the user up via the adapter's
  user filter. If the bind fails, the user lookup is never issued
  (`errors.Is(err, ErrInvalidCredentials)`).
- On success, caches `isAuthenticated=true`, `bindUser`, `bindPassword`,
  `bindDN`.

`CheckUserCredentials`:

- Requires `isAuthenticated == true` (i.e. `AuthenticateConn` or
  `NewAuthenticatedLDAPper` was called). Otherwise returns
  `ErrNotAuthenticated`.
- Uses the **stored `bindDN`** as the base DN for the internal user
  lookup — callers do not repeat it.
- **User enumeration protection**: a missing user is returned as
  `ErrInvalidCredentials`, indistinguishable from a wrong password.
- **Returns `nil` user on any failure** — a returned `*LDAPUser` always
  implies a successful verification. Do not check `user != nil` alone as
  an auth signal.
- Restores the service bind via a deferred rebind. If the rebind itself
  fails, `isAuthenticated` is cleared and the error surfaces as
  `ErrNotAuthenticated` (or is appended to the primary error).

All bind-path errors go through `classifySensitiveBindError`, which never
echoes raw server text — passwords cannot leak into logs.

### Searching

```go
// Escape hatch: build any *ldap.SearchRequest yourself. No DN validation,
// no paging, no search-limit overrides — the caller owns semantics.
res, err := conn.CustomSearch(&ldap.SearchRequest{...})

// Same, with automatic paging applied on top of the request's controls.
// Base DN is validated; result is the concatenation of all pages.
entries, err := conn.CustomSearchPaged(&ldap.SearchRequest{...})

// Fetch a single user by the adapter's user filter template.
user, err := conn.GetUser("jdoe", baseDN)

// Fetch DNs of all groups the user belongs to.
groups, err := conn.GetUserGroups("jdoe", baseDN)

// Fetch a single group by its cn.
group, err := conn.GetGroup("admins", baseDN)

// Fetch a single OU by its ou attribute value (e.g. "Sales").
ou, err := conn.GetOU("Sales", baseDN)

// Fetch every user under an OU DN (subtree search, adapter user filter).
users, err := conn.GetOUUsers("OU=Staff,DC=corp,DC=example,DC=com")
```

- **`GetUser`, `GetGroup`, `GetOU`** — single-object lookups. Each uses
  `SizeLimit=2` internally to detect duplicates and returns:
  - `ErrNotFound` if zero entries match,
  - `ErrAmbiguousResult` if more than one entry matches.
- **`GetUserGroups`** — calls `GetUser` first, then applies the adapter's
  `SearchUserGroupsFilterTemplate` / `SearchUserGroupsFilterTemplateArgs`
  with **`[]string{"1.1"}`** (OID for "no attributes"), so only DNs come
  back from the server. Returns group DNs in server order.
- **`GetOUUsers`** — takes a **DN**, not a short `ou` name. Uses the
  adapter's `UserObjectFilter` and `UserAttrs` to list all users under
  the subtree, subject to paging.
- **`GetOU`** — takes the short `ou` value (e.g. `"Sales"`) plus a base
  DN; the underlying filter template is `(ou=%s)`.
- **`GetGroup`** — takes the short `cn` value; the underlying filter
  template is `(cn=%s)`.

All of these are safe to call concurrently: `opMu` serializes the
underlying LDAP operations.

### Catalog tree discovery

```go
tree, err := conn.GetCatalogTree("DC=corp,DC=example,DC=com", 2)
```

- Performs **one paged subtree search** (`ControlPaging`, page size
  `constants.DefaultCatalogSearchPageSize = 1000`) and builds the `OU`
  tree on the client — O(round-trips) ≈ N / page-size, not N.
- Filters out entries that are not strict descendants of `baseDN`
  (via `ldap.DN.AncestorOf`) — misbehaving servers and cross-tree
  referrals cannot leak foreign entries into the result.
- Skips malformed DNs returned by the server rather than aborting.
- Nodes whose parent is **not** in the fetched set (e.g. server-side
  filtering) are promoted to roots of `tree.Tree`.
- `maxDepth` trims the resulting tree: `0` = no limit, `1` = roots only,
  `2` = roots + first level, etc.
- If the server returns `SizeLimitExceeded` after at least one page, the
  partial tree is returned along with `ErrPartialResult` — callers can
  choose to accept the partial result or bail out.

```go
// Root-level OUs only (single-level scope, one round-trip):
roots, err := conn.ListSingleLevelOUs("DC=corp,DC=example,DC=com")

// Direct children of an OU (same as ListSingleLevelOUs, but explicit):
children, err := conn.GetSubOUs(
    "OU=Staff,DC=corp,DC=example,DC=com",
    ldap.ScopeSingleLevel,
)

// All descendants of an OU (subtree scope):
descendants, err := conn.GetSubOUs(
    "OU=Staff,DC=corp,DC=example,DC=com",
    ldap.ScopeWholeSubtree,
)
```

`GetSubOUs` accepts only `ldap.ScopeSingleLevel` and
`ldap.ScopeWholeSubtree`; `ldap.ScopeBaseObject` is rejected with
`ErrInvalidArgument` (it would always return an empty list). The base DN
itself is always excluded — "sub" means strict descendants.

`GetCatalogTree` is the recommended path for large catalogs: it round-trips
once per page, streams results page-by-page, and assembles the tree in
`O(N)` using a `map[DN]*OUNormalizedInfo` + parent-DN walk.

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

- **`IsAlive`** — checks the local connection state (`IsClosing`) and
  issues a cheap root-DSE search with hard-coded `SizeLimit=1, TimeLimit=1`.
  Intentionally independent of the user-configured search limits.
- **`Reconnect`** — closes the current connection, dials any host in
  `hosts` again, and — if the connection was authenticated — re-binds with
  the stored credentials. `bindDN` is preserved, so `CheckUserCredentials`
  continues to work after a reconnect.
- **`EnsureAlive`** — `IsAlive()` first; reconnect only when stale.
- **`Close`** — idempotent, best-effort (swallows `Close` errors).

---

## Errors

All public functions return sentinel errors that can be tested with
`errors.Is`. The original `*ldap.Error` / `net.Error` is preserved in the
wrapped chain (`errors.As` still works).

| Sentinel                 | Meaning |
|--------------------------|---------|
| `ErrInvalidArgument`     | Config or argument validation failed (empty/invalid DN, empty username, invalid host, invalid port, `useSSL && skipTLS`, nil TLS config, nil adapter, …). |
| `ErrInvalidCredentials`  | Bind rejected as bad credentials. Also returned by `CheckUserCredentials` when the user is missing (enumeration protection). |
| `ErrNotAuthenticated`    | `CheckUserCredentials` called on a connection without a successful prior `AuthenticateConn`/`NewAuthenticatedLDAPper`, or the service rebind was lost. |
| `ErrUnavailable`         | Directory unreachable (dial failure, `LDAPResultUnavailable`/`Busy`/`ServerDown`, transport errors). |
| `ErrTimeout`             | Timeout / deadline exceeded (`LDAPResultTimeout`, `LDAPResultTimeLimitExceeded`, `net.Error.Timeout`, `context.DeadlineExceeded`). |
| `ErrClosed`              | The connection is nil (never initialized, or `Close()` was called). |
| `ErrNotFound`            | Search produced zero matching entries (`LDAPResultNoSuchObject`). |
| `ErrAmbiguousResult`     | Single-object lookup matched more than one entry. |
| `ErrPartialResult`       | Paged search was interrupted by `SizeLimitExceeded` after at least one page — the returned slice/tree is partial. |
| `ErrInsufficientAccess`  | Bind path returned `LDAPResultInsufficientAccessRights`. Surfaced by `classifySensitiveBindError`; kept out of the generic `ErrInvalidCredentials` bucket for diagnosability. |

Bind-path failures **never** wrap the raw LDAP text — this prevents
credential leakage into logs when the server echoes back the submitted
password. All bind errors are mapped to bare sentinels by
`classifySensitiveBindError`.

Non-bind failures use `classifyLDAPError`, which wraps both the sentinel
and the original error:

```go
if errors.Is(err, ldapper.ErrNotFound) { /* ... */ }

var ldapErr *ldap.Error
if errors.As(err, &ldapErr) {
    log.Printf("LDAP result code: %d", ldapErr.ResultCode)
}
```

---

## Writing your own adapter

Implement `interfaces.CatalogAdapter` for your directory. The adapter is
stateless and safe to reuse across connections. Skeleton:

```go
type MyAdapter struct{}

func (MyAdapter) GetNormalizedUserInfo(u types.LDAPUser) *types.UserNormalizedInfo {
    return &types.UserNormalizedInfo{
        DistinguishedName: u.DN,
        CommonName:        u.GetAttributeValue("cn"),
        Mail:              u.GetAttributeValue("mail"),
    }
}

func (MyAdapter) GetNormalizedOUInfoFromEntry(e ldap.Entry) *types.OUNormalizedInfo {
    return &types.OUNormalizedInfo{
        DN:       e.DN,
        Name:     e.GetAttributeValue("ou"),
        OU:       e.GetAttributeValue("ou"),
        Children: make([]*types.OUNormalizedInfo, 0),
    }
}

func (MyAdapter) UserObjectFilter()  string   { return "(&(objectClass=inetOrgPerson))" }
func (MyAdapter) GroupObjectFilter() string   { return "(objectClass=groupOfNames)" }
func (MyAdapter) OUObjectFilter()    string   { return "(objectClass=organizationalUnit)" }

func (MyAdapter) SearchUserFilterTemplate()  string { return "(&(objectClass=inetOrgPerson)(uid=%s))" }
func (MyAdapter) SearchGroupFilterTemplate() string { return "(&(objectClass=groupOfNames)(cn=%s))" }
func (MyAdapter) SearchOUFilterTemplate()    string { return "(&(objectClass=organizationalUnit)(ou=%s))" }

func (MyAdapter) SearchUserGroupsFilterTemplate() string {
    return "(&(objectClass=groupOfNames)(member=%s))"
}
func (MyAdapter) SearchUserGroupsFilterTemplateArgs(u types.LDAPUser) []any {
    return []any{u.DN}
}

func (MyAdapter) UserAttrs()  []string { return []string{"uid", "cn", "mail"} }
func (MyAdapter) OUAttrs()    []string { return []string{"ou", "description"} }
func (MyAdapter) GroupAttrs() []string { return []string{"cn", "member"} }
```

Rules of thumb:

1. **Return raw, unescaped values** from `SearchUserGroupsFilterTemplateArgs`.
   LDAPper runs each value through `ldap.EscapeFilter` before
   substitution. Same for the single argument that is passed into
   `SearchUserFilterTemplate`, `SearchGroupFilterTemplate` and
   `SearchOUFilterTemplate`.
2. **Count placeholders carefully.** `SearchUserFilterTemplate`,
   `SearchGroupFilterTemplate` and `SearchOUFilterTemplate` take exactly
   one argument. `SearchUserGroupsFilterTemplate` may take any number,
   but `SearchUserGroupsFilterTemplateArgs` must return exactly that many
   values in the same order.
3. **Group membership format**:
  - Schema stores DN-valued `member` → use `(member=%s)` and
    return `[user.DN]`.
  - Schema stores uid-valued `memberUid` → use `(memberUid=%s)` and
    return `[user.GetAttributeValue("uid")]`.
  - Both (like `OPENLDAPAdapter` / `ALDPROAdapter`) → use a union with
    two placeholders and return both values in order.
4. **`GetNormalizedOUInfoFromEntry` must return a non-nil `Children`
   slice** — `GetCatalogTree` appends to it.
5. **`DistinguishedName`** in `GetNormalizedUserInfo` must come from
   `ldapUser.DN` (the struct field), not from an LDAP attribute.

See `adapters/msad_adapter.go`, `adapters/openldap_adapter.go`,
`adapters/aldpro_adapter.go` and `adapters/freeipa_adapter.go` for
complete, production-quality examples.

---

## Configuration & tuning

Defaults live in `constants/constants.go`:

| Constant                         | Default | Meaning |
|----------------------------------|---------|---------|
| `LDAPURITemplate`                | `"ldap://%s:%d"`  | Used for plain / StartTLS dials |
| `LDAPSURITemplate`               | `"ldaps://%s:%d"` | Used for LDAPS dials |
| `DefaultSearchSizeLimit`         | `0`     | `0` = no client-side size limit |
| `DefaultSearchTimeLimit`         | `30`    | Seconds |
| `DefaultMaxHostsLength`          | `50`    | Upper bound on the `hosts` slice |
| `DefaultCatalogSearchPageSize`   | `1000`  | Paging control size for paged searches |
| `DefaultDialTimeout`             | `0`     | `0` = use Go's default |

Options (`type Option func(*LDAPper)`):

| Option                          | Effect |
|---------------------------------|--------|
| `WithSearchLimits(size, time)`  | Overrides connection-level search limits |
| `WithDialTimeout(d)`            | Overrides dial / StartTLS-handshake timeout |
| `SetSearchLimits(size, time)`   | Runtime override of search limits |
| `GetSearchLimits()`             | Reads current search limits |
| `SetDialTimeout(d)`             | Runtime override of dial timeout |
| `GetDialTimeout()`              | Reads current dial timeout |

Negative values are clamped to `0` ("no limit"/"Go default").

---

## Testing

The package is designed for testability at every layer.

### Unit tests

Unit tests run without any network access and cover:

- **Core connection & auth** — `ldapper_test.go`, `ldapper_auth_test.go`:
  dial, failover, `AuthenticateConn`, `CheckUserCredentials`, `IsAlive`,
  `Reconnect`, `EnsureAlive`, `Close`.
- **Search primitives** — `ldapper_search_test.go`:
  `newSearchRequest`, `searchSingleEntryLocked`, `searchPaged`,
  `CustomSearch`, `CustomSearchPaged`.
- **User operations** — `ldapper_user_ops_test.go`: `GetUser`,
  `GetUserGroups`, `GetOUUsers`.
- **Group operations** — `ldapper_group_ops_test.go`: `GetGroup`.
- **OU operations** — `ldapper_ou_ops_test.go`: `GetOU`.
- **Catalog tree** — `ldapper_catalog_tree_discovery_test.go`:
  `GetCatalogTree`, `GetSubOUs`, `ListSingleLevelOUs`.
- **Limits & timeouts** — `ldapper_options_test.go`: `With/Set/Get` for
  both `SearchLimits` and `DialTimeout`, clamping, race-guards.
- **Errors** — `ldapper_errors_test.go`: `classifyLDAPError`,
  `classifySensitiveBindError` (including the "no secret leak" regression
  test), `isTimeoutError`, `isTransportError`.
- **Helpers & validators** — `helpers_test.go`, `validators_test.go`.
- **Shipped adapters** — `adapters/*_adapter_test.go`: user-info mapping,
  OU mapping, filter templates parsed by `ldap.CompileFilter`, args
  ordering, attribute lists, distinguishing-attribute guards.

```bash
go test ./...
go test -race ./...
```

Test helpers:

- **`utils_test.go`** (package `ldapper`):
  - `withMockDialURL(t, fn)` — swaps the package-level `dialURL` variable
    for one test.
  - `newDialableLDAPper(hosts)` — builds a minimal `LDAPper` with
    `skipTLS=true` suitable for mocked `dialURL`.
  - `newTestConnection(adapter, conn)` — same, with a pre-set adapter and
    connection.
  - `newLDAPEntry(dn, attrs)` — builds an `*ldap.Entry` from a DN and
    attribute map.
  - `mockOUs(entries...)` — a `MockLDAPConn` returning the given entries
    in a single page.
- **`fake_adapter_test.go`** (package `ldapper`) — `fakeAdapter`, a
  configurable `CatalogAdapter` stub used by all core tests. Each
  `fakeAdapter` field defaults to an empty value; tests populate only
  what they exercise.
- **`ldapper_search_test.go`** (package `ldapper`) — `captureMock` /
  `pagedPage` / `searchCall`: a stateful mock that snapshots every
  `Search` request (including the paging cookie at the time of the call)
  and yields a configurable sequence of responses.
- **`adapters/helpers_test.go`** (package `adapters`):
  - `newLDAPUser(dn, attrs)` — builds a `types.LDAPUser` fixture with a
    non-nil attribute map.
  - `attrMap(map[string]string) map[string][]string` — shorthand for
    single-valued attributes.
  - `newLDAPEntry(dn, attrs) ldap.Entry` — value-form entry, matches the
    signature of `GetNormalizedOUInfoFromEntry`.
  - `requireValidFilter(t, filter)` — fails the test if
    `ldap.CompileFilter` rejects the filter, with the raw text included
    in the diagnostic.

> **Tip:** `StartTLS` on a zero-value `*ldap.Conn` returned by a mocked
> `dialURL` blocks on a `nil` channel. When mocking `dialURL`, always set
> `skipTLS = true` (or `useSSL = true`) on the `LDAPper` under test — see
> `newDialableLDAPper` in `utils_test.go`.

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

- **OpenLDAP** — full end-to-end coverage of the public API against
  `OPENLDAPAdapter`; both branches of the `member` / `memberUid` group
  filter are positively asserted, plus `entryDN`-fallback lookups and
  duplicate detection (`ErrAmbiguousResult`).
- **MS AD** — real Samba 4 AD DC, exercising the AD-only
  `LDAP_MATCHING_RULE_IN_CHAIN` group expansion. Gracefully skips if the
  container cannot be started.
- **FreeIPA** — real FreeIPA container, verifying that
  `ipa group-add-member` populates DN-valued `member`, and cross-checking
  `GetUserGroups` against an independent `CustomSearch` with the same
  filter. Gracefully skips if the container cannot be started.
- **ALDPro** — stock OpenLDAP augmented with a custom schema mirroring
  the ALDPro-specific `rbta-org-unit` objectClass and `rbtadp` attribute.
  Exercises both branches of the dual-branch group filter, and confirms
  that `OUObjectFilter` matches both standard `organizationalUnit` and
  ALDPro-specific `rbta-org-unit` entries.

All integration tests assert error conditions with `errors.Is(err,
ldapper.Err*)` against the sentinel contract — not against error text —
so message rewording does not break them.

---

## License

Copyright © 2020–2026 NGR Softlab. See the `LICENSE` file in the
repository root for the full license text.
