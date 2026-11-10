# LDAPper

[![Go Reference](https://pkg.go.dev/badge/github.com/NGRsoftlab/ldapper.svg)](https://pkg.go.dev/github.com/NGRsoftlab/ldapper)
[![Tests](https://github.com/NGRsoftlab/ldapper/actions/workflows/test.yml/badge.svg)](https://github.com/NGRsoftlab/ldapper/actions/workflows/test.yml)
[![Integration tests](https://github.com/NGRsoftlab/ldapper/actions/workflows/integration.yml/badge.svg)](https://github.com/NGRsoftlab/ldapper/actions/workflows/integration.yml)
[![Go version](https://img.shields.io/github/go-mod/go-version/NGRsoftlab/ldapper)](go.mod)
[![License](https://img.shields.io/badge/License-See%20LICENSE-blue.svg)](LICENSE)

A lightweight, adapter-based LDAP client for Go. LDAPper wraps
[`go-ldap/ldap`](https://github.com/go-ldap/ldap) with:

- **Context-aware operations** — every networked call takes a `context.Context`
  as its first argument; cancellation kills the underlying connection
  deterministically.
- **Multi-host failover** and transparent reconnection.
- **Pluggable catalog adapters** so the same API works against Microsoft
  Active Directory, OpenLDAP, ALD Pro, FreeIPA, and any other directory you
  write an adapter for.
- **Connection-level search limits** (`SizeLimit`, `TimeLimit`, `MaxPages`,
  `MaxEntries`, `RequirePaging`) injected once at construction time.
- **Client-side operation timeouts** applied around individual `Bind` /
  `Search` calls, independent of server-side `TimeLimit`.
- **Efficient catalog tree discovery** — a single paged subtree search
  assembled into an `OU` tree on the client, with optional depth trimming.
- **Sentinel errors** (`ErrNotFoundOrNotVisible`, `ErrUnavailable`,
  `ErrInvalidCredentials`, …) designed for `errors.Is` / `errors.As`.
- **End-to-end integration tests** for every shipped adapter, running
  against real directory servers in Docker (OpenLDAP, Samba 4 AD DC,
  FreeIPA, and OpenLDAP-with-ALDPro-schema).

---

## Test status

| Layer                       | Where it runs                                        | Build tag                | Notes |
|-----------------------------|------------------------------------------------------|--------------------------|-------|
| Unit tests                  | `go test -race ./...` (GitHub Actions, every push)    | —                        | No external dependencies; includes the race detector. |
| Integration — OpenLDAP      | `go test -tags=integration_openldap ./...`            | `integration_openldap`   | Spins up `osixia/openldap:1.5.0` via testcontainers. |
| Integration — MS AD         | `go test -tags=integration_msad ./...`                | `integration_msad`       | Spins up a Samba 4 AD DC; gracefully skips if Docker is unavailable. |
| Integration — FreeIPA       | `go test -tags=integration_freeipa ./...`             | `integration_freeipa`    | Spins up a FreeIPA server; heavy image, gracefully skips on failure. |
| Integration — ALDPro        | `go test -tags=integration_aldpro ./...`              | `integration_aldpro`     | OpenLDAP + custom ALDPro schema. |

Coverage is measured with `go test -coverprofile=coverage.out ./...` and
uploaded to Codecov on every push to `main` and on pull requests. The
current coverage report is available at
[codecov.io/gh/NGRsoftlab/ldapper](https://codecov.io/gh/NGRsoftlab/ldapper).

The default `go test ./...` is intentionally fast and Docker-free: all
integration suites live behind build tags so they do not compile into
the default test binary (Go allows only one `TestMain` per package, so
the tags are also what keeps the four suites from colliding).

## Table of contents

- [Installation](#installation)
- [Quick start](#quick-start)
- [Architecture](#architecture)
- [Core concepts](#core-concepts)
  - [Connections](#connections)
  - [Adapters](#adapters)
  - [Search limits](#search-limits)
  - [Dial timeout](#dial-timeout)
  - [Operation timeouts](#operation-timeouts)
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
    "context"
    "crypto/tls"
    "log"
    "time"

    "github.com/NGRsoftlab/ldapper"
    "github.com/NGRsoftlab/ldapper/adapters"
)

func main() {
    ctx := context.Background()

    adapter := adapters.MSADAdapter{}

    limits := ldapper.DefaultSearchLimits()
    limits.TimeLimit = 30

    conn, err := ldapper.NewAuthenticatedLDAPper(
        ctx,
        "svc-reader@corp.example.com", "secret",       // bind credentials
        "DC=corp,DC=example,DC=com",                   // base DN for probe and user lookups
        []string{"dc1.corp.example.com", "dc2.corp.example.com"},
        636,        // port
        true,       // useSSL (LDAPS)
        false,      // skipTLS (must be false when useSSL is true)
        &tls.Config{MinVersion: tls.VersionTLS12},
        adapter,
        ldapper.WithSearchLimits(limits),
        ldapper.WithDialTimeout(5*time.Second),
    )
    if err != nil {
        log.Fatalf("connect: %v", err)
    }
    defer conn.Close()

    u, err := conn.GetUser(ctx, "jdoe", "DC=corp,DC=example,DC=com")
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
│    conn, _ := ldapper.NewAuthenticatedLDAPper(ctx, ...)            │
│    conn.GetUser(ctx, ...)  /  conn.GetCatalogTree(ctx, ...)  / ... │
└──────────────────────────────────┬─────────────────────────────────┘
                                   │
┌──────────────────────────────────▼─────────────────────────────────┐
│  LDAPper — public API                                              │
│                                                                    │
│  ldapper.go                        constructors + LDAPper struct   │
│  ldapper_connection.go             dial / failover / IsAlive /     │
│                                    Reconnect / EnsureAlive / Close │
│  ldapper_auth.go                   BindConn,               │
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
│                                    ListSingleLevelOUs,             │
│                                    WalkCatalogTree                │
│  ldapper_options.go                Option, SearchLimits,           │
│                                    OperationTimeouts, With/Set/Get │
│  ldapper_errors.go                 sentinel errors + classifiers    │
│  helpers.go                        attrsToMap, escapeFilterArgs,   │
│                                    parentDNOf, canonicalDN         │
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
│  StartTLS / Bind / Search /  │    │  Filters / Attrs / Casts /    │
│  SetTimeout / IsClosing /    │    │  BindIdentity                 │
│  Close                       │    │                               │
└──────────────┬───────────────┘    └──────────────┬────────────────┘
               │                                   │
   prod: *ldap.Conn                  prod: adapters.{MSAD, OPENLDAP,
   test: mocks.MockLDAPConn                ALDPRO, FREEIPA}Adapter
                                     test: fakeAdapter
                                     (ldapper_auth_test.go)

                               │
┌──────────────────────────────▼─────────────────────────────────────┐
│  go-ldap/ldap/v3                                                   │
└──────────────────────────────┬─────────────────────────────────────┘
                               │
                          LDAP server
```

The two interfaces are the only seams:

- **`interfaces.LDAPConn`** is a 6-method subset of `*ldap.Conn`.
  Production uses the real `*ldap.Conn`; tests inject
  `mocks.MockLDAPConn`.
- **`interfaces.CatalogAdapter`** is the *only* place LDAPper knows
  anything about directory schema. All filters, attribute lists, value
  casts and bind-principal translation go through it.

### `LDAPper` struct

```
LDAPper
├── opMu            sync.Mutex                      serializes all ops
│
├── catalogAdapter  interfaces.CatalogAdapter       schema-specific behavior
├── connection      interfaces.LDAPConn             active network connection
│
├── isAuthenticated bool                            set by BindConn
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
├── dialTimeout     time.Duration                   used by dialHost
└── opTimeouts      OperationTimeouts               applied by withCtx
```

Every search method funnels through `newSearchRequest(...)`, which injects
`searchLimits`. Changing limits at runtime (`SetSearchLimits`) is
therefore a single assignment with no plumbing.

`bindDN` is a subtle but useful field: `BindConn(ctx, username,
password, baseDN)` records `baseDN` so that later calls to
`CheckUserCredentials(ctx, username, password)` can look users up under
the same base DN without the caller repeating it.

`dialTimeout` is initialised to `constants.DefaultDialTimeout` (10s) by
the constructors. `WithDialTimeout(0)` (or `SetDialTimeout(0)`) disables
the explicit timeout and falls back to Go's `net.Dialer` default.

`opTimeouts` starts at zero (`Bind: 0, Search: 0`) which means "no
client-side timeout" — the operations rely on `SearchRequest.TimeLimit`
(server-side) and the caller's context deadline. Enabling
`WithOperationTimeout` adds a client-side deadline around each individual
`Bind` / `Search` call.

### Search flow (`GetUser` as example)

```
conn.GetUser(ctx, "jdoe", baseDN)
        │
        ├── catalogAdapter.SearchUserFilterTemplate()
        │       → "(uid=%s)" → fmt.Sprintf → "(uid=jdoe)"
        ├── catalogAdapter.UserAttrs()
        │       → []string{"cn", "mail", ...}
        │
        ▼
   searchSingleEntryLocked(ctx, kindUser, "jdoe", baseDN, template, attrs)
        │
        │   SizeLimit is hardcoded to 2 (ambiguity probe);
        │   TimeLimit comes from conn.searchLimits.
        ▼
   withCtxResult(ctx, opTimeouts.Search, …)
        │
        │   watchdog goroutine closes the connection
        │   if ctx is cancelled mid-flight
        ▼
   conn.connection.Search(req)  ─────────▶  LDAP server
        │
        ▼
   0 entries   → ErrNotFoundOrNotVisible
                 ("user \"jdoe\" not found or not visible")
   1 entry     → types.LDAPUser{DN, Attributes}
   >1 entries  → ErrAmbiguousResult
                 ("too many entries for user ...")
```

### Catalog tree flow (`GetCatalogTree`)

```
conn.GetCatalogTree(ctx, baseDN, maxDepth)
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
       drop if !baseDN.AncestorOfFold(entry.DN)      (caseIgnoreMatch)
       byDN[canonicalDN(info.DN)] = info
        │
        ▼
   attach each node to parentDNOf(info.DN)  →  tree roots
        │
        ▼
   DFS walk respects maxDepth (0 = no limit)
        │
        ▼
   types.CatalogTree{Tree: [...]}
```

Two important details:

- **`canonicalDN`** normalises attribute types and values to lowercase,
  sorts multi-valued RDN attributes by `type=value`, trims whitespace,
  and preserves RDN order. This is not a full RFC 4517 matching-rules
  implementation — it deliberately over-merges case-differing DNs so
  equivalent entries link correctly. Malformed DNs fall back to a
  lowercased raw string.
- **`AncestorOfFold`** (not `AncestorOf`) is used so case-differing
  ancestors still match — otherwise subtree entries with different
  attribute-type case would be silently dropped.

This is the whole reason `GetCatalogTree` is O(1) round-trips instead of
O(N): the server streams pages of the subtree, and the parent-child
wiring is done locally in `O(N)` with a single `map[string]*OUNormalizedInfo`.

---

## Core concepts

### Connections

`LDAPper` is created with one of two constructors. Both take a
`context.Context` as their first argument; that context governs the
initial dial (and, for the authenticated variant, the initial Bind).

```go
// Unauthenticated: dials a host but performs no bind. Suitable for
// directories that allow anonymous reads.
func NewLDAPper(
    ctx context.Context,
    hosts []string,
    port uint,
    useSSL, skipTLS bool,
    tlsCfg *tls.Config,
    catalogAdapter interfaces.CatalogAdapter,
    opts ...Option,
) (*LDAPper, error)

// Authenticated: dials, then binds as `username` and probes `baseDN`
// with a base-object search to confirm the tree is reachable under the
// bound identity. No post-bind user lookup is performed, so service
// principals that do not match UserObjectFilter are accepted. No user
// entry is returned — call GetUser to fetch it. `username` and `baseDN`
// are cached for later CheckUserCredentials calls.
func NewAuthenticatedLDAPper(
    ctx context.Context,
    username, password, baseDN string,
    hosts []string,
    port uint,
    useSSL, skipTLS bool,
    tlsCfg *tls.Config,
    catalogAdapter interfaces.CatalogAdapter,
    opts ...Option,
) (*LDAPper, error)
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
  internally by `formatHost`).
- **`dialConn` is a package-level variable** (of type `DialFunc`) so
  tests can swap it out via `withDialConn(t, fn)` without touching
  production code.

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
    // Contract: templates use fmt-style positional verbs (%[N]s). All
    // arguments are escaped with ldap.EscapeFilter by LDAPper before
    // substitution, so implementers must return raw (unescaped) attribute
    // values.
    SearchUserFilterTemplate()       string  // 1 arg
    SearchUserGroupsFilterTemplate() string  // N args, use with the args helper
    SearchUserGroupsFilterTemplateArgs(ldapUser types.LDAPUser) []any
    SearchOUFilterTemplate()    string       // 1 arg
    SearchGroupFilterTemplate() string       // 1 arg

    // Attribute lists
    UserAttrs()  []string
    OUAttrs()    []string
    GroupAttrs() []string

    // BindIdentity converts a caller-supplied login into the principal
    // that is passed verbatim to LDAPConn.Bind. See "Writing your own
    // adapter" below for the contract.
    BindIdentity(login, baseDN string) (string, error)
}
```

Some adapters additionally implement `interfaces.PrimaryGroupResolver`:

```go
type PrimaryGroupResolver interface {
    ResolvePrimaryGroupDN(ctx context.Context, user types.LDAPUser, ldapConn LDAPConn) (string, error)
}
```

`GetUserGroups` checks for this interface via a type assertion. Only
`MSADAdapter` implements it (for AD's `primaryGroupID` resolution); the
others deliberately do not, because their schemas have no such concept
and the presence of the interface would cause `GetUserGroups` to try to
resolve a non-existent attribute.

**`PrimaryGroupResolver` implementations MUST use only the provided
`LDAPConn` and MUST NOT call `LDAPper` methods** — the resolver is
invoked while `opMu` is already held, so any re-entry into `LDAPper`
would deadlock.

The adapter is the only place LDAPper assumes anything about schema. See
[Shipped adapters](#shipped-adapters) for the four adapters that ship
with the library.

### Search limits

Every search request is built by a single helper that applies
**connection-level** `SearchLimits`:

```go
type SearchLimits struct {
    SizeLimit     int   // 0 = server default
    TimeLimit     int   // seconds; 0 = server default
    MaxPages      int   // 0 = no page budget
    MaxEntries    int   // 0 = no entry budget
    RequirePaging bool  // true = reject paged results without paging control
}
```

```go
conn, _ := ldapper.NewLDAPper(
    ctx, hosts, 636, true, false, tlsCfg, adapter,
    ldapper.WithSearchLimits(ldapper.SearchLimits{
        SizeLimit:  500,
        TimeLimit:  30,
        RequirePaging: true,
    }),
)

// Later, temporarily raise limits for one heavy pass:
old := conn.GetSearchLimits()
conn.SetSearchLimits(ldapper.SearchLimits{TimeLimit: 120})
tree, _ := conn.GetCatalogTree(ctx, "DC=corp,DC=example,DC=com", 0)
conn.SetSearchLimits(old)
```

Field semantics:

- **`SizeLimit`** — server-enforced total across the **entire paged
  operation** (RFC 2696 semantics). `0` means "no client-side size limit;
  use the server default".
- **`TimeLimit`** — server-side time limit in seconds. `0` means "no
  client-side time limit; use the server default".
- **`MaxPages`** — client-side page budget. When exceeded, `searchPaged`
  returns `ErrPartialResult` together with the entries collected so far.
- **`MaxEntries`** — client-side entry budget. Complements `SizeLimit`:
  it works even against servers that ignore `SizeLimit`. Truncates the
  slice and returns `ErrPartialResult`.
- **`RequirePaging`** — when `true`, a server that ignores the paging
  control is treated as a protocol violation and `ErrPartialResult` is
  returned. Defaults to `true` in `DefaultSearchLimits()`. Enable this
  when completeness matters (e.g. security decisions based on "user
  belongs to ALL groups").

Negative values are clamped to `0`. `SetSearchLimits` takes `opMu`, so
it is safe to call concurrently with searches — but the value change
takes effect on the **next** request.

**NB:** `WithSearchLimits` replaces the **entire struct**. Fields
omitted from the argument get Go zero values, **not** the values from
`DefaultSearchLimits()`. In particular:

- `TimeLimit: 0` means "no server-side time limit" (not 30 seconds);
- `RequirePaging: false` means "silently accept missing paging control"
  (not `true`).

Use the read-modify-write pattern with `DefaultSearchLimits()` if you
want to keep the defaults for a subset of fields:

```go
limits := ldapper.DefaultSearchLimits()
limits.SizeLimit = 100
conn, _ := ldapper.NewLDAPper(..., ldapper.WithSearchLimits(limits))
```

### Dial timeout

```go
conn, _ := ldapper.NewLDAPper(
    ctx, hosts, 389, false, true, nil, adapter,
    ldapper.WithDialTimeout(5*time.Second),
)

// At runtime:
conn.SetDialTimeout(10 * time.Second)
fmt.Println(conn.GetDialTimeout())  // 10s
```

- After construction: `dialTimeout == constants.DefaultDialTimeout`
  (`10s`). This is the **actual** default, not 0.
- Explicitly setting it to `0` (via `WithDialTimeout(0)` or
  `SetDialTimeout(0)`) means "no explicit timeout; use Go's `net.Dialer`
  default".
- Negative values are clamped to `0`.
- The timeout is applied as `net.Dialer.Timeout` during the initial dial
  and re-applied during the `StartTLS` handshake (so the handshake cannot
  block indefinitely). After the handshake, `SetTimeout(0)` resets the
  connection so subsequent operations are not capped by the dial timeout.
- `Reconnect` and `EnsureAlive` use the same dial timeout.

### Operation timeouts

`OperationTimeouts` are **client-side** timeouts applied around
individual `Bind` and `Search` calls. They complement — but do not
replace — `SearchLimits.TimeLimit`, which is a **server-side** limit.

```go
type OperationTimeouts struct {
    Bind   time.Duration
    Search time.Duration
}
```

```go
conn, _ := ldapper.NewLDAPper(
    ctx, hosts, 389, false, true, nil, adapter,
    ldapper.WithOperationTimeout(ldapper.OperationTimeouts{
        Bind:   5 * time.Second,
        Search: 30 * time.Second,
    }),
)
```

- Zero value disables the corresponding timeout (`Bind: 0, Search: 0` is
  the default — backwards compatible).
- Negative durations are clamped to zero.
- The timeout is applied via `LDAPConn.SetTimeout` (which is part of the
  `LDAPConn` interface contract — every implementation, including mocks,
  must support it). After the operation, the timeout is reset to zero so
  it does not cap subsequent operations.
- In addition, `withCtx`/`withCtxResult` respect the caller's context
  deadline: the effective timeout is `min(opTimeout, ctx.Deadline - now)`.

---

## Shipped adapters

| Adapter                     | Directory                          | Notes |
|-----------------------------|------------------------------------|-------|
| `adapters.MSADAdapter`      | Microsoft Active Directory         | Uses `objectCategory`-based filters; recursive group search via the `LDAP_MATCHING_RULE_IN_CHAIN` OID (`1.2.840.113556.1.4.1941`); prefers `thumbnailPhoto` over `jpegPhoto`; implements `PrimaryGroupResolver` to resolve `primaryGroupID` into a group DN. |
| `adapters.OPENLDAPAdapter`  | OpenLDAP (and most RFC-4519 dialects) | Handles three group models — `groupOfNames` (via `member`), `groupOfUniqueNames` (via `uniqueMember`), and `posixGroup` (via `memberUid`). User search keyed by `uid` **or** `entryDN`. Short-form bind (`alice`) is expanded to `uid=<login>,<baseDN>`. |
| `adapters.ALDPROAdapter`    | ALD Pro                            | Recognizes `rbta-org-unit` alongside `organizationalUnit`; department mapped from `rbtadp`; two-branch group filter — `member`/`memberIndirect` (DN) for `groupOfNames`/`ipaUserGroup`/`posixGroup`, **and** `memberUid` (uid) for `posixGroup`. Bind is pass-through (UPN/DN). |
| `adapters.FREEIPAAdapter`   | FreeIPA                            | Recognizes `nsContainer` alongside `organizationalUnit`; department is intentionally **not** mapped; group lookup matches DN-valued `member`/`memberIndirect` **and** uid-valued `memberUid`. Short-form bind is expanded to `uid=<login>,cn=users,cn=accounts,<baseDN>`. |

### Adapter-specific gotchas

- **`MSADAdapter`** — `GetUser` matches on `sAMAccountName` /
  `userPrincipalName` / `distinguishedName`. The value passed to
  `NewAuthenticatedLDAPper` must therefore be a valid AD principal (UPN,
  sAMAccountName, or DN). Group search uses
  `LDAP_MATCHING_RULE_IN_CHAIN`, which **Samba 4 AD DC** and Microsoft AD
  both support — OpenLDAP and FreeIPA do **not**.
- **`OPENLDAPAdapter`** — the user filter uses the indexed placeholder
  `%[1]s` so the same argument is substituted into both `uid=` and
  `entryDN=`, allowing lookup by either short name or full DN. The
  user-groups filter is a union of three branches:
  ```
  (|(&(objectClass=groupOfNames)(member=%[1]s))
    (&(objectClass=groupOfUniqueNames)(uniqueMember=%[1]s))
    (&(objectClass=posixGroup)(memberUid=%[2]s)))
  ```
  with args `[user.DN, user.uid]`.
- **`ALDPROAdapter`** — the user-groups filter:
  ```
  (|(&(|(objectClass=groupOfNames)(objectClass=ipaUserGroup)(objectClass=posixGroup))
      (|(member=%[1]s)(memberIndirect=%[1]s)))
    (&(objectClass=posixGroup)(memberUid=%[2]s)))
  ```
  with args `[user.DN, user.uid]`.
- **`FREEIPAAdapter`** — the user-groups filter uses the same shape as
  ALDPro (two positional args, DN and uid).
- **`BindIdentity`**:
  - `MSAD` / `ALDPro` — pass-through. The server performs the mapping.
  - `OPENLDAP` — short-form login is expanded to `uid=<login>,<baseDN>`.
  - `FreeIPA` — short-form login is expanded to
    `uid=<login>,cn=users,cn=accounts,<baseDN>` (the chain is built
    deepest-first: `accounts` → `users` → `uid`, so the final DN is
    `uid=alice,cn=users,cn=accounts,<baseDN>`).
- **`GetNormalizedOUInfoFromEntry.Name`** — all shipped adapters derive
  `Name` from the **first RDN** of `entry.DN` (via the shared helper
  `ouNameFromDN`), not from the `name`/`ou` attribute. Malformed DNs fall
  back to the whole string instead of crashing.
- **`GetNormalizedOUInfoFromEntry.OU`** — MSAD sets `OU` to the **full
  entry DN**; the other three adapters read the `ou` attribute, with
  `cn` fallback for ALDPro's `rbta-org-unit` and FreeIPA's `nsContainer`.

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
- **`Company`** — MSAD uses the `company` attribute, the other three use `o`.
- **`Photo`** — only MSAD falls back from `thumbnailPhoto` to `jpegPhoto`;
  the other three read `jpegPhoto` only and do **not** consult
  `thumbnailPhoto`.
- **`Country` / `City` / `Index`** — OpenLDAP hardcodes these to empty
  regardless of the entry's attributes.

---

## API overview

### Authentication

```go
// Bind as `username` and store the credentials + base DN for later use.
err := conn.BindConn(ctx, username, password, baseDN)

// Verify a user's password against an already-authenticated connection,
// then rebind back to the service account.
user, err := conn.CheckUserCredentials(ctx, username, password)
```

`BindConn`:

- Stores username, password and baseDN on the connection.
- Performs the bind first, then probes baseDN with a base-object search
  to confirm the tree is reachable under the bound identity. No post-bind
  user lookup is performed, and no `*types.LDAPUser` is returned — call
  `GetUser` afterwards if you need the user entry. If the bind fails,
  the base-DN probe is never issued and the error is
  `ErrInvalidCredentials` (testable with `errors.Is`).
- On success, caches `isAuthenticated=true`, `bindUser`, `bindPassword`,
  `bindDN`. `bindUser` is the value returned by `BindIdentity`, **not**
  the raw login — that's what `Reconnect` replays.
- On any failure, closes the connection and invalidates the cached
  credentials (RFC 4513 §4 — a failed Bind transitions the session to
  anonymous; a successful Bind whose base-DN probe failed leaves the
  session identified as an unverified principal).

`CheckUserCredentials`:

- Requires `isAuthenticated == true` (i.e. `BindConn` or
  `NewAuthenticatedLDAPper` was called) **and** a live connection.
  Otherwise returns `ErrNotAuthenticated` or `ErrClosed` respectively.
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
res, err := conn.CustomSearch(ctx, &ldap.SearchRequest{...})

// Same, with automatic paging applied on top of the request's controls.
// Base DN is validated; result is the concatenation of all pages.
entries, err := conn.CustomSearchPaged(ctx, &ldap.SearchRequest{...})

// Fetch a single user by the adapter's user filter template.
user, err := conn.GetUser(ctx, "jdoe", baseDN)

// Fetch DNs of all groups the user belongs to.
groups, err := conn.GetUserGroups(ctx, "jdoe", baseDN)

// Fetch a single group by its cn.
group, err := conn.GetGroup(ctx, "admins", baseDN)

// Fetch a single OU by its ou attribute value (e.g. "Sales").
ou, err := conn.GetOU(ctx, "Sales", baseDN)

// Fetch every user under an OU DN (subtree search, adapter user filter).
users, err := conn.GetOUUsers(ctx, "OU=Staff,DC=corp,DC=example,DC=com")
```

- **`GetUser`, `GetGroup`, `GetOU`** — single-object lookups. Each uses
  `SizeLimit=2` internally to detect duplicates and returns:
  - `ErrNotFoundOrNotVisible` if zero entries match,
  - `ErrAmbiguousResult` if more than one entry matches.

  `ErrNotFoundOrNotVisible` is returned (not `ErrNotFound`) because
  LDAP cannot distinguish "the object does not exist" from "the object is
  hidden by ACL". Never infer "does not exist" from this error in
  security-sensitive paths.
- **`GetUserGroups`** — calls `GetUser` first, then applies the adapter's
  `SearchUserGroupsFilterTemplate` / `SearchUserGroupsFilterTemplateArgs`
  with `[]string{"1.1"}` (OID for "no attributes"), so only DNs come back
  from the server. Returns group **DNs** (not `cn` values). If the adapter
  implements `PrimaryGroupResolver` (only MSAD does), the primary group
  DN is appended to the result.
- **`GetOUUsers`** — takes a **DN**, not a short `ou` name. Uses the
  adapter's `UserObjectFilter` and `UserAttrs` to list all users under
  the subtree, subject to paging.
- **`GetOU`** — takes the short `ou` value (e.g. `"Sales"`) plus a base DN.
- **`GetGroup`** — takes the short `cn` value.

All of these are safe to call concurrently: `opMu` serializes the
underlying LDAP operations.

### Catalog tree discovery

```go
tree, err := conn.GetCatalogTree(ctx, "DC=corp,DC=example,DC=com", 2)
```

- Performs **one paged subtree search** (`ControlPaging`, page size
  `constants.DefaultCatalogSearchPageSize = 1000`) and builds the `OU`
  tree on the client.
- Filters out entries that are not strict descendants of `baseDN`
  (via `ldap.DN.AncestorOfFold`) — misbehaving servers and cross-tree
  referrals cannot leak foreign entries into the result.
- Skips malformed DNs returned by the server rather than aborting.
- Nodes whose parent is **not** in the fetched set (e.g. server-side
  filtering) are promoted to roots of `tree.Tree`.
- `maxDepth` trims the resulting tree: `0` = no limit, `1` = roots only,
  `2` = roots + first level, etc. For `maxDepth == 1`, the tree is fetched
  with `ScopeSingleLevel` — a single round-trip, no full subtree read.
- If the server returns `SizeLimitExceeded` after at least one page, the
  partial tree is returned along with `ErrPartialResult` — callers can
  choose to accept the partial result or bail out.
- A walk error discards the partial tree — the returned
  `types.CatalogTree.Tree` is always non-nil but empty on failure.

```go
// Root-level OUs only (single-level scope, one round-trip):
roots, err := conn.ListSingleLevelOUs(ctx, "DC=corp,DC=example,DC=com")

// Direct children of an OU (same as ListSingleLevelOUs, but explicit):
children, err := conn.GetSubOUs(
    ctx,
    "OU=Staff,DC=corp,DC=example,DC=com",
    ldap.ScopeSingleLevel,
)

// All descendants of an OU (subtree scope):
descendants, err := conn.GetSubOUs(
    ctx,
    "OU=Staff,DC=corp,DC=example,DC=com",
    ldap.ScopeWholeSubtree,
)

// Depth-first walk without building a tree:
err := conn.WalkCatalogTree(ctx, baseDN, 0,
    func(ctx context.Context, depth int, node *types.OUNormalizedInfo) error {
        log.Printf("%*s%s", depth*2, "", node.Name)
        return nil
    })
```

`GetSubOUs` accepts only `ldap.ScopeSingleLevel` and
`ldap.ScopeWholeSubtree`; `ldap.ScopeBaseObject` is rejected with
`ErrInvalidArgument` (it would always return an empty list). The base DN
itself is always excluded — "sub" means strict descendants.

### Health checks & reconnection

```go
if !conn.IsAlive(ctx) {
    _ = conn.Reconnect(ctx)
}

// Or the combined form, suitable as a pre-flight check:
if err := conn.EnsureAlive(ctx); err != nil {
    return err
}
```

- **`IsAlive(ctx)`** — checks the local connection state (`IsClosing`)
  and issues a cheap root-DSE search with hard-coded `SizeLimit=1,
  TimeLimit=1`. Intentionally independent of the user-configured search
  limits.
- **`Reconnect(ctx)`** — closes the current connection, dials any host in
  `hosts` again, and — if the connection was authenticated — re-binds with
  the stored credentials. On rebind failure, the new connection is
  closed, `isAuthenticated` is cleared, and subsequent operations return
  `ErrClosed` until `BindConn` is called again. `bindDN` is
  preserved, so `CheckUserCredentials` continues to work after a
  successful reconnect.
- **`EnsureAlive(ctx)`** — `IsAlive()` first; reconnect only when stale.
  **After `Close()` the client is terminal**: `EnsureAlive` returns
  `ErrClosed` and does **not** attempt to reconnect. That is the
  documented contract — a closed client cannot be revived.
- **`Close()`** — idempotent, best-effort (swallows `Close` errors).
  Sets `closed=true` which is terminal.

---

## Errors

All public functions return sentinel errors that can be tested with
`errors.Is`. Where sensible, the original `*ldap.Error` / `net.Error` is
preserved in the wrapped chain (`errors.As` still works).

| Sentinel                       | Meaning |
|--------------------------------|---------|
| `ErrInvalidArgument`           | Config or argument validation failed (empty/invalid DN, empty username, invalid host, invalid port, `useSSL && skipTLS`, nil TLS config, nil adapter, …). |
| `ErrInvalidCredentials`        | Bind rejected as bad credentials. Also returned by `CheckUserCredentials` when the user is missing (enumeration protection). |
| `ErrInvalidCredentialsOrUnknown` | Bind-path classifier could not map the LDAP result code to a specific sentinel. Treat as inconclusive, not as a rejection. |
| `ErrNotAuthenticated`          | `CheckUserCredentials` called on a connection without a successful prior `BindConn`/`NewAuthenticatedLDAPper`, or the service rebind was lost. |
| `ErrUnavailable`               | Directory unreachable (dial failure, `LDAPResultUnavailable`/`Busy`/`ServerDown`, transport errors). |
| `ErrTimeout`                   | Timeout / deadline exceeded (`LDAPResultTimeout`, `LDAPResultTimeLimitExceeded`, `net.Error.Timeout`, `context.DeadlineExceeded`). |
| `ErrClosed`                    | The connection is nil (never initialized, or `Close()` was called, or a failed reconnect left it nil). |
| `ErrNotFound`                  | Search produced a definitive "no such object" (`LDAPResultNoSuchObject`). Rare — subtree searches usually return zero entries instead. |
| `ErrNotFoundOrNotVisible`      | Subtree search returned zero entries. The object may not exist, or may be hidden by ACL. Do not infer "does not exist". |
| `ErrAmbiguousResult`           | Single-object lookup matched more than one entry. |
| `ErrPartialResult`             | Paged search was interrupted by `SizeLimitExceeded`, budget exhaustion, or a missing paging control (when `RequirePaging` is true). The returned slice/tree is partial. |
| `ErrInsufficientAccess`        | Bind path returned `LDAPResultInsufficientAccessRights`. Surfaced by `classifySensitiveBindError`. |

Bind-path failures **never** wrap the raw LDAP text — this prevents
credential leakage into logs when the server echoes back the submitted
password. All bind errors are mapped to bare sentinels by
`classifySensitiveBindError`.

BindConn can return ErrNotFoundOrNotVisible if baseDN is unreachable under 
the bound identity (for example, when the bind principal has no read access to the tree root). 
This is produced by the base-DN probe, not by a user lookup.

Non-bind failures use `classifyLDAPError`, which wraps both the sentinel
and the original error:

```go
if errors.Is(err, ldapper.ErrNotFoundOrNotVisible) { /* ... */ }

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
        Name:     ouNameFromDN(e.DN),          // first RDN value
        OU:       e.GetAttributeValue("ou"),
        Children: make([]*types.OUNormalizedInfo, 0),
    }
}

func (MyAdapter) UserObjectFilter()  string   { return "(&(objectClass=inetOrgPerson))" }
func (MyAdapter) GroupObjectFilter() string   { return "(objectClass=groupOfNames)" }
func (MyAdapter) OUObjectFilter()    string   { return "(objectClass=organizationalUnit)" }

func (MyAdapter) SearchUserFilterTemplate()  string { return "(&(objectClass=inetOrgPerson)(uid=%[1]s))" }
func (MyAdapter) SearchGroupFilterTemplate() string { return "(&(objectClass=groupOfNames)(cn=%[1]s))" }
func (MyAdapter) SearchOUFilterTemplate()    string { return "(&(objectClass=organizationalUnit)(ou=%[1]s))" }

func (MyAdapter) SearchUserGroupsFilterTemplate() string {
    return "(&(objectClass=groupOfNames)(member=%[1]s))"
}
func (MyAdapter) SearchUserGroupsFilterTemplateArgs(u types.LDAPUser) []any {
    return []any{u.DN}
}

func (MyAdapter) UserAttrs()  []string { return []string{"uid", "cn", "mail"} }
func (MyAdapter) OUAttrs()    []string { return []string{"ou", "description"} }
func (MyAdapter) GroupAttrs() []string { return []string{"cn", "member"} }

// BindIdentity returns the principal passed verbatim to LDAPConn.Bind.
func (MyAdapter) BindIdentity(login, baseDN string) (string, error) {
    if login == "" {
        return "", fmt.Errorf("empty login")
    }
    // Pass-through: server decides whether `login` is a valid principal.
    return login, nil
}
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
- Schema stores DN-valued `member` → use `(member=%[1]s)` and
  return `[user.DN]`.
- Schema stores uid-valued `memberUid` → use `(memberUid=%[1]s)` and
  return `[user.GetAttributeValue("uid")]`.
- Both (like `OPENLDAPAdapter` / `ALDPROAdapter` /
  `FREEIPAAdapter`) → use a union with two placeholders and return
  both values in order.
4. **`GetNormalizedOUInfoFromEntry` must return a non-nil `Children`
   slice** — `GetCatalogTree` may append to it.
5. **`DistinguishedName`** in `GetNormalizedUserInfo` must come from
   `ldapUser.DN` (the struct field), not from an LDAP attribute.
6. **`BindIdentity`** must return something that the server accepts as a
   Simple Bind principal. If the adapter accepts both DN and short-form
   logins, `SearchUserFilterTemplate` must match both (typically by
   unioning the schema attribute with `entryDN=`). See
   `OPENLDAPAdapter`/`FREEIPAAdapter` for examples.
7. **`PrimaryGroupResolver`** — implement only if your schema has a real
   concept of "primary group" that is not covered by ordinary group
   membership (like AD's `primaryGroupID`). The resolver MUST use only
   the provided `LDAPConn` and MUST NOT call `LDAPper` methods — the lock
   is already held.

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
| `DefaultDialTimeout`             | `10s`   | Initial dial / StartTLS-handshake timeout |
| `DefaultStartTLSTimeout`         | `30s`   | Used when no explicit dial timeout is set |

Options (`type Option func(*LDAPper)`):

| Option                                | Effect |
|---------------------------------------|--------|
| `WithSearchLimits(SearchLimits)`      | Replace connection-level search limits (whole struct) |
| `WithDialTimeout(d)`                  | Override dial / StartTLS-handshake timeout |
| `WithOperationTimeout(OperationTimeouts)` | Override client-side Bind/Search timeouts |
| `SetSearchLimits(SearchLimits)`       | Runtime replacement of search limits |
| `GetSearchLimits()`                   | Read current search limits |
| `SetDialTimeout(d)`                   | Runtime override of dial timeout |
| `GetDialTimeout()`                    | Read current dial timeout |
| `SetOperationTimeout(OperationTimeouts)` | Runtime override of operation timeouts |
| `GetOperationTimeout()`               | Read current operation timeouts |

Negative values are clamped to `0` ("no limit"/"Go default"). The zero
value of `OperationTimeouts` disables the client-side timeout, so it is
backwards compatible with code that does not configure it.

`With*` options are applied by `NewLDAPper` before the object is
returned to the caller; there is no concurrent access at that point.
`Set*`/`Get*` take `opMu`, so they are safe to call concurrently with
search operations.

---

## Testing

The package is designed for testability at every layer.

### Unit tests

Unit tests run without any network access and cover:

- **Input validation** — `validators_test.go`: DN / base DN / host /
  port / TLS-config / option validation, `formatHost` IPv4-vs-IPv6.
- **Core helpers** — `helpers_test.go`: `attrsToMap`,
  `escapeFilterArgs`, `parentDNOf` (including multi-valued RDN
  preservation), `canonicalDN` (case folding, RDN-order significance,
  escaped-comma round-trip, malformed fallback).
- **Errors** — `ldapper_errors_test.go`: `classifyLDAPError`,
  `classifySensitiveBindError` (including the "no secret leak" regression
  test), `isTimeoutError`, `isTransportError`.
- **Options & limits** — `ldapper_options_test.go`:
  `With/Set/GetSearchLimits`, `With/Set/GetDialTimeout`,
  `With/Set/GetOperationTimeout`, clamping, `-race` guards.
- **Search primitives** — `ldapper_search_test.go`:
  `searchSingleEntryLocked`, `searchPaged` (single page, multiple pages,
  `MaxPages`/`MaxEntries` budgets, `RequirePaging` on/off, repeated-cookie
  runaway, `SizeLimitExceeded`-preserves-entries, context-cancelled
  during/between pages, raw error propagation),
  `CustomSearch`, `CustomSearchPaged`.
- **Connection** — `ldapper_connection_test.go`: `withCtx` /
  `withCtxResult` (deadline merging, watchdog, cancellation invalidating
  the connection), `Close`, `IsAlive`, `EnsureAlive`, `Reconnect`,
  `dialAnyLocked`. Tests that swap the package-level `dialConn` seam are
  **not** parallel — the swap is process-wide.
- **Auth** — `ldapper_auth_test.go`: `invalidateAuthLocked`,
  `restoreServiceBindLocked`, `bindConnLocked` / `verifyBaseDNLocked`
  (success path, 0-entry base probe, transport failure), `BindConn`,
  `CheckUserCredentials` (user-not-found masking, restore-failure path,
  context-cancelled path).
- **User / group / OU ops** — `ldapper_user_ops_test.go`,
  `ldapper_group_ops_test.go`, `ldapper_ou_ops_test.go`.
- **Catalog tree** — `ldapper_catalog_tree_discovery_test.go`:
  `WalkCatalogTree` (DFS order, depth truncation, deduplication,
  callback errors, context cancellation), `GetCatalogTree`,
  `GetSubOUs`, `ListSingleLevelOUs`.
- **Constructors** — `ldapper_test.go`: `NewLDAPper` /
  `NewAuthenticatedLDAPper` validation and defaults, options, TLS clone,
  hosts copy, dial failure, auth-failure propagation. Note that the
  **success** path of `NewAuthenticatedLDAPper` requires a live
  connection and is covered by integration tests only.
- **Shipped adapters** — `adapters/*_adapter_test.go`: user-info
  mapping, OU mapping, filter templates compiled by `ldap.CompileFilter`,
  args ordering, attribute lists, distinguishing-attribute guards,
  MSAD `ResolvePrimaryGroupDN` child-domain regression, FreeIPA
  `BindIdentity` chain order.

```bash
go test ./...
go test -race -count=20 ./...
go vet ./...
```

Test helpers:

- **`utils_test.go`** (package `ldapper`):
  `newLDAPEntry(dn, attrs) *ldap.Entry` — builds a `*ldap.Entry` with
  both `Values` and `ByteValues` populated so `GetRawAttributeValue`
  works in tests.
- **`ldapper_connection_test.go`**: `withDialConn(t, fn)` — swaps the
  package-level `dialConn` seam for the duration of a test and restores
  it via `t.Cleanup`.
- **`ldapper_auth_test.go`**: `fakeAdapter` — a configurable
  `CatalogAdapter` stub used by core tests; each field defaults to an
  empty value. `newAuthTestLDAPper`, `markAuthenticated` helpers.
- **`ldapper_search_test.go`**: `newTestLDAPper`, `searchCookie`,
  `pagedResponse` — paging helpers.
- **`ldapper_test.go`**: `stubTLSCfg`, `connectStub`.
- **`adapters/helpers_test.go`** (package `adapters`):
  - `newLDAPUser(dn, attrs)` — builds a `types.LDAPUser` fixture with a
    non-nil attribute map.
  - `attrMap(map[string]string) map[string][]string` — shorthand for
    single-valued attributes.
  - `newLDAPEntry(dn, attrs) ldap.Entry` — **value** form, matches the
    signature of `GetNormalizedOUInfoFromEntry`. Note that the
    `ldapper` package has a **pointer**-returning `newLDAPEntry` in
    `utils_test.go` — same name, different package, different form.
  - `requireValidFilter(t, filter)` — fails the test if
    `ldap.CompileFilter` rejects the filter, with the raw text included
    in the diagnostic.

> **Tip:** tests that swap `dialConn` **must not** call `t.Parallel()`.
> The swap is process-wide; parallel tests would stomp on each other.
> `withDialConn` provides the pattern.

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
  duplicate detection (`ErrAmbiguousResult`). Breaks a user's password
  via direct LDAP Modify and verifies that `Reconnect` on the stale
  cached password fails and leaves the client unusable (`ErrClosed`).
- **MS AD** — real Samba 4 AD DC, exercising the AD-only
  `LDAP_MATCHING_RULE_IN_CHAIN` group expansion and the
  `PrimaryGroupResolver` path (Domain Users must appear in
  `GetUserGroups` output). Gracefully skips if the container cannot be
  started.
- **FreeIPA** — real FreeIPA container, verifying that
  `ipa group-add-member` populates DN-valued `member`/`memberIndirect`,
  and cross-checking `GetUserGroups` against an independent
  `CustomSearch` with the same filter. Gracefully skips if the container
  cannot be started. `Reconnect`-rebind-failure is intentionally
  `t.Skip`-ed here (FreeIPA password rotation is not scriptable
  non-interactively); the equivalent path is covered by the OpenLDAP
  suite.
- **ALDPro** — stock OpenLDAP augmented with a custom schema mirroring
  the ALDPro-specific objectClass `rbta-org-unit` and `rbtadp` attribute.
  The `rbta-org-unit` class is **cn-named** (`SUP top MUST cn`, it does
  *not* inherit from `organizationalUnit`), which is what exercises the
  `ou → cn` fallback in `GetNormalizedOUInfoFromEntry` and the `cn=`
  arm of `SearchOUFilterTemplate`. The suite also rewrites the default
  `olcAccess` through `cn=config` right after startup:
  `attrs=userPassword by anonymous auth` (Simple Bind compares the hash
  as an anonymous identity — without this every non-root bind fails with
  `LDAP Result Code 49`) and `to * by users read` (without this every
  authenticated search returns `LDAP Result Code 32 "No Such Object"`
  even though the data is present). Exercises both branches of the
  dual-branch group filter, and confirms that `OUObjectFilter` matches
  both standard `organizationalUnit` and ALDPro-specific
  `rbta-org-unit` entries. Uses a dedicated `svc-reader` inetOrgPerson
  for authenticated binds because the osixia admin is a
  `simpleSecurityObject` that `UserFilter` does not match.

All integration tests assert error conditions with `errors.Is(err,
ldapper.Err*)` against the sentinel contract — not against error text —
so message rewording does not break them.

---

## License

**Distributed under the terms specified in the [`LICENSE`](LICENSE) file
at the repository root.** The file is the authoritative source — this
section is only a pointer.

Copyright © 2020–2026 [NGR Softlab](https://ngrsoftlab.ru). All rights
reserved.

### Using LDAPper in your project

Before adding LDAPper as a dependency, check the `LICENSE` file for the
exact terms (permission to use, redistribute, modify, sublicense,
commercial use, warranty disclaimers, etc.). If your use case is not
covered by the file (e.g. redistribution in a closed-source product,
SaaS deployment with non-standard terms), contact NGR Softlab for a
commercial agreement.

### Third-party dependencies

LDAPper itself is small; the bulk of the dependency tree comes from
`testcontainers-go`, and only the `go-ldap/ldap/v3` dependency is pulled
in at **build time** for production code. Test-only dependencies do not
ship in binaries that import LDAPper.

| Dependency                                              | Role        | License     |
|---------------------------------------------------------|-------------|-------------|
| `github.com/go-ldap/ldap/v3`                            | runtime     | MIT         |
| `github.com/stretchr/testify`                           | tests only  | MIT         |
| `github.com/testcontainers/testcontainers-go` + indirect | tests only  | MIT (various) |

Transitive dependencies are listed in `go.mod`; their licenses are
declared in their respective `LICENSE` files. Run
`go run github.com/google/go-licenses@latest report ./...` for an
up-to-date, machine-generated inventory.