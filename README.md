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
  `ErrInvalidCredentials`, `ErrInsufficientAccess`, …) designed for
  `errors.Is` / `errors.As`.
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
  - [mTLS](#mtls)
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
        true,       // useLDAPS
        false,      // skipStartTLS (must be false when useLDAPS is true)
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
│                                    + runWithWatchdog (per-op       │
│                                      timeout & ctx watchdog)       │
│  ldapper_auth.go                   BindConn,                       │
│                                    CheckUserCredentials            │
│  ldapper_search.go                 searchPaged,                    │
│                                    searchSingleEntryLocked,        │
│                                    newSearchRequest,               │
│                                    renderFilterTemplate,           │
│                                    CustomSearch, CustomSearchPaged │
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
│                                    parentDNOf, canonicalDN,        │
│                                    escapeCanonicalValue            │
│  validators.go                     validateDN / validateBaseDN /   │
│                                    validateHost / formatHost /     │
│                                    isIPLiteral                     │
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

### Cancellation & watchdog

`go-ldap`'s `Bind` / `StartTLS` are not context-aware. LDAPper bridges the
gap with a small watchdog primitive in `ldapper_connection.go`:

- `withCtx` / `withCtxResult` — the two operation wrappers. They compute
  the effective timeout as `min(opTimeout, ctx.Deadline - now)`, apply
  it via `LDAPConn.SetTimeout`, run the operation, and reset the
  timeout to zero afterwards.
- `runWithWatchdog` — the shared primitive. If the caller supplies a
  cancellable context, a goroutine is spawned that closes the
  underlying connection when `ctx` is done. The stop/join and the
  timeout reset happen inside a `defer`, so a panic inside the
  operation cannot leak the goroutine or leave a stale timeout behind.
- `ctx.Err()` is treated as the authoritative signal of "was the
  operation aborted" (a goroutine-local flag would race with the
  operation returning). When it fires, the connection is published
  unusable (`connection = nil`, `invalidateAuthLocked`) and the caller
  receives a wrapped `context.Canceled` / `context.DeadlineExceeded`.

The same watchdog is reused inside `dialHost` (for `StartTLS`) and
`reconnectLocked` (for `Bind`), so all four cancellation-aware paths
share one implementation.

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
├── useLDAPS        bool                            LDAPS vs plain LDAP
├── skipStartTLS    bool                            disable StartTLS upgrade
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
`Bind` / `Search` call. This zero value also means that `Reconnect`
applies **no** client-side Bind timeout when the cached credentials are
replayed — the dial itself is still bounded by `dialTimeout`, so a dead
peer cannot stall the reconnect indefinitely, but a slow `Bind` is not
capped unless `ctx` has a deadline or `opTimeouts.Bind > 0`.

### Search flow (`GetUser` as example)

```
conn.GetUser(ctx, "jdoe", baseDN)
        │
        ├── catalogAdapter.SearchUserFilterTemplate()
        │       → "(uid=%[1]s)" → renderFilterTemplate
        │         (escapes, Sprintf, ldap.CompileFilter validation)
        │       → "(uid=jdoe)"
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

Filter templates are validated before the round-trip:
`renderFilterTemplate` rejects arity mismatches (the `%!s(MISSING)`
marker) and structurural problems (via `ldap.CompileFilter`) with
`ErrInvalidArgument`. A broken adapter is surfaced at the call site,
not as a mysterious "Bad search filter" from the server.

**Note on ambiguity**: single-object lookups use
`ScopeWholeSubtree` + `SizeLimit=2`. On MSAD, a user and a
`contact`/`computer` object with the same `sAMAccountName` in
different OUs will trigger `ErrAmbiguousResult` even though the
caller only cared about the user. See
[Adapter-specific gotchas](#adapter-specific-gotchas).

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
  preserves RDN order, and **escapes `,`, `+`, `=`, and `\` inside
  attribute values**. Without the last step, two structurally different
  DNs would collide at a join point (`cn=a,ou=b` — two RDNs — vs
  `cn=a\,ou=b` — one RDN whose value is `a,ou=b`). The output is an
  opaque equivalence key, never re-parsed as a DN.
- **`AncestorOfFold`** (not `AncestorOf`) is used so case-differing
  ancestors still match — otherwise subtree entries with different
  attribute-type case would be silently dropped.

This is the whole reason `GetCatalogTree` is O(1) round-trips instead of
O(N): the server streams pages of the subtree, and the parent-child
wiring is done locally in `O(N)` with a single `map[string]*OUNormalizedInfo`.

**Partial results are not returned from the tree functions.** If the
server returns `SizeLimitExceeded`, budget exhaustion, or any other
error after at least one page, `searchPaged` preserves the entries
collected so far and returns `ErrPartialResult` **together with those
entries** — but `WalkCatalogTree` / `GetCatalogTree` currently discard
the partial data and return an empty `types.CatalogTree` (non-nil, empty
slice) plus the error. Callers who need the partial data must drive
`searchPaged` themselves (via `CustomSearchPaged`) and assemble the tree
on their side. `GetCatalogTree`'s contract is: "non-nil tree, empty on
failure, complete on success".

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
    useLDAPS, skipStartTLS bool,
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
    useLDAPS, skipStartTLS bool,
    tlsCfg *tls.Config,
    catalogAdapter interfaces.CatalogAdapter,
    opts ...Option,
) (*LDAPper, error)
```

TLS matrix — `useLDAPS` and `skipStartTLS` together select the transport:

| `useLDAPS` | `skipStartTLS` | `tlsCfg` | Result                                          |
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
- **Host strings** — validated against URL-special characters. IPv4
  literals (`1.2.3.4`) and IPv6 literals (`2001:db8::1`, unbracketed)
  are accepted; brackets are added by `formatHost` before the URI is
  built. **IPv6 scoped literals (`fe80::1%eth0`) are rejected** —
  `net.ParseIP` does not parse the `%zone` suffix, and scope IDs are
  link-local-only. Use a globally routable IPv6 address instead.
- **`dialConn` is a package-level variable** (of type `DialFunc`) so
  tests can swap it out via `withDialConn(t, fn)` without touching
  production code.

### mTLS

Mutual TLS works with no LDAPper-specific API: the `*tls.Config` passed
to `NewLDAPper` / `NewAuthenticatedLDAPper` is `Clone()`d and then used
verbatim by both transports —

- **LDAPS** (`useLDAPS=true`) — `tls.Dialer{Config: tlsCfg}` in `dialHost`.
- **StartTLS** (`useLDAPS=false, skipStartTLS=false`) — `conn.StartTLS(tlsCfg)`
  immediately after the plain dial.

Client authentication is configured exactly as in the standard library:
put the client certificate into `tls.Config.Certificates` (or
`tls.Config.GetClientCertificate`), and the CA that signed the server
certificate into `tls.Config.RootCAs`.

#### `ServerName` and multi-host failover

`NewLDAPper` clones the provided `*tls.Config` and, **if
`tlsCfg.ServerName == ""`, sets it to `hosts[0]`**. This matches the
common HA deployment where every host resolves to a certificate carrying
the same SAN (name). The following two cases need explicit attention:

- **Same SAN across hosts** — the default is correct; no action needed.
- **Different SANs across hosts** (e.g. internal vs external names in a
  mixed failover list) — **set `tlsCfg.ServerName` explicitly** before
  calling the constructor. If you leave it empty, failover to
  `hosts[1..]` will fail TLS verification with a name-mismatch error,
  because the client will still expect a certificate for `hosts[0]`.

#### LDAPS

```go
cert, err := tls.LoadX509KeyPair("client.crt", "client.key")
if err != nil {
    log.Fatalf("load client cert: %v", err)
}

caPool := x509.NewCertPool()
caPEM, err := os.ReadFile("ca.crt")
if err != nil {
    log.Fatalf("read CA: %v", err)
}
if !caPool.AppendCertsFromPEM(caPEM) {
    log.Fatal("CA bundle contains no valid certificates")
}

tlsCfg := &tls.Config{
    // Optional for LDAPS: ServerName is inferred from the dialed host.
    // Set it explicitly when `hosts` holds an IP or a name that does not
    // appear in the server certificate's SAN.
    ServerName:   "ldap.example.com",
    RootCAs:      caPool,
    Certificates: []tls.Certificate{cert},
    MinVersion:   tls.VersionTLS12,
}

conn, err := ldapper.NewAuthenticatedLDAPper(
    ctx,
    "svc-reader@corp.example.com", "secret", "DC=corp,DC=example,DC=com",
    []string{"ldap.example.com"}, 636,
    true,  // useLDAPS
    false, // skipStartTLS (must be false when useLDAPS is true)
    tlsCfg,
    adapters.MSADAdapter{},
)
```

#### StartTLS

`go-ldap` calls `tls.Client(conn, cfg)` without a `ServerName` hint, and
the standard library rejects the handshake with

```
tls: either ServerName or InsecureSkipVerify must be specified in the tls.Config
```

unless one of the two fields is set. LDAPper's auto-fill (see
[`ServerName` and multi-host failover](#servername-and-multi-host-failover))
covers the common case, but you should still **set `ServerName`
explicitly** if your failover list spans multiple certificates.
`InsecureSkipVerify: true` defeats the point of TLS — prefer
`ServerName`.

```go
tlsCfg := &tls.Config{
    ServerName:   "ldap.example.com", // required for StartTLS
    RootCAs:      caPool,
    Certificates: []tls.Certificate{cert},
    MinVersion:   tls.VersionTLS12,
}

conn, err := ldapper.NewLDAPper(
    ctx, []string{"ldap.example.com"}, 389,
    false, // useLDAPS
    false, // skipStartTLS → StartTLS upgrade
    tlsCfg,
    adapters.OPENLDAPAdapter{},
)
```

#### Certificate rotation

`NewLDAPper` stores a `Clone()` of the provided `tls.Config`. The clone
is shallow — the `Certificates` slice and the DER bytes inside each
`tls.Certificate` are shared with the caller — so **do not mutate the
certificate bytes after passing them in**. For hot rotation (common with
short-lived mTLS certificates issued by Vault / SPIRE / a custom CA),
use `tls.Config.GetClientCertificate` instead of `Certificates`; the
callback is invoked on every handshake, and `Clone()` copies it by
reference:

```go
type certRotator struct {
    mu  sync.RWMutex
    cur *tls.Certificate
}

func (r *certRotator) load(crtPath, keyPath string) error {
    c, err := tls.LoadX509KeyPair(crtPath, keyPath)
    if err != nil {
        return err
    }
    r.mu.Lock()
    r.cur = &c
    r.mu.Unlock()
    return nil
}

func (r *certRotator) get(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
    r.mu.RLock()
    defer r.mu.RUnlock()
    return r.cur, nil
}

tlsCfg := &tls.Config{
    ServerName:           "ldap.example.com",
    RootCAs:              caPool,
    GetClientCertificate: rotator.get,
    MinVersion:           tls.VersionTLS12,
}
```

To pick up new material, reload it in the rotator and call
`conn.Reconnect(ctx)`: reconnect performs a fresh TLS handshake against
`ldapper.tlsCfg`, so the callback serves the new certificate
immediately. Cached bind credentials (see [Connections](#connections))
survive the reconnect — `Reconnect` replays the bind before publishing
the connection, and a failed rebind still invalidates auth state and
returns `ErrInvalidCredentials`, exactly as for non-mTLS connections.

#### Diagnostics

TLS handshake failures — including "server rejected client certificate"
— flow through `classifyLDAPError` and surface as `ErrUnavailable`
(transport class). This is the case in both directions:

- `*tls.CertificateVerificationError` — the **client** rejected the
  **server** certificate (unknown CA, wrong SAN, expired, …).
- `tls.AlertError` — the **server** rejected the **client**
  certificate (e.g. `bad_certificate` during an mTLS handshake).

Both are recognised by `isTransportError` (see
[`ldapper_errors.go`](ldapper_errors.go)) and therefore reachable via
`errors.Is(err, ErrUnavailable)`. For diagnostics of the underlying
cause, use `errors.As`:

```go
var cvErr *tls.CertificateVerificationError
if errors.As(err, &cvErr) {
    log.Printf("TLS verification failed: %v", cvErr)
}

var alertErr tls.AlertError
if errors.As(err, &alertErr) {
    log.Printf("TLS alert: %v", alertErr)
}
```

> **Note:** `tls.Config.ClientAuth` is a **server-side** field. Setting
> it on the client has no effect — the certificate presented by the
> client is selected from `Certificates` / `GetClientCertificate`, not
> by `ClientAuth`.

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
    // values. LDAPper additionally validates the substituted filter via
    // ldap.CompileFilter and rejects arity mismatches with
    // ErrInvalidArgument before the round-trip.
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

**Timeout semantics.** The resolver is invoked inside a single
`withCtx(ctx, opTimeouts.Search, …)` call. The timeout therefore applies
**per-request** (each `LDAPConn.Bind` / `LDAPConn.Search` on the
supplied connection) — it does **not** cap the resolver's total
wall-clock time. A resolver doing N sequential round-trips can take up
to N × `opTimeouts.Search`. For a hard end-to-end bound, attach a
`context.WithTimeout` to the `GetUserGroups` call.

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

**`MaxPages` is also the primary defence against a misbehaving paging
server.** `searchPaged` tracks every distinct paging cookie it has seen
(to catch A→B→A cycles) in an in-memory set. When `MaxPages == 0` that
set has **no upper bound**: a hostile or buggy server that returns an
endless sequence of fresh cookies will inflate it indefinitely. Callers
that must resist such a server should set `MaxPages` (or `MaxEntries`)
to a finite budget; `searchPaged` will then abort with `ErrPartialResult`
before the set can grow.

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
  the default — backwards compatible). In particular, **`Reconnect` does
  not force a hidden default on the Bind step when `Bind == 0`**: only
  `ctx` (and, for the dial phase, `dialTimeout`) bounds the call.
- Negative durations are clamped to zero.
- The timeout is applied via `LDAPConn.SetTimeout` (which is part of the
  `LDAPConn` interface contract — every implementation, including mocks,
  must support it). After the operation, the timeout is reset to zero so
  it does not cap subsequent operations.
- In addition, `withCtx`/`withCtxResult` respect the caller's context
  deadline: the effective timeout is `min(opTimeout, ctx.Deadline - now)`.
- For `PrimaryGroupResolver` adapters, `opTimeouts.Search` is a
  **per-request** budget on each `LDAPConn.Search` the resolver issues,
  not a total. See [Adapters](#adapters) for details.

---

## Shipped adapters

| Adapter                     | Directory                          | Notes                                                                                                                                                                                                                                                                                                                         |
|-----------------------------|------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `adapters.MSADAdapter`      | Microsoft Active Directory         | Uses `objectCategory`-based filters; recursive group search via the `LDAP_MATCHING_RULE_IN_CHAIN` OID (`1.2.840.113556.1.4.1941`); prefers `thumbnailPhoto` over `jpegPhoto`; implements `PrimaryGroupResolver` to resolve `primaryGroupID` into a group DN.                                                                  |
| `adapters.OPENLDAPAdapter`  | OpenLDAP (and most RFC-4519 dialects) | Handles three group models — `groupOfNames` (via `member`), `groupOfUniqueNames` (via `uniqueMember`), and `posixGroup` (via `memberUid`). User search keyed by `uid` **or** `entryDN`. Short-form bind (`alice`) is expanded to `uid=<login>,<baseDN>`.                                                                      |
| `adapters.ALDPROAdapter`    | ALD Pro                            | Recognizes `rbta-org-unit` alongside `organizationalUnit`; department mapped from `rbtadp`; two-branch group filter — `member`/`memberIndirect` (DN) for `groupOfNames`/`ipaUserGroup`/`posixGroup`, **and** `memberUid` (uid) for `posixGroup`. Bind is pass-through (UPN/DN).                                               |
| `adapters.FREEIPAAdapter`   | FreeIPA                            | Recognizes `nsContainer` alongside `organizationalUnit`; department is intentionally **not** mapped; group lookup matches DN-valued `member`/`memberIndirect` **and** uid-valued `memberUid`. Short-form bind is expanded to `uid=<login>,cn=users,cn=accounts,<baseDN>`, unless `baseDN` already contains those RDN nodes — the detection is **structural** (parsed via `ldap.ParseDN`, compared case-insensitively per-RDN), not a substring match.              |

### Adapter-specific gotchas

- **`MSADAdapter`** — `GetUser` matches on `sAMAccountName` /
  `userPrincipalName` / `distinguishedName`. The value passed to
  `NewAuthenticatedLDAPper` must therefore be a valid AD principal (UPN,
  sAMAccountName, or DN). Group search uses
  `LDAP_MATCHING_RULE_IN_CHAIN`, which **Samba 4 AD DC** and Microsoft AD
  both support — OpenLDAP and FreeIPA do **not**.

  > **Ambiguity risk:** `GetUser` / `GetGroup` / `GetOU` use
  > `ScopeWholeSubtree` + `SizeLimit=2` to detect duplicates. On AD, a
  > user and a `contact`/`computer` object with the same
  > `sAMAccountName` (across different OUs) both match the user filter,
  > so the lookup fails with `ErrAmbiguousResult`. Pass a fully qualified
  > principal (UPN or DN) or narrow the `baseDN` to the user's OU when
  > this happens.

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
    deepest-first: `accounts` → `users` → `uid`). Whether each `cn=...`
    node is added is decided by structural RDN comparison (case-
    insensitive, single-valued RDN), not by substring matching the DN
    string.
- **`GetNormalizedOUInfoFromEntry.Name`** — all shipped adapters derive
  `Name` from the **first RDN of `entry.DN`** via `ouNameFromDN`. The
  helper does not check the RDN attribute type: it returns the first
  attribute's value whatever it is (`ou=sales` → `"sales"`,
  `cn=users` → `"users"`). It is meant for display (tree labels, log
  lines), not identification. Malformed DNs fall back to the raw string.
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
- Asks the adapter's `BindIdentity` for the actual Simple Bind principal,
  then performs the bind, then probes `baseDN` with a base-object search
  to confirm the tree is reachable under the bound identity. No post-bind
  user lookup is performed, and no `*types.LDAPUser` is returned — call
  `GetUser` afterwards if you need the user entry.
- If `BindIdentity` fails, the adapter's error is wrapped with `%w`, so
  callers can `errors.Is` / `errors.As` into it. If the subsequent bind
  fails, the error is `ErrInvalidCredentials` (or another bind-path
  sentinel; testable with `errors.Is`).
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
  `ErrNotAuthenticated` (or is appended to the primary error). **If the
  rebind was aborted by `ctx` cancellation**, however, the raw
  `context.Canceled` / `context.DeadlineExceeded` is surfaced instead —
  `ErrNotAuthenticated` would mislead a caller who already decided to
  tear down.

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
  DN is appended to the result. See [Adapters](#adapters) for the
  per-request timeout semantics of the resolver.
- **`GetOUUsers`** — takes a **DN**, not a short `ou` name. Uses the
  adapter's `UserObjectFilter` and `UserAttrs` to list all users under
  the subtree, subject to paging.
- **`GetOU`** — takes the short `ou` value (e.g. `"Sales"`) plus a base DN.
- **`GetGroup`** — takes the short `cn` value.

Filter templates are validated **before** the search is sent: an arity
mismatch (`%!s(MISSING)`) or a structurally broken filter surfaces as
`ErrInvalidArgument` with the adapter template quoted in the message. See
[Writing your own adapter](#writing-your-own-adapter) for the
adapter-side obligations this depends on.

**Asymmetry between `CustomSearch` and `CustomSearchPaged`:** the two
methods check their inputs in different orders.

- `CustomSearchPaged` rejects a `nil` `*ldap.SearchRequest` **before**
  acquiring `opMu` and **before** running `requireConnLocked`. The nil
  request is treated as a programming error and reported as
  `ErrInvalidArgument` regardless of connection state.
- `CustomSearch` acquires `opMu` and calls `requireConnLocked` first,
  then rejects `nil`. An uninitialized or closed `LDAPper` reports
  `ErrClosed`, even when the caller also passed a nil request.

Both behaviours are pinned by tests (`TestCustomSearchPaged_NilRequest`,
`TestCustomSearch_NilRequest`, `TestCustomSearch_ConnRequired`) and are
intentional — do not "unify" them without adjusting those tests.

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
- On failure the returned `types.CatalogTree.Tree` is **non-nil but
  empty** — the tree builder deliberately discards any partial state, so
  a caller trusting `tree.Tree` never sees half a hierarchy. If you need
  partial data on `ErrPartialResult` (e.g. `SizeLimitExceeded` after the
  first page), drive `CustomSearchPaged` yourself: `searchPaged` returns
  the entries collected so far alongside `ErrPartialResult`, and the
  wiring above is just the same `map[string]*OUNormalizedInfo` dance.

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
  successful reconnect. If `opTimeouts.Bind == 0`, the rebind applies no
  client-side Bind timeout (same contract as `withCtx`); the dial itself
  is still bounded by `dialTimeout`.
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
| `ErrInvalidArgument`           | Config or argument validation failed (empty/invalid DN, empty username, invalid host, invalid port, `useLDAPS && skipStartTLS`, nil TLS config, nil adapter, adapter-supplied filter template arity mismatch / malformed filter, …). |
| `ErrInvalidCredentials`        | Bind rejected as bad credentials. Also returned by `CheckUserCredentials` when the user is missing (enumeration protection). |
| `ErrInvalidCredentialsOrUnknown` | Bind-path classifier could not map the LDAP result code to a specific sentinel. Treat as inconclusive, not as a rejection. |
| `ErrNotAuthenticated`          | `CheckUserCredentials` called on a connection without a successful prior `BindConn`/`NewAuthenticatedLDAPper`, or the service rebind was lost (non-cancellation failure). |
| `ErrUnavailable`               | Directory unreachable (dial failure, `LDAPResultUnavailable`/`Busy`/`ServerDown`, transport errors — **including TLS handshake failures from `tls.CertificateVerificationError` and `tls.AlertError`**). |
| `ErrTimeout`                   | Timeout / deadline exceeded (`LDAPResultTimeout`, `LDAPResultTimeLimitExceeded`, `net.Error.Timeout`, `context.DeadlineExceeded`). |
| `ErrClosed`                    | The connection is nil (never initialized, or `Close()` was called, or a failed reconnect left it nil). |
| `ErrNotFound`                  | Search produced a definitive "no such object" (`LDAPResultNoSuchObject`). Rare — subtree searches usually return zero entries instead. |
| `ErrNotFoundOrNotVisible`      | Subtree search returned zero entries. The object may not exist, or may be hidden by ACL. Do not infer "does not exist". |
| `ErrAmbiguousResult`           | Single-object lookup matched more than one entry. |
| `ErrPartialResult`             | Paged search was interrupted by `SizeLimitExceeded`, budget exhaustion, or a missing paging control (when `RequirePaging` is true). The returned slice/tree is partial. |
| `ErrInsufficientAccess`        | LDAP returned `LDAPResultInsufficientAccessRights`. Surfaced by both `classifyLDAPError` (search path) and `classifySensitiveBindError` (bind path). |

Bind-path failures **never** wrap the raw LDAP text — this prevents
credential leakage into logs when the server echoes back the submitted
password. All bind errors are mapped to bare sentinels by
`classifySensitiveBindError`.

BindConn can return `ErrNotFoundOrNotVisible` if `baseDN` is unreachable
under the bound identity (for example, when the bind principal has no
read access to the tree root). This is produced by the base-DN probe,
not by a user lookup.

`CheckUserCredentials` can return `context.Canceled` /
`context.DeadlineExceeded` when the caller aborts during the service
rebind — the raw ctx error is surfaced rather than masked as
`ErrNotAuthenticated`. See [Authentication](#authentication).

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
   values in the same order. LDAPper validates arity and the compiled
   filter, returning `ErrInvalidArgument` on mismatch — this surfaces
   adapter bugs at the call site rather than as a "Bad search filter"
   from the server.
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
   `OPENLDAPAdapter`/`FREEIPAAdapter` for examples. Errors returned by
   `BindIdentity` are wrapped with `%w` by `BindConn`, so they remain
   reachable through `errors.Is` / `errors.As`. Do not put credentials in
   the error message — it will be surfaced to the caller.
7. **`PrimaryGroupResolver`** — implement only if your schema has a real
   concept of "primary group" that is not covered by ordinary group
   membership (like AD's `primaryGroupID`). The resolver MUST use only
   the provided `LDAPConn` and MUST NOT call `LDAPper` methods — the lock
   is already held. `opTimeouts.Search` applies per-request, not as a
   total — see [Adapters](#adapters).
8. **`appendRDN`** (internal helper, used by FreeIPA/OpenLDAP adapters)
   validates `attrType` against RFC 4514's `descr` / `numericoid`
   grammar before returning. If you build DNs from caller-controlled
   attribute types in a custom adapter, call `appendRDN` rather than
   `ldap.DN.String()` directly — the latter happily renders `foo bar=x`
   which `ldap.ParseDN` then rejects.

See `adapters/msad_adapter.go`, `adapters/openldap_adapter.go`,
`adapters/aldpro_adapter.go` and `adapters/freeipa_adapter.go` for
complete, production-quality examples.

---

## Configuration & tuning

Defaults live in `constants/constants.go`:

| Constant                         | Default | Meaning |
|----------------------------------|---------|---------|
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
backwards compatible with code that does not configure it. In
particular, `opTimeouts.Bind == 0` disables the client-side Bind
timeout applied by `withCtx` **and** by `reconnectLocked` — reconnect
does not force `constants.DefaultDialTimeout` on the Bind step.

`With*` options are applied by `NewLDAPper` before the object is
returned to the caller; there is no concurrent access at that point.
`Set*`/`Get*` take `opMu`, so they are safe to call concurrently with
search operations.

**`MaxPages` and `MaxEntries`** are complementary memory guards for paged
searches: `MaxPages` bounds the number of round-trips (and, indirectly,
the size of the internal `seenCookies` set), `MaxEntries` bounds the
total entries accumulated locally. Setting either is recommended for
long-running services that page through large subtrees — leaving both at
`0` means "no limit", per the same convention as `SizeLimit`.

---

## Testing

The package is designed for testability at every layer.

### Unit tests

Unit tests run without any network access and cover:

- **Input validation** — `validators_test.go`: DN / base DN / host /
  port / TLS-config / option validation, `formatHost` IPv4-vs-IPv6,
  `isIPLiteral` IP-vs-DNS detection, and the IPv6-scoped-literal
  limitation.
- **Core helpers** — `helpers_test.go`: `attrsToMap` (including
  duplicate-name deduplication), `escapeFilterArgs`, `parentDNOf`
  (including multi-valued RDN preservation), `canonicalDN`
  (case folding, RDN-order significance, escaped-comma round-trip,
  structural ambiguity between `cn=a,ou=b` and `cn=a\,ou=b`, malformed
  fallback), `escapeCanonicalValue`.
- **Errors** — `ldapper_errors_test.go`: `classifyLDAPError`,
  `classifySensitiveBindError` (including the "no secret leak" regression
  test and the TLS-error classification), `isTimeoutError`,
  `isTransportError`.
- **Options & limits** — `ldapper_options_test.go`:
  `With/Set/GetSearchLimits`, `With/Set/GetDialTimeout`,
  `With/Set/GetOperationTimeout`, clamping, `-race` guards.
- **Search primitives** — `ldapper_search_test.go`:
  `searchSingleEntryLocked` (including arity and syntax validation via
  `renderFilterTemplate`), `searchPaged` (single page, multiple pages,
  `MaxPages`/`MaxEntries` budgets, `RequirePaging` on/off, repeated-cookie
  runaway, `SizeLimitExceeded`-preserves-entries, context-cancelled
  during/between pages, raw error propagation),
  `CustomSearch`, `CustomSearchPaged`.
- **Connection** — `ldapper_connection_test.go`: `runWithWatchdog` (happy
  path, panic path with defer-based cleanup, timeout reset), `withCtx` /
  `withCtxResult` (deadline merging, watchdog, cancellation invalidating
  the connection), `Close`, `IsAlive`, `EnsureAlive`, `Reconnect`,
  `dialAnyLocked` (including ctx-cancellation between hosts). Tests that
  swap the package-level `dialConn` seam are **not** parallel — the swap
  is process-wide.
- **Auth** — `ldapper_auth_test.go`: `invalidateAuthLocked`,
  `restoreServiceBindLocked`, `bindConnLocked` / `verifyBaseDNLocked`
  (success path, 0-entry base probe, transport failure), `BindConn`
  (including `errors.Is`-reachability of `BindIdentity` errors),
  `CheckUserCredentials` (user-not-found masking, restore-failure path,
  restore-cancellation surfacing `context.Canceled`, context-cancelled
  user-bind path).
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
  `BindIdentity` structural-RDN detection (case-insensitive,
  substring-vs-RDN regression), `appendRDN` `attrType` validation,
  `binarySidToString` boundary (`subAuthorityCount == 255`).

```bash
go test ./...
go test -race -count=20 ./...
go vet ./...
```

### Fuzz tests

`go test -run=^$ -fuzz=FuzzXxx ./...` drives the load-bearing invariants:

- `FuzzCanonicalDN_NoPanic` / `FuzzCanonicalDN_CaseEquivalence`
  (`helpers_fuzz_test.go`) — case-folding and no-panic contracts of the
  tree-linking key.
- `FuzzParentDNOf` (`helpers_fuzz_test.go`) — valid input yields parent =
  `RDNs[1:]`, malformed / single-RDN input yields `""`.
- `FuzzEscapeFilterArgs`, `FuzzValidateDN_SentinelContract`,
  `FuzzValidateHost_SentinelContract` (`helpers_fuzz_test.go`) — filter
  escaping and sentinel-error contracts.
- `FuzzAppendRDN` (`adapters/builtin_adapter_helpers_test.go`) — DN
  built by `appendRDN` must parse, and its first RDN must carry the
  supplied `attrType` / value.
- `FuzzAdapterFilterTemplates` (`adapters/filters_fuzz_test.go`) — for
  every shipped adapter and every user-controlled input, the rendered
  filter must compile; template arity is checked independently, catching
  both under-supply (`%!s(MISSING)`) and over-supply (silently dropped
  args).

### Test helpers

- **`utils_test.go`** (package `ldapper`): `newLDAPEntry(dn, attrs)
  *ldap.Entry` — builds a `*ldap.Entry` with both `Values` and
  `ByteValues` populated so `GetRawAttributeValue` works in tests.
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
- **`integration_helpers_test.go`** (package `ldapper_test`, **no build
  tag**) — shared helpers available to all four tagged integration
  suites. Currently holds `containsDN` (case-insensitive substring match
  for group DNs). Keep it dependency-free: only the standard library.
  If a helper needs testify / `ldap/v3`, move it into the specific tagged
  file that uses it.

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
  `PrimaryGroupResolver` path. The primary-group test resolves the
  expected DN via `primaryGroupToken` (the well-known RID 513), so it
  is locale-independent — "Domain Users" only works in English AD
  deployments, and the suite avoids that assumption. Gracefully skips
  if the container cannot be started.
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

Compile-time guards for the `PrimaryGroupResolver` contract are installed
in each suite:

- `msad_integration_test.go` — `var _ interfaces.PrimaryGroupResolver = adapters.MSADAdapter{}`
  (the interface **must** be implemented).
- `openldap_integration_test.go`, `freeipa_integration_test.go`,
  `aldpro_integration_test.go` — an `init()`-time panic when the
  adapter unexpectedly satisfies `interfaces.PrimaryGroupResolver`.
  Go has no static "does not implement" assertion, so the runtime panic
  is the closest equivalent.

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
