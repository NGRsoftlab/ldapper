# ldapper

> A Go library for working with LDAP directories (supported for now: Microsoft Active Directory and OpenLDAP) with support for authentication, user and group search, and building the organizational unit (OU) tree.

[![Go Version](https://img.shields.io/badge/go-%3E%3D1.26-blue)](https://go.dev/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Module](https://img.shields.io/badge/module-github.com%2FNGRsoftlab%2Fldapper-blue)](https://github.com/NGRsoftlab/ldapper)

---

## 📋 Table of Contents

- [Features](#-features)
- [Installation](#-installation)
- [Quick Start](#-quick-start)
- [Architecture](#-architecture)
- [Usage](#-usage)
  - [Connecting](#connecting)
  - [Authentication](#authentication)
  - [User Search](#user-search)
  - [User Groups](#user-groups)
  - [Users in an OU](#users-in-an-ou)
  - [Catalog Tree](#catalog-tree)
  - [Custom Search](#custom-search)
- [Catalog Adapters](#-catalog-adapters)
- [Data Types](#-data-types)
- [Constants](#-constants)
- [Testing](#-testing)
- [Limitations and TODO](#-limitations-and-todo)

---

## ✨ Features

- 🔐 **Two authentication modes**:
  - `AuthenticateConn` — initial authentication that stores the service account credentials for subsequent operations.
  - `AuthenticateUser` — verifies end-user credentials and rebinds back to the service account.
- 🌐 **LDAP and LDAPS support** (TLS/StartTLS).
- 👤 **User search** by login with a configurable set of attributes.
- 👥 **User group search** with support for recursive search (AD) and two group types (OpenLDAP: `groupOfNames` and `posixGroup`).
- 🗂️ **Users in an OU** search.
- 🌳 **Catalog tree building** (OU) with recursive traversal and depth limit.
- 🔍 **Arbitrary LDAP search** via `CustomSearch`.
- 🧩 **Pluggable adapters** for different directories: `MSADAdapter` and `OPENLDAPAdapter`.
- 🧪 **Full unit-test coverage** using `testify/mock`.

---

## 📦 Installation

```bash
go get github.com/NGRsoftlab/ldapper
```

**Dependencies:**

```
github.com/go-ldap/ldap/v3 v3.4.15
github.com/stretchr/testify v1.8.1
```

Go version: **1.26.10** or later.

---

## 🚀 Quick Start

```go
package main

import (
    "crypto/tls"
    "fmt"
    "log"

    "github.com/NGRsoftlab/ldapper"
)

func main() {
    tlsCfg := &tls.Config{InsecureSkipVerify: true} // example only — do not use in production!
    adapter := ldapper.MSADAdapter{}

    conn, user, err := ldapper.NewAuthenticatedConnection(
        "svc-reader", "password", "dc=example,dc=com",
        "ldap.example.com", 636,
        true,  // useSSL
        false, // skipTLS
        tlsCfg,
        adapter,
    )
    if err != nil {
        log.Fatal(err)
    }
    defer conn.Close()

    fmt.Printf("Authenticated: %s (%s)\n", user.DN, user.GetAttributeValue("cn"))
}
```

---

## 🏗 Architecture

```
┌──────────────────────────────────────────────────────────┐
│                     LDAPConnection                       │
│  ┌──────────────┐  ┌───────────────┐  ┌────────────────┐ │
│  │ LDAPConn     │  │ CatalogAdapter│  │ auth state     │ │
│  │ (interface)  │  │ (interface)   │  │ (bind user/pw) │ │
│  └──────────────┘  └───────────────┘  └────────────────┘ │
└──────────────────────────────────────────────────────────┘
         │                    │
         ▼                    ▼
  ┌────────────┐      ┌──────────────────┐
  │ *ldap.Conn │      │ MSADAdapter      │
  │ (real)     │      │ OPENLDAPAdapter  │
  │ MockLDAPConn│     │ MockCatalogAdapter│
  └────────────┘      └──────────────────┘
```

**Key interfaces:**

| Interface | Purpose |
| :--- | :--- |
| `LDAPConn` | Abstraction over `*ldap.Conn` (`StartTLS`, `Bind`, `Search`, `Close`). Enables mocking the connection. |
| `CatalogAdapter` | Strategy for a specific directory: filters, search templates, attribute lists, entry conversion. |

---

## 📖 Usage

### Connecting

```go
// Unauthenticated — read-only, useful when the server allows anonymous access.
conn, err := ldapper.NewConnection(
    "ldap.example.com", 389,
    false, // useSSL
    true,  // skipTLS (do not use StartTLS)
    nil,   // tlsCfg is not needed when skipTLS is true
    ldapper.OPENLDAPAdapter{},
)
if err != nil {
    log.Fatal(err)
}
defer conn.Close()
```

**Parameters:**

| Parameter | Description |
| :--- | :--- |
| `host` | LDAP server host. |
| `port` | Port (389 for LDAP, 636 for LDAPS). |
| `useSSL` | `true` — use `ldaps://` with TLS from the start. |
| `skipTLS` | `true` — do not perform `StartTLS` after connecting (only for `!useSSL`). |
| `tlsCfg` | TLS configuration. Required if `useSSL` or `!skipTLS`. |
| `catalogAdapter` | Catalog adapter (`MSADAdapter` or `OPENLDAPAdapter`). |

**Validation:**
- `tlsCfg == nil && (!skipTLS || useSSL)` → error `"nil tls config passed"`.
- `catalogAdapter == nil` → error `"nil catalog adapter passed"`.

---

### Authentication

#### `AuthenticateConn` — initial authentication

```go
user, err := conn.AuthenticateConn("jdoe", "secret", "dc=example,dc=com")
if err != nil {
    log.Fatal(err)
}
// The connection is now authenticated as jdoe.
// The service account credentials are stored in conn.bindUser / conn.bindPassword.
```

**What happens:**
1. User lookup by login (`GetUser`).
2. `Bind` as the found `user.DN` with the provided password.
3. On success: `isAuthenticated = true`, `bindUser`, `bindPassword` are stored.

**Errors:**
- `"connection not initialized"` — connection was not created.
- `"user does not exist"` — user not found.
- `"too many entries returned"` — more than one entry matched.
- `"unsuccessful bind with passed bind credentials"` — invalid password (the original error is **not** returned to avoid leaking sensitive data).

#### `AuthenticateUser` — user verification with rebind

```go
user, err := conn.AuthenticateUser("jdoe", "user-password", "dc=example,dc=com")
if err != nil {
    log.Fatal(err)
}
// After verification, the connection is rebound to the service account.
```

**Requirements:**
- The connection must be previously authenticated via `AuthenticateConn` (otherwise: `"connection not authenticated"`).
- The service account must have read access to the directory.

**What happens:**
1. User lookup (`GetUser`).
2. `Bind` as the user with their password.
3. On success — `Bind` back as `conn.bindUser` / `conn.bindPassword`.

**Errors:**
- `"connection not authenticated"` — `AuthenticateConn` was not called.
- `"unsuccessful bind with passed user credentials"` — invalid user password (rebind is not performed).
- `"unsuccessful rebind with bind-config credentials"` — failed to rebind back to the service account.

---

### User Search

```go
user, err := conn.GetUser("jdoe", "dc=example,dc=com")
if err != nil {
    log.Fatal(err)
}

fmt.Println(user.DN)                                // uid=jdoe,dc=example,dc=com
fmt.Println(user.GetAttributeValue("cn"))           // John Doe
fmt.Println(user.GetAttributeValue("mail"))         // jdoe@example.com
fmt.Println(user.GetFirstNonNullAttributeValue([]string{"thumbnailPhoto", "jpegPhoto"}))
```

**Returns:**
- `*LDAPUser` with `DN` and `Attributes map[string][]string`.
- Errors: `"user does not exist"`, `"too many entries returned"`, `"unsuccessful user search: ..."`.

**Notes:**
- The filter is built from `catalogAdapter.SearchUserFilterTemplate()` with `username` substituted.
- Requested attributes come from `catalogAdapter.UserAttrs()`.
- `TimeLimit` = `defaultSearchTimeLimit` (60 seconds).

---

### User Groups

```go
groups, err := conn.GetUserGroups("jdoe", "dc=example,dc=com")
if err != nil {
    log.Fatal(err)
}
fmt.Println(groups) // ["admins", "users", ...]
```

**What happens:**
1. `GetUser` — user lookup.
2. Filter built from `SearchUserGroupsFilterTemplate()` + `SearchUserGroupsFilterTemplateArgs(user)`.
3. Group search and extraction of the `cn` attribute.

**Adapter differences:**

| Directory | Filter template | Arguments |
| :--- | :--- | :--- |
| **MSAD** | `(&(objectCategory=group)(member:1.2.840.113556.1.4.1941:=%s))` — recursive search via `LDAP_MATCHING_RULE_IN_CHAIN`. | `[user.DN]` |
| **OpenLDAP** | `(\|(&(objectClass=groupOfNames)(member=%s))(&(objectClass=posixGroup)(memberUid=%s)))` | `[user.DN, user.GetAttributeValue("uid")]` |

---

### Users in an OU

```go
users, err := conn.GetOUUsers("ou=people,dc=example,dc=com")
if err != nil {
    log.Fatal(err)
}
for _, u := range users {
    fmt.Println(u.DN)
}
```

**Notes:**
- `ScopeWholeSubtree` — recursive search over the entire subtree.
- Filter — `catalogAdapter.UserObjectFilter()`.
- Attributes — `catalogAdapter.UserAttrs()`.

---

### Catalog Tree

```go
tree, err := conn.GetCatalogTree("dc=example,dc=com")
if err != nil {
    log.Fatal(err)
}

for _, ou := range tree.Tree {
    fmt.Printf("%s (%s)\n", ou.Name, ou.DN)
    for _, child := range ou.Children {
        fmt.Printf("  └─ %s\n", child.DN)
    }
}
```

**How it works:**
1. `GetRootOUs(baseDN)` — first-level OU search (`ScopeSingleLevel`).
2. `GetRecursiveOUSearchResult(&rootOUs, 2)` — recursive traversal limited by `defaultSearchDepth = 5`.
3. `GetSubOUs(group, level)` — child OU search for each node.

**Important:**
- **Depth** is limited by `defaultSearchDepth` (5).
- **Filtering** in `GetSubOUs`: an entry is included only if its `DN` ends with `","+group` (i.e., it is genuinely a child) and is not equal to `group`. This avoids false positives like `ou=root2,...` matching `ou=root`.
- `Children` is always initialized as a non-nil empty slice — safe for `append` and JSON serialization.

---

### Custom Search

```go
req := ldap.NewSearchRequest(
    "dc=example,dc=com",
    ldap.ScopeWholeSubtree,
    ldap.NeverDerefAliases,
    0, 0, false,
    "(objectClass=person)",
    []string{"cn", "mail"},
    nil,
)

result, err := conn.CustomSearch(req)
if err != nil {
    log.Fatal(err)
}
for _, entry := range result.Entries {
    fmt.Println(entry.DN)
}
```

**Notes:**
- The error is **not** wrapped — returned as-is (unlike `GetUser`/`GetOUUsers`).
- `connection == nil` check → `"connection not initialized"`.

---

## 🧩 Catalog Adapters

### `MSADAdapter` (Microsoft Active Directory)

| Method | Value |
| :--- | :--- |
| `OUObjectFilter` | `(&(objectClass=organizationalUnit))` |
| `GroupObjectFilter` | `(&(objectCategory=group))` |
| `UserObjectFilter` | `(&(objectClass=user)(objectCategory=person))` |
| `SearchUserFilterTemplate` | `(&(objectCategory=person)(objectClass=user)(sAMAccountName=%s))` |
| `SearchUserGroupsFilterTemplate` | `(&(objectCategory=group)(member:1.2.840.113556.1.4.1941:=%s))` |
| `SearchOUFilterTemplate` | `(&(objectClass=organizationalUnit)(ou=%s))` |
| `SearchGroupFilterTemplate` | `(&(objectCategory=group)(cn=%s))` |
| `GetNormalizedUserInfo` | `Department` ← `department`, `Photo` ← `thumbnailPhoto` → `jpegPhoto` (fallback) |
| `OUInfoFromEntry` | `Name` ← `name` attribute, `OU` ← `entry.DN` |

### `OPENLDAPAdapter` (OpenLDAP)

| Method | Value |
| :--- | :--- |
| `OUObjectFilter` | `(&(objectClass=organizationalUnit))` |
| `GroupObjectFilter` | `(\|(objectClass=groupOfNames)(objectClass=posixGroup))` |
| `UserObjectFilter` | `(&(objectClass=person))` |
| `SearchUserFilterTemplate` | `(&(!(objectClass=computer))(\|(uid=%[1]s)(cn=%[1]s)))` — a single argument substituted twice via `%[1]s` |
| `SearchUserGroupsFilterTemplate` | `(\|(&(objectClass=groupOfNames)(member=%s))(&(objectClass=posixGroup)(memberUid=%s)))` |
| `SearchOUFilterTemplate` | `(&(objectClass=organizationalUnit)(ou=%s))` |
| `SearchGroupFilterTemplate` | `(&(\|(objectClass=groupOfNames)(objectClass=posixGroup))(cn=%s))` |
| `GetNormalizedUserInfo` | `Department` ← `departmentNumber`, `Photo` ← `jpegPhoto`, `Company`/`Country`/`City`/`Index` — always empty |
| `OUInfoFromEntry` | `Name` ← `entry.DN`, `OU` ← `ou` attribute |

### Implementing a Custom Adapter

```go
type MyAdapter struct{}

func (a MyAdapter) GetNormalizedUserInfo(u ldapper.LDAPUser) *ldapper.UserNormalizedInfo { /* ... */ }
func (a MyAdapter) OUInfoFromEntry(e ldap.Entry) *ldapper.OUInfo { /* ... */ }
func (a MyAdapter) UserObjectFilter() string { /* ... */ }
func (a MyAdapter) GroupObjectFilter() string { /* ... */ }
func (a MyAdapter) OUObjectFilter() string { /* ... */ }
func (a MyAdapter) SearchUserFilterTemplate() string { /* ... */ }
func (a MyAdapter) SearchUserGroupsFilterTemplate() string { /* ... */ }
func (a MyAdapter) SearchUserGroupsFilterTemplateArgs(u ldapper.LDAPUser) []any { /* ... */ }
func (a MyAdapter) SearchOUFilterTemplate() string { /* ... */ }
func (a MyAdapter) SearchGroupFilterTemplate() string { /* ... */ }
func (a MyAdapter) UserAttrs() []string { /* ... */ }
func (a MyAdapter) ShortUserAttrs() []string { /* ... */ }
func (a MyAdapter) OUAttrs() []string { /* ... */ }
func (a MyAdapter) GroupAttrs() []string { /* ... */ }
```

---

## 📐 Data Types

### `LDAPUser`

```go
type LDAPUser struct {
    DN         string              // distinguished name
    Attributes map[string][]string // user attributes
}

func (lu *LDAPUser) GetAttributeValue(attribute string) string
func (lu *LDAPUser) GetFirstNonNullAttributeValue(alternatives []string) string
```

- `GetAttributeValue` returns the **first** value of an attribute, or `""`.
- `GetFirstNonNullAttributeValue` iterates over alternatives and returns the first non-empty value.

### `UserNormalizedInfo`

```go
type UserNormalizedInfo struct {
    DistinguishedName string
    CommonName        string
    Mobile            string
    Phone             string
    Mail              string
    Department        string
    Title             string
    Manager           string
    Photo             string
    Company           string
    Country           string
    Address           string
    City              string
    Index             string
}
```

### `OUInfo`

```go
type OUInfo struct {
    Name     string    `json:"name"`
    DN       string    `json:"distinguishedName"`
    OU       string    `json:"ou"`
    Children []*OUInfo `json:"children"`
}
```

### `CatalogTree`

```go
type CatalogTree struct {
    Tree []*OUInfo `json:"tree"`
}
```

---

## ⚙️ Constants

```go
const (
    ldapURITemplate  = "ldap://%s:%d"
    ldapsURITemplate = "ldaps://%s:%d"

    defaultSearchTimeLimit = 60 // seconds
    defaultSearchDepth     = 5  // maximum recursion depth for the OU tree
)
```

| Constant | Value | Purpose |
| :--- | :--- | :--- |
| `ldapURITemplate` | `ldap://%s:%d` | URI template for plain LDAP. |
| `ldapsURITemplate` | `ldaps://%s:%d` | URI template for LDAPS. |
| `defaultSearchTimeLimit` | `60` | LDAP search timeout (seconds). |
| `defaultSearchDepth` | `5` | Maximum recursion depth for the OU tree. |

---

## 🧪 Testing

All methods are covered by unit tests using `testify/mock`. Mocks:

- **`MockLDAPConn`** — implementation of the `LDAPConn` interface (`StartTLS`, `Bind`, `Search`, `Close`).
- **`MockCatalogAdapter`** — implementation of the `CatalogAdapter` interface.

**Run tests:**

```bash
go test ./... -v
```

**Coverage:**

```bash
go test ./... -coverprofile=coverage.out
go tool cover -html=coverage.out
```

**Test structure:**

| File | What is covered |
| :--- | :--- |
| `ldap_connection_test.go` | `NewConnection`, `NewAuthenticatedConnection`, `AuthenticateConn`, `AuthenticateUser`, `Close`, `CustomSearch`, `GetUser`, `GetUserGroups`, `GetOUUsers`, `GetCatalogTree`, `GetRootOUs`, `GetSubOUs`, `GetRecursiveOUSearchResult`. |
| `msad_adapter_test.go` | `GetNormalizedUserInfo`, `OUInfoFromEntry`, filters, templates, `SearchUserGroupsFilterTemplateArgs`, attribute lists. |
| `openldap_adapter_test.go` | Same for OpenLDAP + parentheses balance checks across all search templates. |
| `helpers_test.go` | Helpers `newTestConnection`, `newLDAPEntry`, `newLDAPUser`. |
| `ldap_native_conn_mock.go` | `MockLDAPConn` — a mock for the low-level LDAP connection. |
| `catalog_adapter_mock.go` | `MockCatalogAdapter` — a mock for the catalog adapter. |

**Test scenarios for `LDAPConnection`:**

- ✅ Successful calls.
- ❌ `nil` connection → `"connection not initialized"`.
- ❌ User not found → `"user does not exist"`.
- ❌ More than one entry → `"too many entries returned"`.
- ❌ `Search` / `Bind` errors.
- 🔐 Sensitive data leakage in `Bind` errors — explicitly verified that the original error **does not** appear in the returned error.
- 🔁 `GetRecursiveOUSearchResult` recursion at the `defaultSearchDepth` boundary and below.
- 🧹 `GetSubOUs` filtering: self, unrelated DNs, prefix matches (`ou=root2` vs `ou=root`).

---

## ⚠️ Limitations and TODO

### Current Limitations

- **Single host** — `NewConnection` and `NewAuthenticatedConnection` accept a single host. Multi-host (failover) support is in TODO.
- **Fixed tree depth** — `defaultSearchDepth = 5` is hardcoded. Configurable depth is planned.
- **`GetRecursiveOUSearchResult`** — with several OUs at the same level, `nextLevel` is overwritten on each iteration, so `Children` may contain only the result of the last call. MAYBE Requires fixing (merging results).
- **`NewConnection` / `NewAuthenticatedConnection`** — successful scenarios are not covered by tests because they require a real `ldap.DialURL`. Full coverage requires extracting `DialURL` into a package variable for mocking.

### TODO (from code comments)

- `// TODO: add many hosts support` — multi-host support.
- `// TODO: make controlable depth` — configurable tree depth for recursive search of ou-tree.
- `// TODO: think about limits` — parameterize search limits.
- `// TODO: think what else we need in normalized info` — extend `UserNormalizedInfo`.

---

## 📄 License

Copyright © 2020-2026 NGR Softlab. See the `LICENSE` file in the repository root.

---

## 🤝 Contributing

1. Fork the repository.
2. Create a branch (`git checkout -b feature/my-feature`).
3. Make changes and add tests.
4. Ensure `go test ./...` passes.
5. Open a Pull Request.

**PR requirements:**
- All new methods must be covered by unit tests.
- Public methods and types must have godoc comments.
- Errors must not contain sensitive data (passwords, service account DNs).