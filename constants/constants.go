// Copyright 2020-2026 NGR Softlab
package constants

import "time"

const (
	DefaultSearchSizeLimit = 0 // 0 — no size limit (server default)
	DefaultSearchTimeLimit = 30

	DefaultMaxHostsLength        = 50
	DefaultCatalogSearchPageSize = 1000

	DefaultDialTimeout     = 10 * time.Second
	DefaultStartTLSTimeout = 30 * time.Second
)
