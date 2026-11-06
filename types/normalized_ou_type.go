// Copyright 2020-2026 NGR Softlab
package types

// TODO: think what else we need in normalized ou info

type OUNormalizedInfo struct {
	Name     string              `json:"name"`
	DN       string              `json:"distinguishedName"`
	OU       string              `json:"ou"`
	Children []*OUNormalizedInfo `json:"children"`
}
