package types

type OUInfo struct {
	Name     string    `json:"name"`
	DN       string    `json:"distinguishedName"`
	OU       string    `json:"ou"`
	Children []*OUInfo `json:"children"`
}

type CatalogTree struct {
	Tree []*OUInfo `json:"tree"`
}
