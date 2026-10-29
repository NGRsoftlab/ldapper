// Copyright 2020-2026 NGR Softlab
package types

// TODO: think what else we need in normalized user info
type UserNormalizedInfo struct {
	DistinguishedName string
	CommonName        string

	Mobile string
	Phone  string
	Mail   string

	Department string
	Title      string
	Manager    string

	Photo string

	Company string
	Country string
	Address string
	City    string
	Index   string
}
