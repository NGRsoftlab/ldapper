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

	// Photo holds raw bytes of the user's JPEG/PNG image. Using string
	// here corrupts non-UTF-8 binary data on JSON serialization: Go's
	// json.Marshal replaces invalid UTF-8 with U+FFFD. If you serialize
	// to JSON, encode with encoding/base64 explicitly or implement a
	// custom MarshalJSON on this type.
	Photo []byte

	Company string
	Country string
	Address string
	City    string
	Index   string
}
