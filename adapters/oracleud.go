// Copyright 2020-2026 NGR Softlab
package adapters

// OUDAdapter targets Oracle Unified Directory (OUD).
//
// OUD shares its LDAP engine with OpenDJ: the same group model
// (groupOfNames / groupOfUniqueNames / posixGroup), the same
// inetOrgPerson-based user schema, and the same virtual isMemberOf
// attribute computed on user entries. Everything OUD needs is therefore
// already provided by OpenDJAdapter; this type exists so that call sites
// read naturally (adapters.OUDAdapter{} instead of
// adapters.OpenDJAdapter{} when talking to OUD) and so that OUD-specific
// quirks can be added later without touching OpenDJ users.
type OUDAdapter struct {
	OpenDJAdapter
}
