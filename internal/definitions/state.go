package definitions

import "github.com/Hikyo-Org/hikyo/internal/schema"

// CurrentState is the pure snapshot of a project's definitions a bundle is
// diffed against. The service builds it from the store; this package never sees
// a store or service type. Environment and key-group ids are always populated
// (they are the identities the matcher binds); presence is expressed by
// environment id, the stable identity the diff compares in.
type CurrentState struct {
	SchemaRevision int64
	Environments   []Environment
	KeyGroups      []KeyGroup
	Keys           []CurrentKey
}

// CurrentKey is one live catalogue key. GroupID is "" when the key belongs to
// no group; Required/Forbidden carry environment ids in their explicit sets.
type CurrentKey struct {
	ID              string
	Name            string
	FolderPath      string
	Classification  string
	Description     string
	Deprecated      bool
	DeprecationNote string
	GroupID         string
	Declaration     schema.Declaration
	Required        schema.Presence
	Forbidden       schema.Presence
}

func envEntities(envs []Environment) []entity {
	out := make([]entity, len(envs))
	for i, e := range envs {
		out[i] = entity{id: e.ID, name: e.Name}
	}
	return out
}

func groupEntities(gs []KeyGroup) []entity {
	out := make([]entity, len(gs))
	for i, g := range gs {
		out[i] = entity{id: g.ID, name: g.Name}
	}
	return out
}

func bundleKeyEntities(keys []Key) []entity {
	out := make([]entity, len(keys))
	for i, k := range keys {
		out[i] = entity{id: k.ID, name: k.Name}
	}
	return out
}

func currentKeyEntities(keys []CurrentKey) []entity {
	out := make([]entity, len(keys))
	for i, k := range keys {
		out[i] = entity{id: k.ID, name: k.Name}
	}
	return out
}
