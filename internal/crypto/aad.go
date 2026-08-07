package crypto

import "encoding/binary"

// Associated-data encoding, per the encryption ADR § Envelope format:
// injective by construction. Every AAD is a length-prefixed sequence — each
// field emitted as a uint32 big-endian byte length followed by its bytes,
// absent fields emitted as length zero, field order fixed by the schema for
// its envelope kind, no separators, no text formatting.

func be32(v uint32) []byte {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], v)
	return b[:]
}

func appendLP(dst, field []byte) []byte {
	dst = append(dst, be32(uint32(len(field)))...)
	return append(dst, field...)
}

// AAD is implemented by exactly one struct per envelope kind. The interface
// is sealed (unexported methods): the six schemas below are the closed set
// the ADR fixes, and a new kind is an ADR amendment, not a new struct.
type AAD interface {
	kind() Kind
	fields() [][]byte
}

// appendAAD builds the full associated data for a record: the authenticated
// header bytes followed by the kind's length-prefixed field sequence.
func appendAAD(header []byte, a AAD) []byte {
	out := append([]byte(nil), header...)
	for _, f := range a.fields() {
		out = appendLP(out, f)
	}
	return out
}

// ValueAAD binds a stored value ciphertext to exactly one row: kind `value`,
// fields org_id, project_id, env_id, key_id, row_id, field_tag. (env_id per
// the flat-model amendment to the encryption ADR — every value row has an
// owning environment.)
type ValueAAD struct {
	OrgID, ProjectID, EnvID, KeyID, RowID, FieldTag string
}

func (a ValueAAD) kind() Kind { return KindValue }
func (a ValueAAD) fields() [][]byte {
	return [][]byte{
		[]byte(a.OrgID), []byte(a.ProjectID), []byte(a.EnvID),
		[]byte(a.KeyID), []byte(a.RowID), []byte(a.FieldTag),
	}
}

// WrappedDEKAAD covers tier-3 keys wrapped by the master key: project DEKs,
// the instance DEK (empty org/project), and — per the secret-scanning
// amendment — the future scanning-fingerprint key. Fields org_id, project_id,
// dek_id, dek_version, master_key_version.
type WrappedDEKAAD struct {
	OrgID, ProjectID, DEKID      string
	DEKVersion, MasterKeyVersion uint32
}

func (a WrappedDEKAAD) kind() Kind { return KindWrappedDEK }
func (a WrappedDEKAAD) fields() [][]byte {
	return [][]byte{
		[]byte(a.OrgID), []byte(a.ProjectID), []byte(a.DEKID),
		be32(a.DEKVersion), be32(a.MasterKeyVersion),
	}
}

// WrappedMasterAAD covers the master key wrapped by the operator root:
// fields master_key_version, root_key_epoch.
type WrappedMasterAAD struct {
	MasterKeyVersion, RootKeyEpoch uint32
}

func (a WrappedMasterAAD) kind() Kind { return KindWrappedMaster }
func (a WrappedMasterAAD) fields() [][]byte {
	return [][]byte{be32(a.MasterKeyVersion), be32(a.RootKeyEpoch)}
}

// WrappedTokenKeyAAD covers the root token key wrapped by the master key:
// fields token_key_version, master_key_version.
type WrappedTokenKeyAAD struct {
	TokenKeyVersion, MasterKeyVersion uint32
}

func (a WrappedTokenKeyAAD) kind() Kind { return KindWrappedTokenKey }
func (a WrappedTokenKeyAAD) fields() [][]byte {
	return [][]byte{be32(a.TokenKeyVersion), be32(a.MasterKeyVersion)}
}

// ProjectFieldAAD covers project-scoped sensitive fields outside the value
// table: fields org_id, project_id, owner_table, owner_row_id, field_tag.
type ProjectFieldAAD struct {
	OrgID, ProjectID, OwnerTable, OwnerRowID, FieldTag string
}

func (a ProjectFieldAAD) kind() Kind { return KindProjectField }
func (a ProjectFieldAAD) fields() [][]byte {
	return [][]byte{
		[]byte(a.OrgID), []byte(a.ProjectID),
		[]byte(a.OwnerTable), []byte(a.OwnerRowID), []byte(a.FieldTag),
	}
}

// InstanceFieldAAD covers instance-scoped sensitive fields (MFA seeds,
// recovery codes, instance credentials): fields owner_table, owner_row_id,
// field_tag.
type InstanceFieldAAD struct {
	OwnerTable, OwnerRowID, FieldTag string
}

func (a InstanceFieldAAD) kind() Kind { return KindInstanceField }
func (a InstanceFieldAAD) fields() [][]byte {
	return [][]byte{[]byte(a.OwnerTable), []byte(a.OwnerRowID), []byte(a.FieldTag)}
}
