package definitions

// KindDiff is the rendered per-kind change list carried by a plan and by a
// check result. Environment and key-group entries have only a name, so their
// changes appear as Creates, Renames, and Deletes; Updates is a key-only field.
type KindDiff struct {
	Creates []string `json:"creates"`
	Updates []string `json:"updates"`
	Renames []Rename `json:"renames"`
	Deletes []string `json:"deletes"`
}

// Diff is the human-readable plan preview derived from a Resolution. Deletion
// live-occurrence counts and reveal enforcement are the service's to enrich; the
// pure diff carries the structural shape and the reveal-required key names.
type Diff struct {
	Environments   KindDiff `json:"environments"`
	KeyGroups      KindDiff `json:"key_groups"`
	Keys           KindDiff `json:"keys"`
	RevealRequired []string `json:"reveal_required"`
}

// Diff renders the resolution as the plan preview.
func (r Resolution) Diff() Diff {
	d := Diff{RevealRequired: strs(r.RevealKeys)}
	d.Environments = KindDiff{
		Creates: strs(r.EnvCreates),
		Updates: []string{},
		Renames: renames(r.EnvRenames),
		Deletes: refNames(r.EnvDeletes),
	}
	d.KeyGroups = KindDiff{
		Creates: strs(r.GroupCreates),
		Updates: []string{},
		Renames: renames(r.GroupRenames),
		Deletes: refNames(r.GroupDeletes),
	}
	keyUpdates := make([]string, 0, len(r.KeyUpdates))
	keyRenames := make([]Rename, 0)
	for _, u := range r.KeyUpdates {
		keyUpdates = append(keyUpdates, u.Desired.Name)
		if u.Renamed {
			keyRenames = append(keyRenames, Rename{ID: u.ID, From: u.PrevName, To: u.Desired.Name})
		}
	}
	d.Keys = KindDiff{
		Creates: createNames(r.KeyCreates),
		Updates: keyUpdates,
		Renames: keyRenames,
		Deletes: refNames(r.KeyDeletes),
	}
	return d
}

// Empty reports whether the resolution changes nothing.
func (r Resolution) Empty() bool {
	return len(r.EnvCreates) == 0 && len(r.EnvRenames) == 0 && len(r.EnvDeletes) == 0 &&
		len(r.GroupCreates) == 0 && len(r.GroupRenames) == 0 && len(r.GroupDeletes) == 0 &&
		len(r.KeyCreates) == 0 && len(r.KeyUpdates) == 0 && len(r.KeyDeletes) == 0
}

// DeletionsPresent reports whether any kind carries a deletion.
func (r Resolution) DeletionsPresent() bool {
	return len(r.EnvDeletes) > 0 || len(r.GroupDeletes) > 0 || len(r.KeyDeletes) > 0
}

// DriftState is the four-way file-versus-database classification (source-of-truth
// ADR § Drift). check reports it with the 0/1/2 exit contract.
type DriftState string

const (
	DriftEqual     DriftState = "equal"
	DriftFileAhead DriftState = "file_ahead"
	DriftDBAhead   DriftState = "db_ahead"
	DriftDiverged  DriftState = "diverged"
)

// Classify reports the drift between a bundle and current state. A bundle whose
// base revision is ahead of current is impossible or foreign and is refused; a
// base behind current with content matching current is db_ahead, with content
// differing is diverged; an equal base is equal or file_ahead by whether the
// bundle changes anything. An additive bundle has no base, so it is file_ahead
// when it would create or change anything and equal otherwise.
func Classify(b Bundle, cur CurrentState) (DriftState, error) {
	res, err := resolve(b, cur, false)
	if err != nil {
		return "", err
	}
	diff := !res.Empty()

	if b.Additive() {
		if diff {
			return DriftFileAhead, nil
		}
		return DriftEqual, nil
	}

	base := *b.BaseRevision
	switch {
	case base > cur.SchemaRevision:
		return "", invalidDetail(
			"bundle base revision %d is ahead of the current definitions revision %d — impossible or foreign bundle",
			base, cur.SchemaRevision)
	case base == cur.SchemaRevision:
		if diff {
			return DriftFileAhead, nil
		}
		return DriftEqual, nil
	default: // base < current
		if diff {
			return DriftDiverged, nil
		}
		return DriftDBAhead, nil
	}
}

// Compare classifies drift and renders the diff in one pass, for the diagnostic
// `check`. It tolerates additive modification (records it as a difference rather
// than refusing), because check reports state and never writes.
func Compare(b Bundle, cur CurrentState) (DriftState, Diff, error) {
	res, err := resolve(b, cur, false)
	if err != nil {
		return "", Diff{}, err
	}
	diff := !res.Empty()
	if b.Additive() {
		if diff {
			return DriftFileAhead, res.Diff(), nil
		}
		return DriftEqual, res.Diff(), nil
	}
	base := *b.BaseRevision
	switch {
	case base > cur.SchemaRevision:
		return "", Diff{}, invalidDetail(
			"bundle base revision %d is ahead of the current definitions revision %d — impossible or foreign bundle",
			base, cur.SchemaRevision)
	case base == cur.SchemaRevision:
		if diff {
			return DriftFileAhead, res.Diff(), nil
		}
		return DriftEqual, res.Diff(), nil
	default:
		if diff {
			return DriftDiverged, res.Diff(), nil
		}
		return DriftDBAhead, res.Diff(), nil
	}
}

func strs(in []string) []string {
	if in == nil {
		return []string{}
	}
	return in
}

func renames(in []Rename) []Rename {
	if in == nil {
		return []Rename{}
	}
	return in
}

func refNames(refs []Ref) []string {
	out := make([]string, 0, len(refs))
	for _, r := range refs {
		out = append(out, r.Name)
	}
	return out
}

func createNames(keys []Key) []string {
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		out = append(out, k.Name)
	}
	return out
}
