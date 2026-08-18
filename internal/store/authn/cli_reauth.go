package authn

import (
	"context"
	"time"

	"github.com/Hikyo-Org/hikyo/internal/domain"
	"github.com/Hikyo-Org/hikyo/internal/store/pggen"
	"github.com/Hikyo-Org/hikyo/internal/store/sqlitegen"
)

type CLIReauthHandoff struct {
	ID, SessionID, Operation, EnvironmentSet, PKCEChallenge, RedirectURI string
	StateVerifier, CodeVerifier, ApprovedWindows                         []byte
	PrincipalID                                                          domain.PrincipalID
	CreatedAt, ExpiresAt, ConsumedAt                                     time.Time
}

func (h CLIReauthHandoff) Live(now time.Time) bool {
	return h.ConsumedAt.IsZero() && now.Before(h.ExpiresAt)
}

type NewCLIReauthHandoff struct {
	ID, SessionID, Operation, EnvironmentSet, PKCEChallenge, RedirectURI string
	StateVerifier                                                        []byte
	PrincipalID                                                          domain.PrincipalID
	CreatedAt, ExpiresAt                                                 time.Time
}

func (r *Resolver) CreateCLIReauthHandoff(ctx context.Context, h NewCLIReauthHandoff) error {
	if r.sq != nil {
		return r.sq.InsertCLIReauthHandoff(ctx, sqlitegen.InsertCLIReauthHandoffParams{ID: h.ID, StateVerifier: h.StateVerifier, SessionID: h.SessionID, PrincipalID: string(h.PrincipalID), Operation: h.Operation, EnvironmentSet: h.EnvironmentSet, PkceChallenge: h.PKCEChallenge, RedirectUri: h.RedirectURI, CreatedAt: encodeTime(h.CreatedAt), ExpiresAt: encodeTime(h.ExpiresAt)})
	}
	return r.pg.InsertCLIReauthHandoff(ctx, pggen.InsertCLIReauthHandoffParams{ID: h.ID, StateVerifier: h.StateVerifier, SessionID: h.SessionID, PrincipalID: string(h.PrincipalID), Operation: h.Operation, EnvironmentSet: h.EnvironmentSet, PkceChallenge: h.PKCEChallenge, RedirectUri: h.RedirectURI, CreatedAt: pgTime(h.CreatedAt), ExpiresAt: pgTime(h.ExpiresAt)})
}

func (r *Resolver) CLIReauthHandoffByState(ctx context.Context, verifier []byte) (CLIReauthHandoff, error) {
	if r.sq != nil {
		row, err := r.sq.CLIReauthHandoffByState(ctx, verifier)
		if err != nil {
			return CLIReauthHandoff{}, notFoundOr(err)
		}
		created, err := decodeTime(row.CreatedAt)
		if err != nil {
			return CLIReauthHandoff{}, err
		}
		expires, err := decodeTime(row.ExpiresAt)
		if err != nil {
			return CLIReauthHandoff{}, err
		}
		consumed, err := decodeNullTime(row.ConsumedAt)
		if err != nil {
			return CLIReauthHandoff{}, err
		}
		return CLIReauthHandoff{ID: row.ID, StateVerifier: row.StateVerifier, CodeVerifier: row.CodeVerifier, SessionID: row.SessionID, PrincipalID: domain.PrincipalID(row.PrincipalID), Operation: row.Operation, EnvironmentSet: row.EnvironmentSet, PKCEChallenge: row.PkceChallenge, RedirectURI: row.RedirectUri, ApprovedWindows: []byte(row.ApprovedWindows), CreatedAt: created, ExpiresAt: expires, ConsumedAt: consumed}, nil
	}
	row, err := r.pg.CLIReauthHandoffByState(ctx, verifier)
	if err != nil {
		return CLIReauthHandoff{}, notFoundOr(err)
	}
	return cliReauthFromPG(row), nil
}

func (r *Resolver) CLIReauthHandoffByCode(ctx context.Context, verifier []byte) (CLIReauthHandoff, error) {
	if r.sq != nil {
		row, err := r.sq.CLIReauthHandoffByCode(ctx, verifier)
		if err != nil {
			return CLIReauthHandoff{}, notFoundOr(err)
		}
		created, err := decodeTime(row.CreatedAt)
		if err != nil {
			return CLIReauthHandoff{}, err
		}
		expires, err := decodeTime(row.ExpiresAt)
		if err != nil {
			return CLIReauthHandoff{}, err
		}
		consumed, err := decodeNullTime(row.ConsumedAt)
		if err != nil {
			return CLIReauthHandoff{}, err
		}
		return CLIReauthHandoff{ID: row.ID, StateVerifier: row.StateVerifier, CodeVerifier: row.CodeVerifier, SessionID: row.SessionID, PrincipalID: domain.PrincipalID(row.PrincipalID), Operation: row.Operation, EnvironmentSet: row.EnvironmentSet, PKCEChallenge: row.PkceChallenge, RedirectURI: row.RedirectUri, ApprovedWindows: []byte(row.ApprovedWindows), CreatedAt: created, ExpiresAt: expires, ConsumedAt: consumed}, nil
	}
	row, err := r.pg.CLIReauthHandoffByCode(ctx, verifier)
	if err != nil {
		return CLIReauthHandoff{}, notFoundOr(err)
	}
	return cliReauthFromPG(row), nil
}

func cliReauthFromPG(row pggen.CliReauthHandoff) CLIReauthHandoff {
	return CLIReauthHandoff{ID: row.ID, StateVerifier: row.StateVerifier, CodeVerifier: row.CodeVerifier, SessionID: row.SessionID, PrincipalID: domain.PrincipalID(row.PrincipalID), Operation: row.Operation, EnvironmentSet: row.EnvironmentSet, PKCEChallenge: row.PkceChallenge, RedirectURI: row.RedirectUri, ApprovedWindows: row.ApprovedWindows, CreatedAt: row.CreatedAt.Time, ExpiresAt: row.ExpiresAt.Time, ConsumedAt: row.ConsumedAt.Time}
}

func (r *Resolver) ApproveCLIReauthHandoff(ctx context.Context, id string, codeVerifier, windows []byte) (bool, error) {
	if r.sq != nil {
		n, err := r.sq.ApproveCLIReauthHandoff(ctx, sqlitegen.ApproveCLIReauthHandoffParams{ID: id, CodeVerifier: codeVerifier, ApprovedWindows: string(windows)})
		return n == 1, err
	}
	n, err := r.pg.ApproveCLIReauthHandoff(ctx, pggen.ApproveCLIReauthHandoffParams{ID: id, CodeVerifier: codeVerifier, ApprovedWindows: windows})
	return n == 1, err
}

func (r *Resolver) ConsumeCLIReauthHandoff(ctx context.Context, id string, at time.Time) (bool, error) {
	if r.sq != nil {
		n, err := r.sq.ConsumeCLIReauthHandoff(ctx, sqlitegen.ConsumeCLIReauthHandoffParams{ID: id, ConsumedAt: nullTimeString(at)})
		return n == 1, err
	}
	n, err := r.pg.ConsumeCLIReauthHandoff(ctx, pggen.ConsumeCLIReauthHandoffParams{ID: id, ConsumedAt: nullPGTime(at)})
	return n == 1, err
}
