package remotefetch

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// The directory fetch itself: the one request this package makes.
//
// The PATH is a constant here and never comes from configuration. The URL
// grammar refuses a stored value carrying a path at all, and this is the other
// half of that rule — "the fetch path is appended by the client from the API
// contract, never from configuration" (ADR § The outbound client). An endpoint
// whose target is named by stored data is a proxy whatever it is called.
const directoryPath = "/api/v1/instance/directory"

// Ingest caps. Foreign bytes are bounded BEFORE they are parsed and again
// after: ResponseCap bounds the transfer, and these bound the structure, so a
// peer that answers within a megabyte still cannot hand this instance a
// hundred thousand org names to hold in memory or render.
const (
	MaxOrgs            = 1000
	MaxProjectsPerOrg  = 1000
	MaxListingNameLen  = 200
	MaxIdentityLen     = 128
	MaxVersionStringLn = 64
)

// Listing is the served directory: what the connection credential authorizes,
// exhaustively. Instance identity, version, and the NAMES of orgs and projects.
// No values, no keys, no environments, no membership, no settings, no audit —
// and there is deliberately no field here that could hold one.
//
// Counts are not fields: they are len(). A count beside the names it counts is
// a second copy of the same fact that can disagree with it.
type Listing struct {
	Identity string     `json:"identity"`
	Version  string     `json:"version"`
	Orgs     []OrgEntry `json:"orgs"`
	// OrgCount and ProjectCount are on the WIRE but are not the source of
	// truth: they are len() of what is beside them, sent so a client can show
	// a number without walking the tree. boundListing REFUSES a listing whose
	// counts disagree with its own names — a peer that says "12 orgs" and
	// sends 3 is either broken or lying, and picking one of the two numbers
	// would be picking which lie to believe.
	OrgCount     int `json:"org_count"`
	ProjectCount int `json:"project_count"`
}

// OrgEntry is one organisation's name and its projects' names.
type OrgEntry struct {
	Name     string   `json:"name"`
	Projects []string `json:"projects"`
}

// CountProjects is the total across every org, computed from the names. The
// wire field is checked against it on ingest and is never trusted instead.
func (l Listing) CountProjects() int {
	n := 0
	for _, o := range l.Orgs {
		n += len(o.Projects)
	}
	return n
}

// Directory performs one authenticated fetch against one remote.
//
// It returns the outcome ALWAYS — including on success — because the caller
// writes that outcome to the snapshot either way, and a caller that had to
// infer "ok" from a nil error would eventually infer it wrongly. The error is
// the detail for logs; the outcome is the operator-visible state.
//
// Nothing about the response is trusted before it is bounded: the body is read
// through a limit reader at ResponseCap, parsed, and then length-capped field
// by field. A peer that overruns any cap is a fetch failure by name, not a
// silently truncated listing.
func (c *Client) Directory(ctx context.Context, origin, pin, credential string) (Listing, Outcome, error) {
	// Canonical, not merely valid: a stored value with a trailing slash would
	// otherwise build `//api/v1/instance/directory`.
	canonical, err := CanonicalRemoteURL(origin)
	if err != nil {
		return Listing{}, OutcomeUnreachable, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, canonical+directoryPath, nil)
	if err != nil {
		return Listing{}, OutcomeUnreachable, err
	}
	// The credential leaves the process only here, inside TLS to the pinned
	// remote, and only after VerifyPeerCertificate has accepted the key.
	req.Header.Set("Authorization", "Bearer "+credential)
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient(pin).Do(req)
	if err != nil {
		return Listing{}, ClassifyError(err, 0), err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return Listing{}, ClassifyError(nil, resp.StatusCode),
			fmt.Errorf("remotefetch: remote answered %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, c.cfg.ResponseCap+1))
	if err != nil {
		return Listing{}, OutcomeUnreachable, err
	}
	if int64(len(body)) > c.cfg.ResponseCap {
		return Listing{}, OutcomeUnreachable,
			fmt.Errorf("remotefetch: response exceeds the %d-byte cap", c.cfg.ResponseCap)
	}

	var l Listing
	// Unknown fields are refused rather than ignored: the listing is a closed
	// contract, and a peer sending something this revision does not know about
	// is a version-skew signal, not a field to drop on the floor.
	dec := json.NewDecoder(strings.NewReader(string(body)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&l); err != nil {
		// Sanitized: the parse error is the caller's to log, never the
		// operator's to read as foreign text on a card.
		return Listing{}, OutcomeUnreachable, fmt.Errorf("remotefetch: listing did not parse: %w", err)
	}
	if err := boundListing(l); err != nil {
		return Listing{}, OutcomeUnreachable, err
	}
	return l, OutcomeOK, nil
}

// boundListing is the parse-before-trust half: every field the remote controls
// is length-capped on ingest.
func boundListing(l Listing) error {
	switch {
	case l.Identity == "" || len(l.Identity) > MaxIdentityLen:
		return fmt.Errorf("remotefetch: listing identity is empty or over %d bytes", MaxIdentityLen)
	case len(l.Version) > MaxVersionStringLn:
		return fmt.Errorf("remotefetch: listing version is over %d bytes", MaxVersionStringLn)
	case len(l.Orgs) > MaxOrgs:
		return fmt.Errorf("remotefetch: listing names more than %d organisations", MaxOrgs)
	case l.OrgCount != len(l.Orgs):
		return fmt.Errorf("remotefetch: listing claims %d organisations and names %d", l.OrgCount, len(l.Orgs))
	case l.ProjectCount != l.CountProjects():
		return fmt.Errorf("remotefetch: listing claims %d projects and names %d", l.ProjectCount, l.CountProjects())
	}
	for _, o := range l.Orgs {
		if len(o.Name) > MaxListingNameLen {
			return fmt.Errorf("remotefetch: an organisation name exceeds %d bytes", MaxListingNameLen)
		}
		if len(o.Projects) > MaxProjectsPerOrg {
			return fmt.Errorf("remotefetch: an organisation names more than %d projects", MaxProjectsPerOrg)
		}
		for _, p := range o.Projects {
			if len(p) > MaxListingNameLen {
				return fmt.Errorf("remotefetch: a project name exceeds %d bytes", MaxListingNameLen)
			}
		}
	}
	return nil
}

// Target is one remote to fetch in a fan-out round.
type Target struct {
	ID         string
	Origin     string
	Pin        string
	Credential string
}

// Result pairs a target with what came back.
type Result struct {
	ID      string
	Listing Listing
	Outcome Outcome
	Err     error
}

// FetchAll runs one fan-out round under the configured cap.
//
// The cap is a semaphore rather than a worker pool because the bound the ADR
// states is on CONCURRENT CONNECTIONS, not on goroutines: with RemoteCount at
// 50 and FanOut at 4, a pathological all-unreachable directory is thirteen
// sequential rounds of the per-remote deadline, which is the arithmetic the
// bound was chosen for.
// FetchAll returns a result for every target it ATTEMPTED, and omits every
// target it did not. The distinction is the whole contract: a target the round
// never reached has produced no evidence about the remote, and inventing
// `unreachable` for it would persist a failure snapshot and an audit event for
// a connection nobody opened. A caller that finds no entry for a target serves
// its last-known snapshot AS a snapshot, which is the honest answer.
//
// Two places drop a target, both before any byte is written: the queue, if the
// round ends while it is waiting for a fan-out slot, and the moment after
// acquiring one, if the round ended in between.
func (c *Client) FetchAll(ctx context.Context, targets []Target) []Result {
	out := make([]Result, len(targets))
	attempted := make([]bool, len(targets))
	sem := make(chan struct{}, c.cfg.FanOut)
	var wg sync.WaitGroup
	for i, t := range targets {
		wg.Add(1)
		go func(i int, t Target) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				return
			}
			defer func() { <-sem }()
			if ctx.Err() != nil {
				return
			}
			attempted[i] = true
			l, o, err := c.Directory(ctx, t.Origin, t.Pin, t.Credential)
			out[i] = Result{ID: t.ID, Listing: l, Outcome: o, Err: err}
		}(i, t)
	}
	wg.Wait()
	got := make([]Result, 0, len(targets))
	for i := range out {
		if attempted[i] {
			got = append(got, out[i])
		}
	}
	return got
}

// RoundBudget is the honest whole-round maximum for n targets: the number of
// WAVES the fan-out cap forces, each allowed its per-remote deadline, plus one
// deadline of margin for scheduling.
//
// A flat multiple of the per-remote deadline is what this replaced, and it was
// a lie at fleet scale: at 50 remotes and a fan-out of 4 the round needs
// thirteen waves, so a two-deadline budget cancelled forty-two requests that
// had never had their own chance. They came back `unreachable` and were
// persisted as fetch failures — the round manufacturing evidence about remotes
// it never dialled.
func (c *Client) RoundBudget(n int) time.Duration {
	if n <= 0 {
		return c.cfg.Deadline
	}
	fanOut := c.cfg.FanOut
	if fanOut < 1 {
		fanOut = 1
	}
	waves := (n + fanOut - 1) / fanOut
	return time.Duration(waves+1) * c.cfg.Deadline
}
