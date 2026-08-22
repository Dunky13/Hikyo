// Package adapter defines the compiled-in deployment-module seam. Provider
// implementations receive plaintext only for the lifetime of Sync; adapter
// configuration, planning, and connection tests cannot carry it.
package adapter

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode/utf8"
)

const SentinelName = "MANAGED_BY_HIKYO"

type Surface string

const (
	Secret   Surface = "secret"
	Variable Surface = "variable"
)

type Classification string

const (
	SecretClassification Classification = "secret"
	ConfigClassification Classification = "config"
)

type DestinationKind string

const (
	Repository   DestinationKind = "repository"
	Organization DestinationKind = "organization"
	Environment  DestinationKind = "environment"
)

type LedgerState string

const (
	Reserved   LedgerState = "reserved"
	Dispatched LedgerState = "dispatched"
	Owned      LedgerState = "owned"
	Released   LedgerState = "released"
)

type Config struct {
	Origin string
}

type Destination struct {
	Kind                  DestinationKind
	Owner                 string
	Name                  string
	Environment           string
	NumericID             int64
	RepositoryID          int64
	Visibility            string
	SelectedRepositoryIDs []int64
}

type Target struct {
	ID          string
	Environment string
	Destination Destination
	NamePrefix  string
	Generation  int64
}

type Access struct {
	Credential string
}

type ConnectionRequest struct {
	Config                  Config
	Destination             Destination
	Access                  Access
	Gate                    func(context.Context) error
	AllowEnvironmentCreate  bool
	BeforeEnvironmentCreate func(context.Context) error
	AfterEnvironmentCreate  func(context.Context, error) error
}

type Connection struct {
	Version             string
	DestinationID       int64
	RepositoryID        int64
	CredentialExpiresAt time.Time
}

type ManifestEntry struct {
	KeyID          string
	CanonicalName  string
	Classification Classification
	Value          string
}

func (m ManifestEntry) Surface() Surface {
	if m.Classification == ConfigClassification {
		return Variable
	}
	return Secret
}

type LedgerEntry struct {
	Surface       Surface
	EffectiveName string
	State         LedgerState
	// Missing records that Hikyo owns this name but the provider no longer has
	// it. This makes PATCH-404 -> POST crash safe without treating the retry as
	// an unowned capture attempt.
	Missing bool
}

type Disposition string

const (
	Create   Disposition = "create"
	Update   Disposition = "update"
	Delete   Disposition = "delete"
	Conflict Disposition = "conflict"
	Unknown  Disposition = "unknown-until-sync"
)

type Change struct {
	Surface       Surface
	EffectiveName string
	Disposition   Disposition
}

type PlanRequest struct {
	Config   Config
	Target   Target
	Access   Access
	Manifest []ManifestEntry
	Ledger   []LedgerEntry
	Gate     func(context.Context) error
}

type Plan struct {
	Changes  []Change
	Warnings []string
}

type SyncRequest struct {
	Config   Config
	Target   Target
	Access   Access
	Manifest []ManifestEntry
	Ledger   []LedgerEntry
	// Teardown is explicit and fail-closed. Every ordinary sync desires both
	// sentinels; only a tombstoned target's scrub sets this true.
	Teardown bool
	// Completed names were durably finished earlier in this leased job before
	// an in-job provider-rate wait. Modules skip them when plaintext is reloaded.
	Completed []Change
}

type SyncResult struct {
	Changes   []Change
	Conflicts []Change
	Failed    []Change
	Warnings  []string
}

type Effect struct {
	Surface       Surface
	EffectiveName string
	Disposition   Disposition
	KeyID         string
}

type Completion struct {
	Outcome        string
	State          LedgerState // empty releases the claim
	Conflict       bool
	Missing        bool
	ProviderStatus int
	Finding        string
}

// Journal is the durable half of Sync. Prepare runs immediately before each
// external request and must atomically persist the ownership transition and
// INTENT. Complete atomically persists the OUTCOME and resulting ledger state.
// Gate re-authorizes the recorded authority and checks the target generation.
type Journal interface {
	Gate(ctx context.Context, effect Effect) error
	Reserve(ctx context.Context, effect Effect) (LedgerState, error)
	Prepare(ctx context.Context, effect Effect, prior LedgerState) error
	// Finish atomically writes the terminal OUTCOME, applies the final ledger
	// state (empty means release), records any conflict artifact, and releases
	// the provider-write lease held since Prepare.
	Finish(ctx context.Context, effect Effect, completion Completion) error
	// Refuse atomically records a pre-dispatch conflict artifact and releases a
	// bare reservation. It writes no OUTCOME because no provider call began.
	Refuse(ctx context.Context, effect Effect) error
	// ReleaseReservation drops a bare, undispatched reservation that is no
	// longer desired. It records no conflict or OUTCOME and is fenced to the
	// exact current target generation.
	ReleaseReservation(ctx context.Context, effect Effect) error
}

// Module is the locked four-operation, in-process seam.
type Module interface {
	ValidateConfig(Config) error
	TestConnection(context.Context, ConnectionRequest) (Connection, error)
	Plan(context.Context, PlanRequest) (Plan, error)
	Sync(context.Context, SyncRequest, Journal) (SyncResult, error)
}

var effectiveName = regexp.MustCompile(`^[A-Z_][A-Z0-9_]*$`)

// ValidateManifest enforces byte-exact Forgejo delivery. Refusal names the
// key; no normalization or encoding changes application semantics silently.
func ValidateManifest(prefix string, entries []ManifestEntry) error {
	seen := make(map[string]struct{}, len(entries))
	for _, entry := range entries {
		name := prefix + entry.CanonicalName
		switch {
		case entry.Classification != SecretClassification && entry.Classification != ConfigClassification:
			return fmt.Errorf("adapter: %s: unknown classification %q", entry.CanonicalName, entry.Classification)
		case name == prefix+SentinelName:
			return fmt.Errorf("adapter: %s: effective name is reserved for the management sentinel", entry.CanonicalName)
		case len(name) > 128:
			return fmt.Errorf("adapter: %s: effective name exceeds Forgejo's 128-byte limit", entry.CanonicalName)
		case !effectiveName.MatchString(name):
			return fmt.Errorf("adapter: %s: effective name %q is not uppercase Forgejo identifier syntax", entry.CanonicalName, name)
		case strings.HasPrefix(name, "FORGEJO_"), strings.HasPrefix(name, "GITHUB_"), strings.HasPrefix(name, "GITEA_"):
			return fmt.Errorf("adapter: %s: effective name %q uses a reserved provider prefix", entry.CanonicalName, name)
		case entry.Classification == ConfigClassification && name == "CI":
			return fmt.Errorf("adapter: %s: Forgejo reserves CI on the variable surface", entry.CanonicalName)
		case strings.ContainsRune(entry.Value, '\r'):
			return fmt.Errorf("adapter: %s: Forgejo normalizes carriage returns", entry.CanonicalName)
		}
		normalized := strings.ToUpper(name)
		if _, ok := seen[normalized]; ok {
			return fmt.Errorf("adapter: %s: effective name %q collides case-insensitively", entry.CanonicalName, name)
		}
		seen[normalized] = struct{}{}
	}
	return nil
}

// ValidateGitHubActionsManifest applies GitHub's name and byte contract.
// Unlike Forgejo, GitHub permits FORGEJO_, GITEA_, and CI; only GITHUB_ is
// provider-reserved.
func ValidateGitHubActionsManifest(prefix string, entries []ManifestEntry, values bool) error {
	seen := make(map[string]struct{}, len(entries))
	for _, entry := range entries {
		name := prefix + entry.CanonicalName
		switch {
		case entry.Classification != SecretClassification && entry.Classification != ConfigClassification:
			return fmt.Errorf("github-actions: %s: unknown classification %q", entry.CanonicalName, entry.Classification)
		case name == prefix+SentinelName:
			return fmt.Errorf("github-actions: %s: effective name is reserved for management sentinel", entry.CanonicalName)
		case !effectiveName.MatchString(name):
			return fmt.Errorf("github-actions: %s: effective name %q is not uppercase GitHub Actions identifier syntax", entry.CanonicalName, name)
		case strings.HasPrefix(name, "GITHUB_"):
			return fmt.Errorf("github-actions: %s: effective name %q uses reserved GITHUB_ prefix", entry.CanonicalName, name)
		case values && len([]byte(entry.Value)) > 48*1024:
			return fmt.Errorf("github-actions: %s: value exceeds GitHub's 48 KB limit", entry.CanonicalName)
		case values && strings.ContainsRune(entry.Value, '\x00'):
			return fmt.Errorf("github-actions: %s: NUL-containing values are not workflow-byte-exact", entry.CanonicalName)
		case values && !utf8.ValidString(entry.Value):
			return fmt.Errorf("github-actions: %s: non-UTF-8 values cannot be represented byte-exactly by GitHub's JSON API", entry.CanonicalName)
		}
		normalized := strings.ToUpper(name)
		if _, ok := seen[normalized]; ok {
			return fmt.Errorf("github-actions: %s: effective name %q collides case-insensitively", entry.CanonicalName, name)
		}
		seen[normalized] = struct{}{}
	}
	return nil
}

func ValidateProviderManifest(provider, prefix string, entries []ManifestEntry, values bool) error {
	kind, err := ParseProvider(provider)
	if err != nil {
		return err
	}
	switch kind {
	case GitHubActionsProvider:
		return ValidateGitHubActionsManifest(prefix, entries, values)
	case ForgejoProvider:
		return ValidateManifest(prefix, entries)
	default:
		return fmt.Errorf("adapter: unknown provider %q", provider)
	}
}

// Workflow renders names only. Prefixing is provider wiring; applications
// continue to receive canonical names in every environment.
func Workflow(prefix string, entries []ManifestEntry) (string, error) {
	if err := ValidateManifest(prefix, entries); err != nil {
		return "", err
	}
	return renderWorkflow(prefix, entries), nil
}

func WorkflowForProvider(provider, prefix string, entries []ManifestEntry) (string, error) {
	if err := ValidateProviderManifest(provider, prefix, entries, false); err != nil {
		return "", err
	}
	return renderWorkflow(prefix, entries), nil
}

// RecipientSetNeedsCeremony classifies the exact locked narrowing cases.
// Only all->private, all->selected, and removal from an unchanged selected
// set may skip the full recipient-set authorization ceremony.
func RecipientSetNeedsCeremony(oldVisibility string, oldIDs []int64, newVisibility string, newIDs []int64) bool {
	oldSet := append([]int64(nil), oldIDs...)
	newSet := append([]int64(nil), newIDs...)
	slices.Sort(oldSet)
	slices.Sort(newSet)
	if oldVisibility == newVisibility {
		if oldVisibility != "selected" || slices.Equal(oldSet, newSet) {
			return false
		}
		for _, id := range newSet {
			if !slices.Contains(oldSet, id) {
				return true
			}
		}
		return false
	}
	return !(oldVisibility == "all" && (newVisibility == "private" || newVisibility == "selected"))
}

func renderWorkflow(prefix string, entries []ManifestEntry) string {
	rows := slices.Clone(entries)
	slices.SortFunc(rows, func(a, b ManifestEntry) int { return strings.Compare(a.CanonicalName, b.CanonicalName) })
	var out strings.Builder
	out.WriteString("env:\n")
	for _, entry := range rows {
		surface := "secrets"
		if entry.Classification == ConfigClassification {
			surface = "vars"
		}
		_, _ = fmt.Fprintf(&out, "  %s: ${{ %s.%s%s }}\n", entry.CanonicalName, surface, prefix, entry.CanonicalName)
	}
	return out.String()
}

var (
	ErrConflict      = errors.New("adapter: exists, unowned")
	ErrSuperseded    = errors.New("adapter: target generation superseded")
	ErrUnauthorized  = errors.New("adapter: recorded authority no longer authorized")
	ErrProviderAuth  = errors.New("adapter: provider credential was refused")
	ErrIndeterminate = errors.New("adapter: provider outcome indeterminate")
	ErrVersionFloor  = errors.New("adapter: Forgejo requires version >= 1.21")
	ErrDestinationID = errors.New("adapter: destination numeric id changed")
	ErrProviderBusy  = errors.New("adapter: provider write is still in flight")
	ErrQueueFull     = errors.New("adapter: target outbox queue limit reached")
	ErrLedgerFull    = errors.New("adapter: target ownership ledger limit reached")
	ErrRateLimited   = errors.New("adapter: provider rate limited")
)

// RetryAtError lets a provider preserve an authoritative rate-limit deadline
// through the generic outbox boundary without retaining plaintext in memory.
type RetryAtError interface {
	error
	RetryAt() time.Time
}

func ProviderRetryAt(err error) (time.Time, bool) {
	var retry RetryAtError
	if !errors.As(err, &retry) {
		return time.Time{}, false
	}
	return retry.RetryAt(), true
}
