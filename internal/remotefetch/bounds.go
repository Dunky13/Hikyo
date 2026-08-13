package remotefetch

import "time"

// The multi-instance ADR's composable-maxima entries (#71, amending the ops
// spec #32).
//
// RATIFIED by the owner on 2026-08-13. The directory bounds and handoff expiry
// remain exactly as proposed for #71. The workspace lifetime pair was ratified
// with the hard-short values below after the ADR's extractable-bearer residual
// was dispositioned. If a value moves, it moves here and nowhere else.
//
// They are colocated in this package deliberately. Three of them
// (WorkspaceSessionIdle, WorkspaceSessionAbsolute, HandoffExpiry) are not
// outbound-client concerns at all and would naturally live beside the workspace
// service — but they are one ADR's one catalogue addition, and splitting them
// across packages is how half a table gets ratified and the other half
// forgotten. One block, one review.
const (
	// Deadline bounds one remote's entire fetch, connect through body read.
	// Rhymes with row 17's HTTP header/read timeout scale.
	Deadline = 10 * time.Second

	// ResponseCap bounds the bytes read from one remote. Rhymes with row 19's
	// adapter response cap. A directory listing is org and project names and
	// counts; a megabyte is already generous for it, which is the point — the
	// cap exists to bound a hostile or broken peer, not to fit the payload.
	ResponseCap = 1 << 20 // 1 MiB

	// RemoteCount caps configured entries. Rhymes with row 13's environment cap
	// scale. It bounds the fan-out's worst case as much as the directory's
	// size: fifty entries is a fleet, not a rounding error.
	RemoteCount = 50

	// FanOut caps parallel fetches, matching the four-concurrent-per-org
	// pattern in rows 17 and 19. With RemoteCount at 50 this makes a full
	// directory view at most thirteen sequential rounds of a ten-second
	// deadline in the pathological all-unreachable case.
	FanOut = 4

	// CoalesceWindow is how long concurrent viewers share one in-flight fetch.
	// It exists so a card open on several screens is one connection per remote,
	// not one per human — the per-viewer rate below bounds a single human, and
	// this bounds the crowd.
	CoalesceWindow = 5 * time.Second

	// ViewerTriggerRate bounds how often ONE holder of instance-directory may
	// trigger a fetch round. Human card-refresh scale: six a minute is a person
	// clicking refresh, and anything faster is not a person.
	ViewerTriggerRate = 6 // per minute, per viewer

	// AggregateTriggerRate bounds the WHOLE INSTANCE, and it is the cap that
	// actually protects the fleet. The ADR is explicit that per-viewer limiting
	// alone does not bound many principals: fifty viewers each politely under
	// their own limit is still fifty times the traffic at every remote. Rhymes
	// with row 17's fail-closed default budget.
	AggregateTriggerRate = 60 // per minute, instance-wide

	// WorkspaceSessionIdle and WorkspaceSessionAbsolute are the ratified
	// HARD-SHORT pair (owner, 2026-08-13), deliberately matching ops-spec row
	// 5's reveal window and cap: a workspace is a disclosure surface, and its
	// header-borne bearer is extractable and replayable outside the browser.
	// The shell's liveness poll (currently every 5 seconds) keeps an open tab
	// alive, so idle means the session dies 15 minutes after the tab closes.
	WorkspaceSessionIdle     = 15 * time.Minute
	WorkspaceSessionAbsolute = 4 * time.Hour

	// HandoffExpiry bounds the single-use handoff transaction. Authorization-
	// code analogue, rhyming with row 7. The ADR says "expires in minutes"; ten
	// is the loosest reading of that, chosen because the ceremony inside the
	// popup may include a full OIDC round trip with an unfamiliar IdP.
	HandoffExpiry = 10 * time.Minute
)

// DefaultConfig is the owner-ratified Config every production caller
// builds from. New() still refuses an incomplete Config, so this is the only
// place the numbers enter the system — a caller that wants different bounds has
// to say so explicitly rather than inherit a silent default.
func DefaultConfig() Config {
	return Config{
		Deadline:    Deadline,
		ResponseCap: ResponseCap,
		FanOut:      FanOut,
	}
}
