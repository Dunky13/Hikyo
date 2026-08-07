// Package badredact is the negative fixture for the redaction analyzer:
// every construct here must be caught, or the analyzer is vacuous.
package badredact

import (
	"encoding/json"
	"fmt"
	"log"
	"log/slog"

	"github.com/Dunky13/wenv/internal/audit"
	"github.com/Dunky13/wenv/internal/crypto"
	"github.com/Dunky13/wenv/internal/store"
)

// Leak formats and marshals sensitive types outside their owning package,
// and mirrors audit content into the ops log.
func Leak(kr *crypto.Keyring, ps *crypto.ProjectSealer, ev audit.Event, row store.AuditEvent) {
	fmt.Printf("keyring: %v\n", kr)       // sensitive → fmt
	_ = fmt.Sprintf("%#v", ps)            // sensitive → fmt
	_, _ = json.Marshal(kr)               // sensitive → encoding/json
	slog.Info("audit event", "event", ev) // audit content → slog
	log.Printf("row: %v", row)            // audit content → log
}
