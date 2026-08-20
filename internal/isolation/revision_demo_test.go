package isolation

import (
	"bufio"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Hikyo-Org/hikyo/internal/cli"
)

// runRevisionDemo is the #51 demo criterion, executed rather than described:
//
//	edit -> selective publish -> fetch the resolved snapshot via the CLI,
//	with a SECOND CLIENT seeing the SSE advisory.
//
// Real server, real CLI over a socket, real keyring, real datastore. The only
// thing that is not the CLI is the advisory stream, and only because the CLI
// has no verb for it: the channel authenticates on the same session artifact
// the browser surface uses, so the second client presents the artifact the CLI
// itself just used.
func runRevisionDemo(t *testing.T, ios func() cli.IO, org, baseURL string, bearer func() string) {
	t.Helper()

	run := func(args ...string) string {
		t.Helper()
		out := &strings.Builder{}
		io := ios()
		io.Stdout = out
		if code := cli.Run(t.Context(), io, args); code != cli.ExitOK {
			t.Fatalf("hikyo %s exited %d\n%s", strings.Join(args, " "), code, out.String())
		}
		return out.String()
	}
	decode := func(raw string, into any) {
		t.Helper()
		if err := json.Unmarshal([]byte(raw), into); err != nil {
			t.Fatalf("output is not JSON: %v\n%s", err, raw)
		}
	}
	type row struct{ Id, Name string }

	// It rides the org the hierarchy demo already built, where the
	// administrator holds the admin template: minting a second org would need
	// a second self-grant, which kills its own session, and the relogin that
	// follows counts against the instance-wide pre-auth admission limiter this
	// flow has already spent most of.
	var project row
	decode(run("project", "create", "--org", org, "--name", "billing", "-o", "json"), &project)
	var dev row
	decode(run("env", "create", "--org", org, "--project", project.Id, "--name", "dev", "-o", "json"), &dev)

	scope := []string{"--org", org, "--project", project.Id}
	envScope := append(append([]string{}, scope...), "--env", dev.Id)

	// Two keys, so the publish below is genuinely SELECTIVE: one draft is
	// named and the other is left pending.
	for _, name := range []string{"LOG_LEVEL", "FEATURE_FLAG"} {
		run(append(append([]string{"key", "create", "--name", name}, scope...),
			"--classification", "config", "--declaration", `{"rule":{"type":"string"}}`, "-o", "json")...)
	}

	// THE SECOND CLIENT subscribes BEFORE the publish. `Last-Event-ID` replays
	// nothing, so a subscriber that connects afterwards would legitimately see
	// silence — the ordering is the test, not an implementation detail.
	events := watchAdvisory(t, baseURL, org, project.Id, bearer())

	// EDIT. `values set` stages: the draft lands in the caller's own working
	// state with an immutable version id and the environment keeps delivering
	// what it delivered.
	stage := func(key, value string) string {
		t.Helper()
		io := ios()
		out := &strings.Builder{}
		io.Stdout = out
		io.Stdin = strings.NewReader(value)
		args := append(append([]string{"values", "set", key}, envScope...), "--stdin", "-o", "json")
		if code := cli.Run(t.Context(), io, args); code != cli.ExitOK {
			t.Fatalf("hikyo values set %s exited %d\n%s", key, code, out.String())
		}
		var staged struct {
			VersionId string `json:"version_id"`
		}
		decode(out.String(), &staged)
		if staged.VersionId == "" {
			t.Fatalf("values set returned no version id: %s", out.String())
		}
		return staged.VersionId
	}
	logLevel := stage("LOG_LEVEL", "debug")
	stage("FEATURE_FLAG", "on")

	// The drafts are visible to their owner, with the ids a publish names.
	var pending struct {
		Cells []struct {
			Name             string
			PendingVersionId *string `json:"pending_version_id"`
		}
	}
	decode(run(append([]string{"values", "pending", "-o", "json"}, envScope...)...), &pending)
	staged := map[string]string{}
	for _, cell := range pending.Cells {
		if cell.PendingVersionId != nil {
			staged[cell.Name] = *cell.PendingVersionId
		}
	}
	if len(staged) != 2 {
		t.Fatalf("`values pending` shows %d drafts, want 2: %+v", len(staged), pending.Cells)
	}

	// SELECTIVE PUBLISH: one version id, by name.
	var published struct {
		Published    []string
		Environments []struct {
			Revision    int64
			ChangeToken string `json:"change_token"`
		}
	}
	decode(run(append(append([]string{"values", "publish"}, envScope...),
		"--versions", logLevel, "-o", "json")...), &published)
	if len(published.Published) != 1 || published.Published[0] != logLevel {
		t.Fatalf("selective publish committed %+v, want exactly the named version", published.Published)
	}
	if len(published.Environments) != 1 || published.Environments[0].ChangeToken == "" {
		t.Fatalf("publish returned no environment or no change token: %+v", published.Environments)
	}

	// FETCH THE RESOLVED SNAPSHOT via the CLI. This is what "fetch resolved"
	// actually is (api-cli-surface ADR): it reads a committed snapshot, never
	// live values.
	var exported struct {
		Revision int64
		Items    []struct {
			Name  string
			Value *string
		}
	}
	decode(run(append(append([]string{"values", "export"}, envScope...), "--format", "json")...), &exported)
	if exported.Revision != published.Environments[0].Revision {
		t.Fatalf("export served revision %d, want the one just published (%d)",
			exported.Revision, published.Environments[0].Revision)
	}
	delivered := map[string]string{}
	for _, item := range exported.Items {
		if item.Value != nil {
			delivered[item.Name] = *item.Value
		}
	}
	if delivered["LOG_LEVEL"] != "debug" {
		t.Fatalf("the published draft did not deliver: %+v", delivered)
	}
	// SELECTION ISOLATION on the wire: the unselected draft did not ride along.
	if _, ok := delivered["FEATURE_FLAG"]; ok {
		t.Fatalf("an unselected draft was published: %+v", delivered)
	}

	// THE SECOND CLIENT SAW IT. Metadata only — the event names the
	// environment and the revision, and carries no value and no change token.
	seen := <-events
	if seen.err != nil {
		t.Fatalf("advisory stream: %v", seen.err)
	}
	if seen.event != "revision.published" {
		t.Fatalf("advisory event = %q, want revision.published", seen.event)
	}
	if seen.data["environment_id"] != dev.Id {
		t.Fatalf("advisory names environment %v, want %q", seen.data["environment_id"], dev.Id)
	}
	if _, leaked := seen.data["change_token"]; leaked {
		t.Fatalf("the advisory carried a change token: %+v", seen.data)
	}
	for field := range seen.data {
		if strings.Contains(field, "value") {
			t.Fatalf("the advisory carried a value-shaped field %q: %+v", field, seen.data)
		}
	}

	// The history is lineage, and it is readable without any reveal gate.
	var history struct {
		Items []struct {
			Revision    int64
			ChangedKeys []struct {
				Name   string
				Change string
			} `json:"changed_keys"`
		}
	}
	decode(run(append([]string{"revision", "list", "-o", "json"}, envScope...)...), &history)
	if len(history.Items) == 0 || history.Items[0].Revision != exported.Revision {
		t.Fatalf("revision list does not lead with the published revision: %+v", history.Items)
	}
	changed := history.Items[0].ChangedKeys
	if len(changed) != 1 || changed[0].Name != "LOG_LEVEL" || changed[0].Change != "added" {
		t.Fatalf("lineage for the publish = %+v, want LOG_LEVEL added", changed)
	}
}

type advisorySighting struct {
	event string
	data  map[string]any
	err   error
}

// watchAdvisory opens the SSE stream and returns a channel carrying the first
// `revision.published` event it sees.
//
// It reads the raw stream rather than using a client library because the frame
// shape IS part of the contract: an `event:` line naming the type and a `data:`
// line carrying the metadata-only body.
func watchAdvisory(t *testing.T, baseURL, org, project, bearer string) <-chan advisorySighting {
	t.Helper()
	if bearer == "" {
		t.Fatal("no session artifact captured: the advisory stream has nothing to authenticate with")
	}
	out := make(chan advisorySighting, 1)
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet,
		baseURL+"/api/v1/orgs/"+org+"/projects/"+project+"/events", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		t.Fatalf("advisory stream answered %d", resp.StatusCode)
	}
	if got := resp.Header.Get("Content-Type"); !strings.HasPrefix(got, "text/event-stream") {
		resp.Body.Close()
		t.Fatalf("advisory stream content type = %q", got)
	}
	// Intermediaries buffer streams unless told not to, which turns a stream
	// into a hang. The header is part of the contract.
	if got := resp.Header.Get("X-Accel-Buffering"); got != "no" {
		resp.Body.Close()
		t.Fatalf("advisory stream did not disable proxy buffering: %q", got)
	}
	go func() {
		defer resp.Body.Close()
		scanner := bufio.NewScanner(resp.Body)
		event := ""
		for scanner.Scan() {
			line := scanner.Text()
			switch {
			case strings.HasPrefix(line, "event: "):
				event = strings.TrimPrefix(line, "event: ")
			case strings.HasPrefix(line, "data: "):
				if event != "revision.published" {
					continue
				}
				var data map[string]any
				if err := json.Unmarshal([]byte(strings.TrimPrefix(line, "data: ")), &data); err != nil {
					out <- advisorySighting{err: err}
					return
				}
				out <- advisorySighting{event: event, data: data}
				return
			}
		}
		out <- advisorySighting{err: scanner.Err()}
	}()
	t.Cleanup(func() {
		select {
		case <-out:
		case <-time.After(time.Millisecond):
		}
	})
	return out
}
