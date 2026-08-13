package oidctest

import (
	"encoding/json"
	"fmt"
	"time"
)

// The three issuer SHAPES federation must be exercised against (#62,
// machine-identities ADR § Federation: "one mechanism covers Kubernetes
// projected ServiceAccount tokens, Forgejo Actions and GitHub Actions").
//
// They are real shapes, not placeholders, and that is the point of having three:
// the subject grammar, the claim vocabulary and the DEFAULT AUDIENCE differ per
// platform, and every one of those differences is a rule the binding has to
// carry. A single synthetic shape would have made the CI `event_name` rule and
// the default-audience refusal look like arbitrary policy rather than the
// specific defences they are.
//
// Each shape provides two halves that must agree: the claims a token carries,
// and the claims a correct binding pins. A fixture that built only the first
// would let a binding pin claims no issuer emits and still pass.

// Shape is one issuer's token vocabulary.
type Shape struct {
	// Subject is the `sub` the platform mints, byte-exact.
	Subject string
	// Claims are the platform-specific claims beyond the registered ones.
	Claims map[string]any
	// Pinned is the required-claim set a correct binding names for this shape.
	Pinned map[string]any
	// DefaultAudience is the audience the platform uses when nobody asks for
	// one. A binding may never name it, and a token carrying it is refused.
	DefaultAudience string
}

// RequiredClaimsJSON renders the pinned set as the binding's stored document.
func (s Shape) RequiredClaimsJSON() (string, error) {
	raw, err := json.Marshal(s.Pinned)
	if err != nil {
		return "", fmt.Errorf("oidctest: encode pinned claims: %w", err)
	}
	return string(raw), nil
}

// KubernetesShape is a projected ServiceAccount token, in the claim shape a real
// cluster actually mints.
//
// The subject grammar is `system:serviceaccount:<namespace>:<name>`, and it is
// the whole reason the ADR forbids pattern bindings: a rule such as "any
// ServiceAccount in namespace prod" hands a Hikyo principal to anyone holding
// `create serviceaccount` in that namespace — a far wider group than
// cluster-admin.
//
// EVERYTHING PLATFORM-SPECIFIC IS NESTED under the single literal top-level claim
// `kubernetes.io`, and this fixture mints exactly that. An earlier version
// invented flattened scalars (`kubernetes.io/serviceaccount/uid` as a top-level
// key) that Kubernetes never emits — which made the tests pass against a token
// shape no cluster produces, and left the real UID unpinnable. The pins are
// therefore JSON Pointers into the nested document.
//
// The UID is what the ADR's immutable-identifier rule means here: a UID is
// immutable per object, so a ServiceAccount deleted and recreated with the same
// name has a different one. Pinning the name alone would let the replacement
// inherit the binding.
//
// DefaultAudience is the API server's, and it is operator-supplied in reality —
// whatever that cluster was configured with — which is why the issuer
// configuration carries the refused list rather than deriving it.
func KubernetesShape(namespace, name, serviceAccountUID, apiServerAudience string) Shape {
	subject := fmt.Sprintf("system:serviceaccount:%s:%s", namespace, name)
	return Shape{
		Subject: subject,
		Claims: map[string]any{
			"sub": subject,
			// The real document: a `pod` and a `serviceaccount` object, each with
			// a name and a uid, beside a `namespace` string. Reproduced rather
			// than simplified, because the pointer resolution under test has to
			// walk it.
			"kubernetes.io": map[string]any{
				"namespace": namespace,
				"pod": map[string]any{
					"name": name + "-7d4f9",
					"uid":  "pod-" + serviceAccountUID,
				},
				"serviceaccount": map[string]any{
					"name": name,
					"uid":  serviceAccountUID,
				},
			},
		},
		Pinned: map[string]any{
			"/kubernetes.io/serviceaccount/uid": serviceAccountUID,
			"/kubernetes.io/namespace":          namespace,
		},
		DefaultAudience: apiServerAudience,
	}
}

// ForgejoShape is a Forgejo Actions token.
//
// The subject is `repo:<repository>:ref:<ref>` for every event EXCEPT an exact
// `pull_request` trigger, which alone carries `repo:<repository>:pull_request`.
// So `pull_request_target` carries the ORDINARY ref-form subject — the default
// branch's subject, the one a production binding names — and Forgejo documents
// that a `pull_request_target` workflow with `enable-openid-connect` touching
// untrusted pull-request content may leak the ID-token request credentials. A
// crafted pull request against such a workflow therefore yields a token bearing
// the bound production subject. The protection is the pinned `event_name`.
//
// DefaultAudience is `<instance>/<owner>`, shared across every repository that
// owner has, so accepting it makes any workflow in any of their repositories
// satisfy the binding.
func ForgejoShape(instance, repository, ref, event string) Shape {
	owner, _ := splitRepo(repository)
	subject := fmt.Sprintf("repo:%s:ref:%s", repository, ref)
	if event == "pull_request" {
		subject = fmt.Sprintf("repo:%s:pull_request", repository)
	}
	return Shape{
		Subject: subject,
		Claims: map[string]any{
			"sub":              subject,
			"repository":       repository,
			"repository_owner": owner,
			"ref":              ref,
			"event_name":       event,
			"workflow_ref":     fmt.Sprintf("%s/.forgejo/workflows/deploy.yaml@%s", repository, ref),
		},
		// `workflow_ref` is pinned alongside `event_name`, which the ADR
		// recommends: without it one compromised workflow in a repository speaks
		// for every workflow in it.
		Pinned: map[string]any{
			"repository":   repository,
			"event_name":   event,
			"workflow_ref": fmt.Sprintf("%s/.forgejo/workflows/deploy.yaml@%s", repository, ref),
		},
		DefaultAudience: fmt.Sprintf("%s/%s", instance, owner),
	}
}

// GitHubActionsShape is a GitHub Actions token.
//
// It is the one platform that exposes IMMUTABLE NUMERIC identifiers for the
// repository and its owner, so the binding pins `repository_id` and
// `repository_owner_id` rather than the names: a rename or transfer would
// otherwise silently re-point a production binding at whatever now occupies the
// old path. Both are pinned as JSON NUMBERS, and the validator never folds a
// number to a string — `123` and `"123"` are different claim values.
//
// GitHub requires an explicit audience per request, so there is no shared
// default in the Forgejo sense; the refused audience here is the repository
// owner's URL, which older tooling used as a de-facto default.
func GitHubActionsShape(repository string, repositoryID, ownerID int64, ref, event string) Shape {
	owner, _ := splitRepo(repository)
	subject := fmt.Sprintf("repo:%s:ref:%s", repository, ref)
	if event == "pull_request" {
		subject = fmt.Sprintf("repo:%s:pull_request", repository)
	}
	workflowRef := fmt.Sprintf("%s/.github/workflows/deploy.yml@%s", repository, ref)
	return Shape{
		Subject: subject,
		Claims: map[string]any{
			"sub":                 subject,
			"repository":          repository,
			"repository_id":       repositoryID,
			"repository_owner":    owner,
			"repository_owner_id": ownerID,
			"ref":                 ref,
			"event_name":          event,
			"workflow_ref":        workflowRef,
			"runner_environment":  "github-hosted",
		},
		Pinned: map[string]any{
			"repository_id":       repositoryID,
			"repository_owner_id": ownerID,
			"event_name":          event,
			"workflow_ref":        workflowRef,
		},
		DefaultAudience: fmt.Sprintf("https://github.com/%s", owner),
	}
}

func splitRepo(repository string) (owner, name string) {
	for i := range repository {
		if repository[i] == '/' {
			return repository[:i], repository[i+1:]
		}
	}
	return repository, ""
}

// MintShape signs a token carrying the shape's claims plus the registered ones,
// for the given audience and instant.
//
// `audience` is `any` because `aud` legitimately is: a single string or an array.
// It is a caller argument rather than part of the shape because the whole
// audience-binding rule turns on which audience a token was minted for — the same
// workload identity asking for Hikyo's audience, asking for the platform default,
// and asking for both at once must produce three different tokens, and only one
// of them authenticates.
func (p *IdP) MintShape(s Shape, audience any, issuedAt time.Time, lifetime time.Duration) (string, error) {
	claims := map[string]any{
		"iss": p.Issuer(),
		"aud": audience,
		"iat": issuedAt.Unix(),
		"nbf": issuedAt.Unix(),
		"exp": issuedAt.Add(lifetime).Unix(),
	}
	for k, v := range s.Claims {
		claims[k] = v
	}
	return p.MintIDToken(claims)
}

// JWKSDocument returns the fixture's current JWKS as the static-mode
// configuration would carry it, so the air-gap alternative is exercised against
// the same keys the discovery path serves.
func (p *IdP) JWKSDocument() (string, error) {
	p.mu.Lock()
	keys := []map[string]any{jwkOf(&p.key.PublicKey, p.keyID)}
	if p.PublishRetired {
		for _, r := range p.retired {
			keys = append(keys, jwkOf(&r.key.PublicKey, r.keyID))
		}
	}
	p.mu.Unlock()
	raw, err := json.Marshal(map[string]any{"keys": keys})
	if err != nil {
		return "", fmt.Errorf("oidctest: encode jwks: %w", err)
	}
	return string(raw), nil
}
