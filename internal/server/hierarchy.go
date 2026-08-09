package server

import (
	"context"
	"net/http"

	"github.com/Dunky13/wenv/api"
	"github.com/Dunky13/wenv/api/apigen"
	"github.com/Dunky13/wenv/internal/domain"
	"github.com/Dunky13/wenv/internal/service"
)

// The hierarchy transport (#48): Project, Environment and Folder handlers,
// plus the organisation rename and delete that complete the org surface.
//
// These handlers return a bare domain error on every refusal instead of
// building one of twenty near-identical per-operation refusal objects. The
// strict server routes that error to writeHandlerError, which is the SAME
// uniform writer every other refusal goes through — so the "fixed message per
// code" rule is enforced in one place rather than restated eighty times, and a
// handler cannot invent a status the sentinels are built to hide. The contract
// still decides which statuses exist per operation; the contract tests
// validate the actual wire response against it.
//
// Every method hands the service a raw artifact (service.Bearer) and never a
// resolved principal: identity is resolved inside the transaction that
// authorizes the operation, or the decision about who the caller is would sit
// on the far side of a transaction boundary from the authorization trusting it.

// ProjectService, EnvironmentService and FolderService are the domain surfaces
// this transport exposes. Scopes are addressed as domain.Scope — the same shape
// authorize() takes — so a wrong-depth address is refused at the chokepoint
// rather than silently widened here.
type ProjectService interface {
	Create(ctx context.Context, actor service.Actor, org domain.OrgID, name string) (service.Project, error)
	Get(ctx context.Context, actor service.Actor, scope domain.Scope) (service.Project, error)
	List(ctx context.Context, actor service.Actor, org domain.OrgID) ([]service.Project, error)
	Rename(ctx context.Context, actor service.Actor, scope domain.Scope, name string) (service.Project, error)
	Delete(ctx context.Context, actor service.Actor, scope domain.Scope) error
}

type EnvironmentService interface {
	Create(ctx context.Context, actor service.Actor, scope domain.Scope, name string) (service.Environment, error)
	Get(ctx context.Context, actor service.Actor, scope domain.Scope) (service.Environment, error)
	List(ctx context.Context, actor service.Actor, scope domain.Scope) ([]service.Environment, error)
	Rename(ctx context.Context, actor service.Actor, scope domain.Scope, name string) (service.Environment, error)
	Reorder(ctx context.Context, actor service.Actor, scope domain.Scope, ordered []string) ([]service.Environment, error)
	Delete(ctx context.Context, actor service.Actor, scope domain.Scope) error
}

type FolderService interface {
	Create(ctx context.Context, actor service.Actor, scope domain.Scope, path string) (service.Folder, error)
	Get(ctx context.Context, actor service.Actor, scope domain.Scope, id string) (service.Folder, error)
	List(ctx context.Context, actor service.Actor, scope domain.Scope) ([]service.Folder, error)
	Rename(ctx context.Context, actor service.Actor, scope domain.Scope, id, path string) (service.Folder, error)
	Delete(ctx context.Context, actor service.Actor, scope domain.Scope, id string) error
}

// writeRequestError renders the strict server's request-decode leg. A body the
// generated decoder cannot read is a shape failure, decided before any tenant
// resolution — the one class permitted to name the offending member, and here
// there is nothing finer to name than the body itself.
func (a *API) writeRequestError(w http.ResponseWriter, _ *http.Request, _ error) {
	writeError(w, apigen.ErrorCodeBadRequest, "body")
}

// writeHandlerError renders a refusal a handler returned as an error. The cause
// is logged only where it is a fault: a 404 or a 409 is the system working.
//
// The log names the CONTRACT OPERATION rather than a hand-written label. Every
// handler that returned a bare error used to carry its own string ("local
// login", "list orgs"), which is a second name for the operation that can drift
// from the first; the contract already has the authoritative one.
func (a *API) writeHandlerError(w http.ResponseWriter, r *http.Request, err error) {
	code := classify(err)
	if code == apigen.ErrorCodeInternal {
		operation, ok := api.OperationIDFor(r)
		if !ok {
			operation = "unrouted request"
		}
		a.fault(r.Context(), operation, err)
	}
	writeError(w, code, "")
}

// ---------------------------------------------------------------------------
// Organisation — the by-id mutations
// ---------------------------------------------------------------------------

func (a *API) RenameOrg(ctx context.Context, req apigen.RenameOrgRequestObject) (apigen.RenameOrgResponseObject, error) {
	org, err := a.Orgs.Rename(ctx, service.Bearer(bearer(ctx)), domain.OrgID(req.Org), req.Body.Name)
	if err != nil {
		return nil, err
	}
	return apigen.RenameOrg200JSONResponse(wireOrg(org)), nil
}

func (a *API) DeleteOrg(ctx context.Context, req apigen.DeleteOrgRequestObject) (apigen.DeleteOrgResponseObject, error) {
	if err := a.Orgs.Delete(ctx, service.Bearer(bearer(ctx)), domain.OrgID(req.Org)); err != nil {
		return nil, err
	}
	return apigen.DeleteOrg204Response{}, nil
}

// ---------------------------------------------------------------------------
// Project
// ---------------------------------------------------------------------------

func (a *API) ListProjects(ctx context.Context, req apigen.ListProjectsRequestObject) (apigen.ListProjectsResponseObject, error) {
	projects, err := a.Projects.List(ctx, service.Bearer(bearer(ctx)), domain.OrgID(req.Org))
	if err != nil {
		return nil, err
	}
	items := make([]apigen.Project, 0, len(projects))
	for _, p := range projects {
		items = append(items, wireProject(p))
	}
	return apigen.ListProjects200JSONResponse{Items: items, Count: len(items)}, nil
}

func (a *API) CreateProject(ctx context.Context, req apigen.CreateProjectRequestObject) (apigen.CreateProjectResponseObject, error) {
	project, err := a.Projects.Create(ctx, service.Bearer(bearer(ctx)), domain.OrgID(req.Org), req.Body.Name)
	if err != nil {
		return nil, err
	}
	return apigen.CreateProject201JSONResponse(wireProject(project)), nil
}

func (a *API) GetProject(ctx context.Context, req apigen.GetProjectRequestObject) (apigen.GetProjectResponseObject, error) {
	project, err := a.Projects.Get(ctx, service.Bearer(bearer(ctx)), projectScope(req.Org, req.Project))
	if err != nil {
		return nil, err
	}
	return apigen.GetProject200JSONResponse(wireProject(project)), nil
}

func (a *API) RenameProject(ctx context.Context, req apigen.RenameProjectRequestObject) (apigen.RenameProjectResponseObject, error) {
	project, err := a.Projects.Rename(ctx, service.Bearer(bearer(ctx)), projectScope(req.Org, req.Project), req.Body.Name)
	if err != nil {
		return nil, err
	}
	return apigen.RenameProject200JSONResponse(wireProject(project)), nil
}

func (a *API) DeleteProject(ctx context.Context, req apigen.DeleteProjectRequestObject) (apigen.DeleteProjectResponseObject, error) {
	if err := a.Projects.Delete(ctx, service.Bearer(bearer(ctx)), projectScope(req.Org, req.Project)); err != nil {
		return nil, err
	}
	return apigen.DeleteProject204Response{}, nil
}

// ---------------------------------------------------------------------------
// Environment
// ---------------------------------------------------------------------------

func (a *API) ListEnvironments(ctx context.Context, req apigen.ListEnvironmentsRequestObject) (apigen.ListEnvironmentsResponseObject, error) {
	envs, err := a.Environments.List(ctx, service.Bearer(bearer(ctx)), projectScope(req.Org, req.Project))
	if err != nil {
		return nil, err
	}
	return apigen.ListEnvironments200JSONResponse(wireEnvironmentList(envs)), nil
}

func (a *API) CreateEnvironment(ctx context.Context, req apigen.CreateEnvironmentRequestObject) (apigen.CreateEnvironmentResponseObject, error) {
	env, err := a.Environments.Create(ctx, service.Bearer(bearer(ctx)), projectScope(req.Org, req.Project), req.Body.Name)
	if err != nil {
		return nil, err
	}
	return apigen.CreateEnvironment201JSONResponse(wireEnvironment(env)), nil
}

func (a *API) ReorderEnvironments(ctx context.Context, req apigen.ReorderEnvironmentsRequestObject) (apigen.ReorderEnvironmentsResponseObject, error) {
	envs, err := a.Environments.Reorder(ctx, service.Bearer(bearer(ctx)),
		projectScope(req.Org, req.Project), req.Body.EnvironmentIds)
	if err != nil {
		return nil, err
	}
	return apigen.ReorderEnvironments200JSONResponse(wireEnvironmentList(envs)), nil
}

func (a *API) GetEnvironment(ctx context.Context, req apigen.GetEnvironmentRequestObject) (apigen.GetEnvironmentResponseObject, error) {
	env, err := a.Environments.Get(ctx, service.Bearer(bearer(ctx)), envScope(req.Org, req.Project, req.Environment))
	if err != nil {
		return nil, err
	}
	return apigen.GetEnvironment200JSONResponse(wireEnvironment(env)), nil
}

func (a *API) RenameEnvironment(ctx context.Context, req apigen.RenameEnvironmentRequestObject) (apigen.RenameEnvironmentResponseObject, error) {
	env, err := a.Environments.Rename(ctx, service.Bearer(bearer(ctx)),
		envScope(req.Org, req.Project, req.Environment), req.Body.Name)
	if err != nil {
		return nil, err
	}
	return apigen.RenameEnvironment200JSONResponse(wireEnvironment(env)), nil
}

func (a *API) DeleteEnvironment(ctx context.Context, req apigen.DeleteEnvironmentRequestObject) (apigen.DeleteEnvironmentResponseObject, error) {
	err := a.Environments.Delete(ctx, service.Bearer(bearer(ctx)), envScope(req.Org, req.Project, req.Environment))
	if err != nil {
		return nil, err
	}
	return apigen.DeleteEnvironment204Response{}, nil
}

// ---------------------------------------------------------------------------
// Folder
// ---------------------------------------------------------------------------

func (a *API) ListFolders(ctx context.Context, req apigen.ListFoldersRequestObject) (apigen.ListFoldersResponseObject, error) {
	folders, err := a.Folders.List(ctx, service.Bearer(bearer(ctx)), projectScope(req.Org, req.Project))
	if err != nil {
		return nil, err
	}
	items := make([]apigen.Folder, 0, len(folders))
	for _, f := range folders {
		items = append(items, wireFolder(f))
	}
	return apigen.ListFolders200JSONResponse{Items: items, Count: len(items)}, nil
}

func (a *API) CreateFolder(ctx context.Context, req apigen.CreateFolderRequestObject) (apigen.CreateFolderResponseObject, error) {
	folder, err := a.Folders.Create(ctx, service.Bearer(bearer(ctx)), projectScope(req.Org, req.Project), req.Body.Path)
	if err != nil {
		return nil, err
	}
	return apigen.CreateFolder201JSONResponse(wireFolder(folder)), nil
}

func (a *API) GetFolder(ctx context.Context, req apigen.GetFolderRequestObject) (apigen.GetFolderResponseObject, error) {
	folder, err := a.Folders.Get(ctx, service.Bearer(bearer(ctx)), projectScope(req.Org, req.Project), req.Folder)
	if err != nil {
		return nil, err
	}
	return apigen.GetFolder200JSONResponse(wireFolder(folder)), nil
}

func (a *API) RenameFolder(ctx context.Context, req apigen.RenameFolderRequestObject) (apigen.RenameFolderResponseObject, error) {
	folder, err := a.Folders.Rename(ctx, service.Bearer(bearer(ctx)),
		projectScope(req.Org, req.Project), req.Folder, req.Body.Path)
	if err != nil {
		return nil, err
	}
	return apigen.RenameFolder200JSONResponse(wireFolder(folder)), nil
}

func (a *API) DeleteFolder(ctx context.Context, req apigen.DeleteFolderRequestObject) (apigen.DeleteFolderResponseObject, error) {
	err := a.Folders.Delete(ctx, service.Bearer(bearer(ctx)), projectScope(req.Org, req.Project), req.Folder)
	if err != nil {
		return nil, err
	}
	return apigen.DeleteFolder204Response{}, nil
}
