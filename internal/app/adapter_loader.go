package app

import (
	"context"
	"errors"
	"sync"

	"github.com/Hikyo-Org/hikyo/internal/adapter"
	"github.com/Hikyo-Org/hikyo/internal/crypto"
	"github.com/Hikyo-Org/hikyo/internal/store"
)

type adapterLoader struct {
	runtime        *store.AdapterRuntime
	keyring        *crypto.Keyring
	moduleFactory  adapter.ModuleFactory
	loadExecution  func(context.Context, adapter.Job) (store.AdapterExecution, error)
	loadActivation func(context.Context, adapter.Job) (store.AdapterActivation, error)
	openField      func(crypto.ProjectFieldAAD, []byte) ([]byte, error)
}

func (l *adapterLoader) LoadActivation(ctx context.Context, job adapter.Job, journal adapter.Journal) (adapter.LoadedActivation, error) {
	if l == nil || (l.runtime == nil && l.loadActivation == nil) || (l.keyring == nil && l.openField == nil) || l.moduleFactory == nil {
		return adapter.LoadedActivation{}, errors.New("adapter activation loader is not configured")
	}
	if journal == nil {
		return adapter.LoadedActivation{}, errors.New("adapter activation loader requires the leased job journal")
	}
	if err := journal.Gate(ctx, adapter.Effect{Surface: adapter.Secret, EffectiveName: "route", Disposition: adapter.Update}); err != nil {
		return adapter.LoadedActivation{}, err
	}
	loadActivation := l.loadActivation
	if loadActivation == nil {
		loadActivation = l.runtime.LoadActivation
	}
	material, err := loadActivation(ctx, job)
	if err != nil {
		return adapter.LoadedActivation{}, err
	}
	provider, err := adapter.ParseProvider(material.Provider)
	if err != nil {
		return adapter.LoadedActivation{}, err
	}
	openField := l.openField
	if openField == nil {
		sealer, err := l.keyring.ForProject(ctx, job.OrgID, job.ProjectID)
		if err != nil {
			return adapter.LoadedActivation{}, err
		}
		openField = sealer.OpenField
	}
	if err := journal.Gate(ctx, adapter.Effect{Surface: adapter.Secret, EffectiveName: "credential", Disposition: adapter.Update}); err != nil {
		return adapter.LoadedActivation{}, err
	}
	credential, err := openField(crypto.ProjectFieldAAD{
		OrgID: job.OrgID, ProjectID: job.ProjectID,
		OwnerTable: "adapters", OwnerRowID: material.CredentialOwnerID, FieldTag: "credential",
	}, material.CredentialCiphertext)
	if err != nil {
		return adapter.LoadedActivation{}, err
	}
	lease, err := l.moduleFactory(provider, adapter.Config{Origin: material.Origin}, string(credential))
	if err != nil {
		crypto.Zero(credential)
		return adapter.LoadedActivation{}, err
	}
	release := sync.OnceFunc(func() {
		crypto.Zero(credential)
		lease.Release()
	})
	return adapter.LoadedActivation{
		Module: lease.Module,
		Request: adapter.ConnectionRequest{
			Config:      adapter.Config{Origin: material.Origin},
			Destination: material.Target.Destination, Access: adapter.Access{Credential: string(credential)},
			Gate: func(gateCtx context.Context) error {
				return journal.Gate(gateCtx, adapter.Effect{Surface: adapter.Secret, EffectiveName: "route", Disposition: adapter.Update})
			},
		},
		Release: release,
	}, nil
}

func (l *adapterLoader) Load(ctx context.Context, job adapter.Job, journal adapter.Journal) (adapter.LoadedSync, error) {
	if l == nil || (l.runtime == nil && l.loadExecution == nil) || (l.keyring == nil && l.openField == nil) || l.moduleFactory == nil {
		return adapter.LoadedSync{}, errors.New("adapter loader is not configured")
	}
	if journal == nil {
		return adapter.LoadedSync{}, errors.New("adapter loader requires the leased job journal")
	}
	if err := journal.Gate(ctx, adapter.Effect{Surface: adapter.Secret, EffectiveName: "manifest", Disposition: adapter.Update}); err != nil {
		return adapter.LoadedSync{}, err
	}
	loadExecution := l.loadExecution
	if loadExecution == nil {
		loadExecution = l.runtime.LoadExecution
	}
	material, err := loadExecution(ctx, job)
	if err != nil {
		return adapter.LoadedSync{}, err
	}
	provider, err := adapter.ParseProvider(material.Provider)
	if err != nil {
		return adapter.LoadedSync{}, err
	}
	openField := l.openField
	if openField == nil {
		sealer, err := l.keyring.ForProject(ctx, job.OrgID, job.ProjectID)
		if err != nil {
			return adapter.LoadedSync{}, err
		}
		openField = sealer.OpenField
	}
	if err := journal.Gate(ctx, adapter.Effect{Surface: adapter.Secret, EffectiveName: "credential", Disposition: adapter.Update}); err != nil {
		return adapter.LoadedSync{}, err
	}
	if len(material.CredentialCiphertext) == 0 {
		return adapter.LoadedSync{}, adapter.ErrProviderAuth
	}
	credential, err := openField(crypto.ProjectFieldAAD{
		OrgID: job.OrgID, ProjectID: job.ProjectID,
		OwnerTable: "adapters", OwnerRowID: material.CredentialOwnerID, FieldTag: "credential",
	}, material.CredentialCiphertext)
	if err != nil {
		return adapter.LoadedSync{}, err
	}
	lease, err := l.moduleFactory(provider, adapter.Config{Origin: material.Origin}, string(credential))
	if err != nil {
		crypto.Zero(credential)
		return adapter.LoadedSync{}, err
	}
	manifest := make([]adapter.ManifestEntry, 0, len(material.Entries))
	opened := make([][]byte, 0, len(material.Entries))
	for _, row := range material.Entries {
		surface := adapter.Secret
		if adapter.Classification(row.Classification) == adapter.ConfigClassification {
			surface = adapter.Variable
		}
		if err := journal.Gate(ctx, adapter.Effect{Surface: surface, EffectiveName: material.Target.NamePrefix + row.KeyName, Disposition: adapter.Update, KeyID: row.KeyID}); err != nil {
			for _, value := range opened {
				crypto.Zero(value)
			}
			crypto.Zero(credential)
			lease.Release()
			return adapter.LoadedSync{}, err
		}
		plain, err := openField(crypto.ProjectFieldAAD{
			OrgID: job.OrgID, ProjectID: job.ProjectID,
			OwnerTable: "snapshot_entries", OwnerRowID: row.ID, FieldTag: "snapshot_value",
			EnvironmentID: job.EnvironmentID, KeyID: row.KeyID, SnapshotID: row.SnapshotID,
		}, row.Ciphertext)
		if err != nil {
			for _, value := range opened {
				crypto.Zero(value)
			}
			crypto.Zero(credential)
			lease.Release()
			return adapter.LoadedSync{}, err
		}
		opened = append(opened, plain)
		manifest = append(manifest, adapter.ManifestEntry{
			KeyID: row.KeyID, CanonicalName: row.KeyName,
			Classification: adapter.Classification(row.Classification), Value: string(plain),
		})
	}
	request := adapter.SyncRequest{
		Config: adapter.Config{Origin: material.Origin}, Target: material.Target,
		Manifest: manifest, Ledger: material.Ledger,
	}
	release := sync.OnceFunc(func() {
		for i := range manifest {
			manifest[i].Value = ""
		}
		for _, value := range opened {
			crypto.Zero(value)
		}
		crypto.Zero(credential)
		lease.Release()
	})
	return adapter.LoadedSync{
		Module: lease.Module, Request: request, Revision: material.Revision,
		Release: release,
	}, nil
}
