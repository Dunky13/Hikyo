package importer

import (
	"errors"
	"testing"
)

func fuzzArtifactSeed(f *testing.F, value any) []byte {
	f.Helper()
	raw, err := Encode(value)
	if err != nil {
		f.Fatal(err)
	}
	return raw
}

func requireImporterError(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		return
	}
	var importerErr *Error
	if !errors.As(err, &importerErr) {
		t.Fatalf("parser error type = %T, want *importer.Error", err)
	}
}

// FuzzParseTemplate checks the import-paths mapping decoder returns a template or the package's own error type.
func FuzzParseTemplate(f *testing.F) {
	valid := fuzzArtifactSeed(f, Template{
		FormatVersion: FormatVersion, ConnectorContractVersion: ConnectorContractVersion,
		Source: "k8s", Project: "project", Environments: []EnvironmentMapping{{Target: "production"}},
	})
	f.Add(valid)
	f.Add(valid[:len(valid)/2])
	f.Add([]byte("arbitrary"))

	f.Fuzz(func(t *testing.T, raw []byte) {
		_, err := ParseTemplate(raw)
		requireImporterError(t, err)
	})
}

// FuzzParseManifest checks the import-paths manifest decoder returns a manifest or the package's own error type.
func FuzzParseManifest(f *testing.F) {
	valid := fuzzArtifactSeed(f, Manifest{
		FormatVersion: FormatVersion, ConnectorContractVersion: ConnectorContractVersion,
		Target: Target{Project: "project", Environments: []string{"production"}},
	})
	f.Add(valid)
	f.Add(valid[:len(valid)/2])
	f.Add([]byte{0xff, 0, '{', '}'})

	f.Fuzz(func(t *testing.T, raw []byte) {
		_, err := ParseManifest(raw)
		requireImporterError(t, err)
	})
}

// FuzzParseValuesFile checks the import-paths values decoder returns a values file or the package's own error type.
func FuzzParseValuesFile(f *testing.F) {
	valid := fuzzArtifactSeed(f, ValuesFile{
		FormatVersion: FormatVersion, Project: "project", Environment: "production",
		Entries: []ValuesEntry{{Key: "API_TOKEN", Value: "secret"}},
	})
	f.Add(valid)
	f.Add(valid[:len(valid)/2])
	f.Add([]byte(`{"format_version":1}`))

	f.Fuzz(func(t *testing.T, raw []byte) {
		_, err := ParseValuesFile(raw)
		requireImporterError(t, err)
	})
}
