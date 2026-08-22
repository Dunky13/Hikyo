package crypto

import (
	"bytes"
	"testing"
)

func TestScopedTokenFamiliesPreserveGoldenVectorsAndScopeSeparation(t *testing.T) {
	t.Parallel()

	// Fixed root, scope and payload make these known-answer vectors protocol
	// sentinels: changing a label or field encoding changes the literal output.
	newKeyring := func() *Keyring {
		return &Keyring{token: keyHandle{key: bytes.Repeat([]byte{0x42}, KeySize)}}
	}
	type tokenFn func(*Keyring, string, string, string, []byte) (string, error)
	tests := []struct {
		name string
		tag  tokenFn
		want string
	}{
		{name: "change token", tag: (*Keyring).ChangeToken, want: "v1:poH7aqEWVkpCymIJegWYLoe2hA7Bip7csZ01BkgMyDA"},
		{name: "delivery cursor", tag: (*Keyring).DeliveryCursor, want: "v1:4_dpQeRHtYsAhf1FiIZWqjKtXvRyY90a90MD8SNuJGE"},
		{name: "occurrence token", tag: (*Keyring).OccurrenceToken, want: "v1:AMuqmqeGm-zZv8roG7AuxyQyQjcDPr2mswE482p7KtY"},
		{name: "publish preview", tag: (*Keyring).PublishPreviewToken, want: "v1:wt3UZgkb_Ep1Ehs_GLEZt0PThYFi1Xfk--sft1gdfoI"},
	}
	seen := make(map[string]string, len(tests))

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kr := newKeyring()
			got, err := tt.tag(kr, "org_1", "project_1", "production", []byte("canonical payload"))
			if err != nil {
				t.Fatal(err)
			}
			if got != tt.want {
				t.Errorf("golden token = %q, want %q", got, tt.want)
			}
			if otherPurpose, ok := seen[got]; ok {
				t.Errorf("same scope and payload matched %s token", otherPurpose)
			}
			seen[got] = tt.name

			otherScope, err := tt.tag(kr, "org_2", "project_1", "production", []byte("canonical payload"))
			if err != nil {
				t.Fatal(err)
			}
			if otherScope == got {
				t.Error("different organizations produced the same token")
			}

			left, err := tt.tag(kr, "a", "bc", "production", []byte("canonical payload"))
			if err != nil {
				t.Fatal(err)
			}
			right, err := tt.tag(kr, "ab", "c", "production", []byte("canonical payload"))
			if err != nil {
				t.Fatal(err)
			}
			if left == right {
				t.Error("boundary-shifted scopes produced the same token")
			}
		})
	}
}
