package samlsp

import (
	"errors"
	"strings"
	"testing"
)

func TestParseXMLRefusesPreparseThreats(t *testing.T) {
	t.Parallel()

	deep := strings.Repeat("<x>", MaxElementDepth+1) + strings.Repeat("</x>", MaxElementDepth+1)
	manyTokens := "<x>" + strings.Repeat("<?x?>", MaxXMLTokens) + "</x>"
	tests := []struct {
		name string
		xml  []byte
		want error
	}{
		{name: "oversize", xml: make([]byte, MaxDocumentBytes+1), want: ErrDocumentTooLarge},
		{name: "DTD", xml: []byte(`<!DOCTYPE x [<!ENTITY y "boom">]><x>&y;</x>`), want: ErrDTD},
		{name: "malformed namespace", xml: []byte(`<x::Root/>`), want: ErrMalformedXML},
		{name: "depth", xml: []byte(deep), want: ErrDocumentTooDeep},
		{name: "token count", xml: []byte(manyTokens), want: ErrTooManyTokens},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := ParseXML(tt.xml)
			if !errors.Is(err, tt.want) {
				t.Fatalf("ParseXML() error = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestParseXMLAllowsDocumentAtDepthLimit(t *testing.T) {
	t.Parallel()

	xml := strings.Repeat("<x>", MaxElementDepth) + strings.Repeat("</x>", MaxElementDepth)
	if _, err := ParseXML([]byte(xml)); err != nil {
		t.Fatalf("ParseXML() error = %v", err)
	}
}
