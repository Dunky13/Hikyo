package samlsp

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/beevik/etree"
	xrv "github.com/mattermost/xml-roundtrip-validator"
)

const (
	MaxDocumentBytes = 256 << 10
	MaxElementDepth  = 32
	MaxXMLTokens     = 50_000
)

var (
	ErrDocumentTooLarge = errors.New("samlsp: XML document exceeds 256 KiB")
	ErrDocumentTooDeep  = errors.New("samlsp: XML element depth exceeds 32")
	ErrTooManyTokens    = errors.New("samlsp: XML token count exceeds 50000")
	ErrDTD              = errors.New("samlsp: DTD declarations are forbidden")
	ErrMalformedXML     = errors.New("samlsp: malformed XML document")
	ErrRoundTrip        = errors.New("samlsp: XML round-trip validation failed")
	ErrDuplicateID      = errors.New("samlsp: duplicate XML ID")
	ErrEmptyID          = errors.New("samlsp: empty XML ID")
)

// Document is one bounded XML parse tree. Policy validation and extraction
// consume this tree so callers never need a second, potentially divergent,
// parse of attacker-controlled bytes.
type Document struct {
	tree *etree.Document
}

// ParseXML applies the ADR's resource bounds and DTD/ID refusals while
// constructing the one tree used by every later policy check.
func ParseXML(raw []byte) (*Document, error) {
	if len(raw) > MaxDocumentBytes {
		return nil, ErrDocumentTooLarge
	}

	decoder := xml.NewDecoder(bytes.NewReader(raw))
	// RawToken is used only for bounds and refusals. The round-trip validator
	// must see namespace-instability payloads before a stricter parser masks
	// their distinct cause.
	decoder.Strict = false
	ids := make(map[string]struct{})
	tokens := 0
	depth := 0
	roots := 0

	for {
		token, err := decoder.RawToken()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrMalformedXML, err)
		}
		tokens++
		if tokens > MaxXMLTokens {
			return nil, ErrTooManyTokens
		}

		switch typed := token.(type) {
		case xml.Directive:
			return nil, ErrDTD
		case xml.StartElement:
			depth++
			if depth > MaxElementDepth {
				return nil, ErrDocumentTooDeep
			}
			if depth == 1 {
				roots++
			}
			for _, attr := range typed.Attr {
				if attr.Name.Local != "ID" {
					continue
				}
				if attr.Value == "" {
					return nil, ErrEmptyID
				}
				if _, exists := ids[attr.Value]; exists {
					return nil, fmt.Errorf("%w: %q", ErrDuplicateID, attr.Value)
				}
				ids[attr.Value] = struct{}{}
			}
		case xml.EndElement:
			if depth == 0 {
				return nil, fmt.Errorf("%w: unexpected closing element", ErrMalformedXML)
			}
			depth--
		case xml.CharData:
			if depth == 0 {
				if strings.TrimSpace(string(typed)) != "" {
					return nil, fmt.Errorf("%w: character data outside root", ErrMalformedXML)
				}
			}
		}
	}
	if roots != 1 || depth != 0 {
		return nil, ErrMalformedXML
	}
	if err := xrv.Validate(bytes.NewReader(raw)); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrRoundTrip, err)
	}
	tree := etree.NewDocument()
	tree.ReadSettings.MaxDepth = MaxElementDepth
	tree.ReadSettings.PreserveDuplicateAttrs = true
	if err := tree.ReadFromBytes(raw); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformedXML, err)
	}
	return &Document{tree: tree}, nil
}
