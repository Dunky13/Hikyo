package scimproto

import "testing"

var fuzzResources = []Resource{ResourceUser, ResourceGroup}

// FuzzParseFilter checks the SCIM closed filter recognizer returns normally for both resource kinds.
func FuzzParseFilter(f *testing.F) {
	f.Add(`userName eq "alice@example.com"`)
	f.Add(`userName eq "`)
	f.Add("arbitrary")

	f.Fuzz(func(t *testing.T, raw string) {
		for _, resource := range fuzzResources {
			_, _ = ParseFilter(raw, resource)
		}
	})
}

// FuzzParsePatch checks the SCIM atomic PATCH decoder returns normally for both resource kinds.
func FuzzParsePatch(f *testing.F) {
	f.Add([]byte(`{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"externalId","value":"x"}]}`))
	f.Add([]byte(`{"schemas":[`))
	f.Add([]byte{0xff, 0, '{', '}'})

	f.Fuzz(func(t *testing.T, raw []byte) {
		for _, resource := range fuzzResources {
			_, _ = ParsePatch(raw, resource)
		}
	})
}

// FuzzDecodeUser checks the bounded SCIM User decoder returns normally on arbitrary JSON.
func FuzzDecodeUser(f *testing.F) {
	f.Add([]byte(`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"alice@example.com","active":true}`))
	f.Add([]byte(`{"userName":`))
	f.Add([]byte("arbitrary"))

	f.Fuzz(func(t *testing.T, raw []byte) {
		_, _ = DecodeUser(raw)
	})
}

// FuzzDecodeGroup checks the bounded SCIM Group decoder returns normally on arbitrary JSON.
func FuzzDecodeGroup(f *testing.F) {
	f.Add([]byte(`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"operators","members":[]}`))
	f.Add([]byte(`{"displayName":`))
	f.Add([]byte{0, 1, 2})

	f.Fuzz(func(t *testing.T, raw []byte) {
		_, _ = DecodeGroup(raw)
	})
}
