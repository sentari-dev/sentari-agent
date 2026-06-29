package npm

import "encoding/json"

// mustMarshal is a test-only helper that JSON-encodes v and
// panics on failure.  Only ever called with map/struct fixtures
// we control — panicking is appropriate because a failure here
// means the test setup itself is broken, which is a developer
// error we want visible immediately rather than propagated as
// a vague "got 0 records" downstream.
func mustMarshal(v any) []byte {
	data, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return data
}
