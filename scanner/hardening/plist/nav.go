package plist

// Navigation helpers for the decoded plist tree. macOS security plists store
// booleans inconsistently (sometimes <true/>, sometimes <integer>1</integer>),
// so Bool coerces an int as well.

// String returns the string value at key in a dict node.
func String(node any, key string) (string, bool) {
	m, ok := node.(map[string]any)
	if !ok {
		return "", false
	}
	s, ok := m[key].(string)
	return s, ok
}

// Int returns the int64 value at key in a dict node.
func Int(node any, key string) (int64, bool) {
	m, ok := node.(map[string]any)
	if !ok {
		return 0, false
	}
	switch v := m[key].(type) {
	case int64:
		return v, true
	case float64:
		return int64(v), true
	default:
		return 0, false
	}
}

// Bool returns the boolean value at key, coercing a numeric 0/non-0 to
// false/true (Apple stores enable-flags both ways).
func Bool(node any, key string) (bool, bool) {
	m, ok := node.(map[string]any)
	if !ok {
		return false, false
	}
	switch v := m[key].(type) {
	case bool:
		return v, true
	case int64:
		return v != 0, true
	case float64:
		return v != 0, true
	default:
		return false, false
	}
}
