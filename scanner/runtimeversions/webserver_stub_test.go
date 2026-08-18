package runtimeversions

import "testing"

func TestDetectIISCompiles(t *testing.T) {
	_ = detectIIS() // must be defined on every platform
}
