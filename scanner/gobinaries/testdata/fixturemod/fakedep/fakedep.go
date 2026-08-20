// Package fakedep is a local, network-free dependency for the fixture module.
package fakedep

// Greeting returns a fixed string so the linker retains the package.
func Greeting() string { return "hello from fakedep" }
