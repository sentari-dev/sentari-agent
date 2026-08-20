// Command fixturemod is a hermetic test fixture: a stdlib-only Go program
// with a single dependency satisfied by a local replace directive. It exists
// only so the build toolchain produces a real Go binary whose embedded module
// metadata the gobinaries probe tests can read back. It is never executed.
package main

import (
	"fmt"

	"example.com/fakedep"
)

func main() {
	fmt.Println(fakedep.Greeting())
}
