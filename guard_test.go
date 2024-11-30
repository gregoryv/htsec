package htsec

import "fmt"

func ExampleGuard_String() {
	g := Guard{Name: "x"}
	fmt.Print(g.String())
	// output:
	// guard x
}
