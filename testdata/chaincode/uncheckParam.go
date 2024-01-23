package fixtures

import "fmt"

func ExampleFunc1(x int, y string) {
	fmt.Println(y)
}

func ExampleFunc2(x int, y string, z bool) {
	if y != "" {
		fmt.Println(x)
	}
}
