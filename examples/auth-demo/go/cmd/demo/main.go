package main

import (
	"fmt"
	"os"

	"tafrah-examples-go/tafrah"
)

func main() {
	json, err := tafrah.RunProofJSON()
	if err != nil {
		fmt.Fprintf(os.Stderr, "go demo failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(json)
}
