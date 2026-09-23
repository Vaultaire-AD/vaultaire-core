//go:build !windows

package main

import (
	"fmt"
	"os"
)

// Outil Windows : voir main_windows.go. La souche garde le module compilable
// sur la machine de développement.
func main() {
	fmt.Fprintln(os.Stderr, "vaultaire_login : Windows uniquement")
	os.Exit(2)
}
