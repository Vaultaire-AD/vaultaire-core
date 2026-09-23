//go:build !windows

package main

import (
	"fmt"
	"os"
)

// L'agent ne tourne QUE sous Windows : le canal qu'il sert est un tube nommé,
// et le compte qu'il provisionne est un compte Windows.
//
// Cette souche existe pour que le module se compile et se TESTE sur la machine
// de développement, qui est sous Linux — protocole du tube, nommage des comptes,
// validation des requêtes n'ont rien de spécifique au système.
func servir(bool) {
	fmt.Fprintln(os.Stderr,
		"vaultaire : cet agent est celui de Windows ; sous Linux, utilisez src/vaultaire_client")
	os.Exit(2)
}
