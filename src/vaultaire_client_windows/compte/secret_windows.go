//go:build windows

package compte

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// La garde des secrets par DPAPI, portée MACHINE (TO-DO 195).
//
// Portée machine et non utilisateur : l'agent tourne en SYSTEM, et le secret
// doit se relire après un redémarrage, sans session ouverte. Tout processus
// SYSTEM ou administrateur de la machine peut le déchiffrer — c'est le cas de
// toute façon : un administrateur remet à zéro n'importe quel mot de passe
// local. Ce que DPAPI ajoute : une copie du disque ne livre rien.

func init() {
	proteger = func(clair []byte) ([]byte, error) {
		return dpapi(clair, true)
	}
	deproteger = func(chiffre []byte) ([]byte, error) {
		return dpapi(chiffre, false)
	}
}

// entropieVaultaire : un sel propre à l'agent. Un autre programme qui
// déchiffrerait « au hasard » les blobs machine de ce poste ne lit pas ceux-ci
// sans le connaître.
var entropieVaultaire = []byte("vaultaire-compte-local-195")

func dpapi(entree []byte, chiffrer bool) ([]byte, error) {
	if len(entree) == 0 {
		return nil, fmt.Errorf("donnée vide")
	}
	in := windows.DataBlob{Size: uint32(len(entree)), Data: &entree[0]}
	sel := windows.DataBlob{Size: uint32(len(entropieVaultaire)), Data: &entropieVaultaire[0]}
	var out windows.DataBlob
	drapeaux := uint32(windows.CRYPTPROTECT_UI_FORBIDDEN | windows.CRYPTPROTECT_LOCAL_MACHINE)
	var err error
	if chiffrer {
		err = windows.CryptProtectData(&in, nil, &sel, 0, nil, drapeaux, &out)
	} else {
		err = windows.CryptUnprotectData(&in, nil, &sel, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out)
	}
	if err != nil {
		return nil, err
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data)))
	resultat := make([]byte, out.Size)
	copy(resultat, unsafe.Slice(out.Data, out.Size))
	if !chiffrer {
		// Le tampon de Windows porte le clair : effacé avant d'être rendu.
		effacer(unsafe.Slice(out.Data, out.Size))
	}
	return resultat, nil
}
