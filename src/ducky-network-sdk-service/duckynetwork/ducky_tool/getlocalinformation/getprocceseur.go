//go:build !windows

package getlocalinformation

import (
	"fmt"
	"os/exec"
	"strings"
)

func GetCPUCount() (string, error) {
	cmd := exec.Command("nproc") // 'nproc' renvoie le nombre de cœurs CPU
	output, err := cmd.Output()
	if err != nil {
		return "0", fmt.Errorf("erreur lors de l'exécution de la commande nproc : %v", err)
	}

	// La sortie de nproc finit par un retour à la ligne. Gardé, il ajoutait
	// une ligne à l'inventaire 02_12 : le core lisait alors les sessions
	// ouvertes à la place de la version de l'agent (TO-DO 214).
	return strings.TrimSpace(string(output)), nil
}
