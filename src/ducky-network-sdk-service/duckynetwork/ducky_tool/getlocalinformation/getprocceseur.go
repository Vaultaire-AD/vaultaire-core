package getlocalinformation

import (
	"fmt"
	"os/exec"
)

func GetCPUCount() (string, error) {
	cmd := exec.Command("nproc") // 'nproc' renvoie le nombre de cœurs CPU
	output, err := cmd.Output()
	if err != nil {
		return "0", fmt.Errorf("erreur lors de l'exécution de la commande nproc : %v", err)
	}

	return string(output), nil
}
