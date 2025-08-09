package getlocalinformation

import (
	"fmt"
	"os/exec"
	"strings"
)

func GetRAM() (string, error) {
	cmd := exec.Command("free", "-h") // 'free -h' pour obtenir les informations sur la RAM en format lisible
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("erreur lors de l'exécution de la commande free : %v", err)
	}
	// Chercher la ligne qui contient la RAM totale
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "Mem:") { // Vérifie si la ligne commence par "Mem:"
			fields := strings.Fields(line) // Divise la ligne en mots
			if len(fields) >= 3 {
				totalRAM := fields[1] // ex: "15Gi" (total)
				usedRAM := fields[2]  // ex: "7Gi" (used)
				return fmt.Sprintf("%s/%s", totalRAM, usedRAM), nil
			}
		}
	}
	return "", fmt.Errorf("impossible de récupérer la RAM")
}
