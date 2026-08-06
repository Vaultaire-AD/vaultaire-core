package getlocalinformation

import (
	"fmt"
	"os/exec"
	"strings"
)

// Fonction pour obtenir le système d'exploitation
func GetOS() (string, error) {
	cmd := exec.Command("bash", "-c", "cat /etc/os-release | grep PRETTY_NAME | head -n 1") // Exécuter la commande en bash
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("erreur lors de l'exécution de la commande pour récupérer l'OS : %v", err)
	}
	// Nettoyer l'output pour ne récupérer que le nom
	os := strings.TrimSpace(strings.Split(string(output), "=")[1]) // On découpe par "=" et on prend la partie après
	os = strings.ReplaceAll(os, "\"", "")
	return os, nil
}
