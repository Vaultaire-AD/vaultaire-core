package autoaddclientgo

import (
	"vaultaire/serveur/storage"
	"bytes"
	"fmt"
	"os/exec"
	"strings"
)

func ExecuterCommandesSSHAvecCle(user, privateKeyPath, host string, port int) error {
	remote := fmt.Sprintf("%s@%s", user, host)

	// Étape 1 : récupérer le nom de l'OS
	cmdDetect := exec.Command("ssh", "-i", privateKeyPath, "-p", fmt.Sprintf("%d", port), remote, "cat /etc/os-release")
	var out bytes.Buffer
	var stderr bytes.Buffer
	cmdDetect.Stdout = &out
	cmdDetect.Stderr = &stderr

	if err := cmdDetect.Run(); err != nil {
		return fmt.Errorf("❌ Impossible de détecter l'OS distant : %s\n%s", err, stderr.String())
	}

	osRelease := out.String()
	var osType string
	switch {
	case strings.Contains(osRelease, "ID=debian"):
		osType = "debian"
		err := LoadCommandsFromShellScript(storage.Sh_folder_path + osType + ".sh")
		if err != nil {
			return fmt.Errorf("failed to load command file" + err.Error())
		}
	case strings.Contains(osRelease, "ID=ubuntu"):
		osType = "ubuntu"
		err := LoadCommandsFromShellScript(storage.Sh_folder_path + osType + ".sh")
		if err != nil {
			return fmt.Errorf("failed to load command file" + err.Error())
		}
	case strings.Contains(osRelease, "ID=\"rocky\"") || strings.Contains(osRelease, "ID=rocky"):
		osType = "rocky"
		err := LoadCommandsFromShellScript(storage.Sh_folder_path + osType + ".sh")
		if err != nil {
			return fmt.Errorf("failed to load command file" + err.Error())
		}
	default:
		return fmt.Errorf("⚠️ OS non reconnu :\n%s", osRelease)
	}

	fmt.Printf("✅ OS détecté : %s\n", osType)
	// Exécution des commandes en SSH
	for _, commande := range storage.AutoAddClientCommandesList {

		fullCommand := fmt.Sprintf("bash -c '%s'", escapeSingleQuotes(commande))

		cmd := exec.Command("ssh", "-i", privateKeyPath, "-p", fmt.Sprintf("%d", port), remote, fullCommand)

		var stderr bytes.Buffer
		cmd.Stderr = &stderr

		fmt.Printf("▶️  %s\n", commande)
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("❌ Erreur commande : %s\n%s", commande, stderr.String())
		}
	}

	fmt.Println("✅ Toutes les commandes ont été exécutées avec succès.")
	return nil
}

func escapeSingleQuotes(cmd string) string {
	// Transforme chaque ' en '\'' (échappement POSIX pour bash -c '')
	return strings.ReplaceAll(cmd, "'", "'\\''")
}
