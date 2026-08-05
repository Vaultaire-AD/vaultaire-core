package autoaddclientgo

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"vaultaire/core/storage"
)

//
//func ExecuterCommandesSSHAvecCle(user, privateKeyPath, host string, port int) error {
//	remote := fmt.Sprintf("%s@%s", user, host)
//
//	// Étape 1 : récupérer le nom de l'OS
//	cmdDetect := exec.Command("ssh", "-i", privateKeyPath, "-p", fmt.Sprintf("%d", port), remote, "cat /etc/os-release")
//	var out bytes.Buffer
//	var stderr bytes.Buffer
//	cmdDetect.Stdout = &out
//	cmdDetect.Stderr = &stderr
//
//	if err := cmdDetect.Run(); err != nil {
//		return fmt.Errorf("❌ Impossible de détecter l'OS distant : %s\n%s", err, stderr.String())
//	}
//
//	osRelease := out.String()
//	var osType string
//	switch {
//	case strings.Contains(osRelease, "ID=debian"):
//		osType = "debian"
//		err := LoadCommandsFromShellScript(storage.Sh_folder_path + osType + ".sh")
//		if err != nil {
//			return fmt.Errorf("%s", "failed to load command file"+err.Error())
//		}
//	case strings.Contains(osRelease, "ID=ubuntu"):
//		osType = "ubuntu"
//		err := LoadCommandsFromShellScript(storage.Sh_folder_path + osType + ".sh")
//		if err != nil {
//			return fmt.Errorf("%s", "failed to load command file"+err.Error())
//		}
//	case strings.Contains(osRelease, "ID=\"rocky\"") || strings.Contains(osRelease, "ID=rocky"):
//		osType = "rocky"
//		err := LoadCommandsFromShellScript(storage.Sh_folder_path + osType + ".sh")
//		if err != nil {
//			return fmt.Errorf("%s", "failed to load command file"+err.Error())
//		}
//	default:
//		return fmt.Errorf("⚠️ OS non reconnu :\n%s", osRelease)
//	}
//
//	fmt.Printf("✅ OS détecté : %s\n", osType)
//	// Exécution des commandes en SSH
//	for _, commande := range storage.AutoAddClientCommandesList {
//
//		fullCommand := fmt.Sprintf("bash -c '%s'", escapeSingleQuotes(commande))
//
//		cmd := exec.Command("ssh", "-i", privateKeyPath, "-p", fmt.Sprintf("%d", port), remote, fullCommand)
//
//		var stderr bytes.Buffer
//		cmd.Stderr = &stderr
//
//		fmt.Printf("▶️  %s\n", commande)
//		if err := cmd.Run(); err != nil {
//			return fmt.Errorf("❌ Erreur commande : %s\n%s", commande, stderr.String())
//		}
//	}
//
//	fmt.Println("✅ Toutes les commandes ont été exécutées avec succès.")
//	return nil
//}
//

func ExecuterCommandesSSHAvecCle(user, privateKeyPath, host string, port int) error {
	remote := fmt.Sprintf("%s@%s", user, host)
	portStr := fmt.Sprintf("%d", port)

	// 1. Détecter l'OS distant (identique à votre code)
	cmdDetect := exec.Command("ssh", "-i", privateKeyPath, "-p", portStr, remote, "cat /etc/os-release")
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
	case strings.Contains(osRelease, "ID=ubuntu"):
		osType = "ubuntu"
	case strings.Contains(osRelease, "ID=\"rocky\"") || strings.Contains(osRelease, "ID=rocky"):
		osType = "rocky"
	default:
		return fmt.Errorf("⚠️ OS non reconnu :\n%s", osRelease)
	}

	localScriptPath := storage.Sh_folder_path + osType + ".sh"
	remoteScriptPath := "/tmp/vaultaire_install.sh"

	fmt.Printf("✅ OS détecté : %s. Transfert du script...\n", osType)

	// 2. Transférer le script sur le serveur distant via SCP
	scpCmd := exec.Command("scp", "-i", privateKeyPath, "-P", portStr, localScriptPath, fmt.Sprintf("%s:%s", remote, remoteScriptPath))
	if err := scpCmd.Run(); err != nil {
		return fmt.Errorf("❌ Erreur lors du transfert du script via SCP : %v", err)
	}

	// 3. Exécuter le script distant en tant que root/bash
	runCmd := exec.Command("ssh", "-i", privateKeyPath, "-p", portStr, remote, fmt.Sprintf("bash %s", remoteScriptPath))
	runCmd.Stdout = os.Stdout
	runCmd.Stderr = os.Stderr

	fmt.Println("▶️ Exécution du script distant...")
	if err := runCmd.Run(); err != nil {
		return fmt.Errorf("❌ Erreur lors de l'exécution du script distant : %v", err)
	}

	fmt.Println("✅ Toutes les commandes ont été exécutées avec succès.")
	return nil
}

func escapeSingleQuotes(cmd string) string {
	// Transforme chaque ' en '\'' (échappement POSIX pour bash -c '')
	return strings.ReplaceAll(cmd, "'", "'\\''")
}
