package autoaddclientgo

import (
	duckykey "vaultaire/serveur/ducky-network/key_management"
	"vaultaire/serveur/logs"
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
)

func Manage_Auto_ADD_client(hostuser, hostip, client_softwareID string) string {

	// Étape 0 : Ajouter automatiquement le host au known_hosts
	if err := AddHostToKnownHosts(hostip, 22); err != nil {
		logs.Write_LogCode("WARNING", logs.CodeNetConnection, "autoadd: host key scan failed for "+hostip+": "+err.Error())
		return "host key scan failed for " + hostip + " : " + err.Error()
	}

	privateKeyPath, err := duckykey.GetLoginClientPrivateKeyPath()
	if err != nil {
		logs.Write_LogCode("ERROR", logs.CodeCertLoad, "autoadd: login client SSH key from database failed: "+err.Error())
		return "error: " + err.Error()
	}

	err = envoyerFichierSCPAvecCleSSH(hostuser, privateKeyPath, client_softwareID, hostip, 22)
	if err != nil {
		logs.Write_LogCode("WARNING", logs.CodeNetConnection, "autoadd: send file to host "+client_softwareID+" failed: "+err.Error())
		return "error send file: " + err.Error()
	}
	err = ExecuterCommandesSSHAvecCle(hostuser, privateKeyPath, hostip, 22)
	if err != nil {
		logs.Write_LogCode("WARNING", logs.CodeNetConnection, "autoadd: execute commands on host "+client_softwareID+" failed: "+err.Error())
		return "error execute commands: " + err.Error()
	}
	return ("new client setup remotly with succes with this ID : " + client_softwareID)
}

// AddHostToKnownHosts ajoute automatiquement la clé du host distant dans ~/.ssh/known_hosts
func AddHostToKnownHosts(host string, port int) error {
	// Obtenir le chemin de ~/.ssh/known_hosts
	currentUser, err := user.Current()
	if err != nil {
		return fmt.Errorf("❌ Impossible de récupérer l'utilisateur courant : %v", err)
	}
	sshDir := filepath.Join(currentUser.HomeDir, ".ssh")
	knownHostsPath := filepath.Join(sshDir, "known_hosts")

	// Créer ~/.ssh s’il n’existe pas
	if _, err := os.Stat(sshDir); os.IsNotExist(err) {
		if err := os.MkdirAll(sshDir, 0700); err != nil {
			return fmt.Errorf("❌ Impossible de créer ~/.ssh : %v", err)
		}
	}

	// Vérifie si le host est déjà présent
	if content, err := os.ReadFile(knownHostsPath); err == nil {
		if strings.Contains(string(content), host) {
			return nil // déjà présent
		}
	}

	// Utiliser ssh-keyscan pour récupérer la clé
	var out bytes.Buffer
	cmd := exec.Command("ssh-keyscan", "-p", fmt.Sprintf("%d", port), host)
	cmd.Stdout = &out
	cmd.Stderr = &bytes.Buffer{}

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("❌ ssh-keyscan a échoué : %v", err)
	}

	// Ajouter la clé au fichier known_hosts
	f, err := os.OpenFile(knownHostsPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("❌ Impossible d’ouvrir known_hosts : %v", err)
	}
	defer func() {
		if err := f.Close(); err != nil {
			logs.Write_Log("DEBUG", "autoadd: known_hosts file close failed: "+err.Error())
		}
	}()

	if _, err := f.Write(out.Bytes()); err != nil {
		return fmt.Errorf("❌ Impossible d’écrire dans known_hosts : %v", err)
	}

	return nil
}
