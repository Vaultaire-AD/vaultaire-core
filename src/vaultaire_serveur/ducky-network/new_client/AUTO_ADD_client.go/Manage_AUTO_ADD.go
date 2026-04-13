package autoaddclientgo

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"vaultaire/core/logs"
	duckykey "vaultaire/ducky-network/key_management"
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
	currentUser, err := user.Current()
	if err != nil {
		return fmt.Errorf("user error: %v", err)
	}

	sshDir := filepath.Join(currentUser.HomeDir, ".ssh")
	knownHostsPath := filepath.Join(sshDir, "known_hosts")

	if err := os.MkdirAll(sshDir, 0700); err != nil {
		return err
	}

	var stdout, stderr bytes.Buffer
	// On force le type de clé pour éviter les lenteurs et on utilise le chemin complet
	cmd := exec.Command("ssh-keyscan", "-p", fmt.Sprintf("%d", port), host)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		// C'EST ICI que tu verras pourquoi ça échoue vraiment
		return fmt.Errorf("ssh-keyscan failed: %v | Stderr: %s", err, stderr.String())
	}

	// Filtrage pour ne garder QUE les clés (on vire les lignes commençant par #)
	lines := strings.Split(stdout.String(), "\n")
	var cleanOutput strings.Builder
	for _, line := range lines {
		if line != "" && !strings.HasPrefix(line, "#") {
			cleanOutput.WriteString(line + "\n")
		}
	}

	if cleanOutput.Len() == 0 {
		return fmt.Errorf("aucune clé valide trouvée pour %s (stderr: %s)", host, stderr.String())
	}

	// Écriture propre
	f, err := os.OpenFile(knownHostsPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer f.Close()

	if _, err := f.WriteString(cleanOutput.String()); err != nil {
		return err
	}

	return nil
}
