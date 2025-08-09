package autoaddclientgo

import (
	"bytes"
	"fmt"
	"os/exec"
)

// this function is use inside the cli directly for the password request
func sendpublickeySSH(user, privateKeyPath, pubkeypath, host string, port int) error {
	// 2. Envoyer la clé publique avec ssh-copy-id
	cmd := exec.Command(
		"ssh-copy-id", "-f", "-i", pubkeypath,
		"-p", fmt.Sprintf("%d", port),
		fmt.Sprintf("%s@%s", user, host),
	)

	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	fmt.Println("📤 Envoi de la clé publique avec ssh-copy-id...")

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("❌ Erreur ssh-copy-id : %v\n%s", err, stderr.String())
	}

	fmt.Println("✅ Clé publique ajoutée avec succès via ssh-copy-id.")
	return nil
}
