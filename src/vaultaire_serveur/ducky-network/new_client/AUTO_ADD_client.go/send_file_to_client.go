package autoaddclientgo

import (
	"bytes"
	"fmt"
	"os/exec"
	"vaultaire/core/storage"
)

func envoyerFichierSCPAvecCleSSH(user, privateKeyPath, client_softwareID, host string, port int) error {
	remoteDir := "/opt/vaultaire/"

	// 1. Créer le dossier distant s’il n'existe pas
	cmdMkdir := exec.Command(
		"ssh", "-i", privateKeyPath, "-p", fmt.Sprintf("%d", port),
		fmt.Sprintf("%s@%s", user, host),
		fmt.Sprintf("mkdir -p %s", remoteDir),
	)

	var mkdirErr bytes.Buffer
	cmdMkdir.Stderr = &mkdirErr
	if err := cmdMkdir.Run(); err != nil {
		return fmt.Errorf("❌ Erreur création dossier distant : %v\n%s", err, mkdirErr.String())
	}

	// 2. Envoyer les fichiers avec SCP
	cmdSCP := exec.Command(
		"scp", "-i", privateKeyPath, "-P", fmt.Sprintf("%d", port),
		"-r", "/opt/vaultaire/vaultaire_client/",
		fmt.Sprintf("%s@%s:%s", user, host, remoteDir),
	)

	var scpErr bytes.Buffer
	cmdSCP.Stderr = &scpErr

	fmt.Println("📦 Envoi du fichier avec SCP...")
	if err := cmdSCP.Run(); err != nil {
		return fmt.Errorf("❌ Erreur SCP : %v\n%s", err, scpErr.String())
	}
	cmdSCP = exec.Command(
		"sh", "-c",
		fmt.Sprintf(
			"scp -i %s -P %d -r /opt/vaultaire/clientsoftware/%s/* %s@%s:%s/",
			privateKeyPath, port, client_softwareID, user, host, storage.Client_Conf_path,
		),
	)
	cmdSCP.Stderr = &scpErr

	fmt.Println("📦 Envoi du fichier avec SCP...")
	if err := cmdSCP.Run(); err != nil {
		return fmt.Errorf("❌ Erreur SCP : %v\n%s", err, scpErr.String())
	}

	fmt.Println("✅ Fichier envoyé avec succès")
	return nil
}
