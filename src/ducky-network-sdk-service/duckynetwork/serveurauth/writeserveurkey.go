package serveurauth

import (
	"duckynetworkclient/V1/duckynetwork/storage"
	"os"
	"path/filepath"
)

func WriteToFile(content string) error {
	// Définir le chemin du fichier et le créer s'il n'existe pas
	filePath := storage.CheminDansKeyPath("serveurpublickey.pem")

	// Le répertoire du fichier qu'on écrit — et lui seul.
	//
	// L'ancienne version créait « .ssh » RELATIF au répertoire courant du
	// processus, avec os.ModePerm (0777) :
	//
	//	os.MkdirAll(".ssh", os.ModePerm)
	//
	// Trois défauts en une ligne. Le répertoire créé n'était pas celui de
	// filePath, donc l'écriture échouait quand même si KeyPath n'existait pas.
	// Il apparaissait là où l'agent avait été lancé, au hasard du répertoire
	// courant. Et 0777 annonce « accessible en écriture à tous » pour un
	// répertoire de clés.
	//
	// 0700 : ce répertoire ne regarde que le compte qui fait tourner l'agent.
	if err := os.MkdirAll(filepath.Dir(filePath), 0o700); err != nil {
		return err
	}

	// La clé PUBLIQUE du core : 0644 est correct, elle n'a rien de secret.
	// C'est son intégrité qui compte, pas sa confidentialité — c'est elle qui
	// permet d'authentifier le serveur.
	if err := os.WriteFile(filePath, []byte(content), 0o644); err != nil {
		return err
	}

	return nil
}
