package serveurauth

import (
	"duckynetworkclient/V1/duckynetwork/storage"
	"os"
)

// HaveServeurKey indique si la clé publique du core est déjà sur disque.
//
// Placée dans serveurauth et non dans le paquet appelant : c'est le paquet qui
// écrit ce fichier (WriteToFile) et qui le lit. Laisser chaque appelant
// reconstruire le chemin de son côté, c'est se garantir qu'un jour l'un d'eux
// regardera au mauvais endroit après un renommage.
func HaveServeurKey() bool {
	_, err := os.Stat(storage.CheminDansKeyPath("serveurpublickey.pem"))
	return err == nil
}
