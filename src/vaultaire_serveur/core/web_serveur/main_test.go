package webserveur

import (
	"os"
	"path/filepath"
	"testing"
)

// TestMain désigne les ressources du portail par un chemin ABSOLU.
//
// # Le défaut que cela ferme
//
// Les ressources du portail sont désignées par un chemin relatif —
// `web_packet/sso_WEB_page` — résolu depuis le répertoire de travail. C'est ce
// qu'il faut pour le service systemd et les conteneurs, dont le répertoire de
// travail est fixé.
//
// `go test`, lui, exécute chaque paquet depuis SON répertoire. Les tests qui
// lisent les gabarits cherchaient donc `core/web_serveur/web_packet/...`, qui
// n'existe pas : ils échouaient tous, en accusant des gabarits absents qui sont
// bel et bien là. Un test qui échoue pour une raison qu'il n'éprouve pas finit
// par être ignoré — et ceux-ci gardent la correspondance entre les champs des
// pages et ce que le code leur passe.
//
// Le répertoire de travail n'est PAS changé : d'autres tests du paquet lisent
// des fichiers source (`web_admin.go`…) à côté d'eux, et un chdir les casserait
// à leur tour. C'est donc VAULTAIRE_WEB_PACKET — la variable prévue pour cela —
// qui est posée, avec un chemin absolu.
//
// La racine est CHERCHÉE plutôt qu'écrite en dur : le dépôt peut être cloné
// n'importe où, et un chemin relatif du genre « ../../.. » se périme au premier
// déplacement de paquet.
func TestMain(m *testing.M) {
	if racine, err := racineDuDepot(); err == nil {
		os.Setenv(VariableRacineWeb, filepath.Join(racine, "web_packet", "sso_WEB_page"))
	}
	os.Exit(m.Run())
}

// racineDuDepot remonte jusqu'au répertoire qui porte VERSION et web_packet.
func racineDuDepot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		_, errVersion := os.Stat(filepath.Join(dir, "VERSION"))
		_, errWeb := os.Stat(filepath.Join(dir, "web_packet"))
		if errVersion == nil && errWeb == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", os.ErrNotExist
		}
		dir = parent
	}
}
