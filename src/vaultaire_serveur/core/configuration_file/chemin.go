package configuration_file

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Où le core cherche sa configuration.
//
// # Ce que ce fichier corrige
//
// Le chemin était écrit en dur dans main :
//
//	configurationfile.LoadConfig("/opt/vaultaire/serveur_conf.yaml")
//
// Trois conséquences.
//
// Le core ne pouvait pas tourner ailleurs qu'à cet emplacement — ni sous un
// autre utilisateur, ni depuis un dépôt cloné, ni dans un conteneur qui range
// sa configuration autrement. L'agent, lui, résout déjà ses chemins par
// variable d'environnement : les deux moitiés du produit ne s'installaient pas
// de la même façon.
//
// Ensuite, l'échec de lecture rendait l'erreur brute de `os.Open` :
//
//	Erreur lors de la lecture du fichier de configuration :
//	open /opt/vaultaire/serveur_conf.yaml: no such file or directory
//
// Vrai, et inutile : il ne dit pas ce que le fichier doit contenir, ni où en
// trouver un modèle, ni qu'un autre emplacement est possible.
//
// Enfin, `/opt` n'est pas l'endroit d'un fichier de configuration. La
// hiérarchie Unix range la configuration dans `/etc`, l'état variable dans
// `/var/lib`, et `/opt` reçoit les logiciels tiers avec leur arborescence
// propre. Un administrateur qui sauvegarde `/etc` perdait la configuration du
// core sans le savoir.

const (
	// EnvConfig désigne le fichier de configuration du core.
	//
	// Même convention que les variables de l'agent (VAULTAIRE_KEY_PATH,
	// VAULTAIRE_LOG_PATH) : un préfixe commun rend l'ensemble découvrable par
	// un `env | grep VAULTAIRE`.
	EnvConfig = "VAULTAIRE_CONFIG"

	// CheminStandard est l'emplacement recommandé.
	//
	// `/etc/vaultaire/` : c'est là qu'un administrateur cherche la
	// configuration d'un service, et c'est ce que sauvegarde un `/etc` copié.
	CheminStandard = "/etc/vaultaire/serveur_conf.yaml"

	// CheminHistorique est l'emplacement des installations existantes.
	//
	// Toujours accepté, en repli. Le retirer casserait les déploiements en
	// place pour un gain esthétique — et le fichier Compose de développement,
	// le Dockerfile de préproduction et la documentation d'installation le
	// désignent tous.
	CheminHistorique = "/opt/vaultaire/serveur_conf.yaml"
)

// CheminConfig rend le fichier de configuration à lire.
//
// # L'ordre de recherche
//
//	1. $VAULTAIRE_CONFIG        — décision explicite, elle l'emporte
//	2. /etc/vaultaire/…         — l'emplacement recommandé
//	3. /opt/vaultaire/…         — les installations existantes
//
// La variable l'emporte même si le fichier qu'elle désigne n'existe pas : la
// poser est une décision, et se rabattre en silence sur un autre fichier
// donnerait un core qui tourne avec une configuration que personne n'a
// demandée. L'erreur est alors franche, et nomme le chemin qu'on a choisi.
//
// Rend aussi la liste des emplacements consultés, pour que le message d'erreur
// puisse les montrer. Un « fichier introuvable » qui ne dit pas où l'on a
// cherché oblige à lire le code pour le savoir.
func CheminConfig() (chemin string, consultes []string) {
	if v := strings.TrimSpace(os.Getenv(EnvConfig)); v != "" {
		return v, []string{v + " (via " + EnvConfig + ")"}
	}

	candidats := []string{CheminStandard, CheminHistorique}
	for _, c := range candidats {
		if _, err := os.Stat(c); err == nil {
			return c, candidats
		}
	}

	// Aucun trouvé : on rend le chemin RECOMMANDÉ. L'erreur qui suivra le
	// nommera, donc dira où poser le fichier — plutôt que de désigner
	// l'emplacement historique et de perpétuer l'ancien usage.
	return CheminStandard, candidats
}

// ErreurConfigIntrouvable compose un message qui dit quoi faire.
//
// # Pourquoi un message aussi long
//
// C'est le tout premier obstacle d'une installation, celui qu'on rencontre
// avant d'avoir la moindre idée de la structure du projet. Économiser six
// lignes ici se paie en une recherche dans les sources.
func ErreurConfigIntrouvable(consultes []string, cause error) error {
	var b strings.Builder
	b.WriteString("configuration du core introuvable ou illisible.\n\n")
	b.WriteString("  Emplacements consultés :\n")
	for _, c := range consultes {
		b.WriteString("    " + c + "\n")
	}
	b.WriteString("\n  Cause : " + cause.Error() + "\n")
	b.WriteString("\n  Pour y remédier :\n")
	b.WriteString("    sudo mkdir -p " + filepath.Dir(CheminStandard) + "\n")
	b.WriteString("    sudo cp deployments/configs/serveur_conf.yaml " + CheminStandard + "\n")
	b.WriteString("\n  Ou désignez un autre fichier :\n")
	b.WriteString("    " + EnvConfig + "=/chemin/vers/serveur_conf.yaml\n")
	b.WriteString("\n  Voir docs/Installation/Setup.md")
	return fmt.Errorf("%s", b.String())
}
