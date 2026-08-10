package webserveur

import (
	"os"
	"path/filepath"
	"strings"

	"vaultaire/core/logs"
)

// Emplacement des gabarits et des fichiers statiques du portail.
//
// # Le doublon que ce fichier supprime
//
// Le chemin `web_packet/sso_WEB_page/...` était écrit en clair à quatre
// endroits, et `auto-compil.sh` recopiait par-dessus tout le répertoire dans
// `cmd/web_packet/`. Il existait donc DEUX arborescences de gabarits, sans que
// rien ne dise laquelle faisait foi.
//
// La copie ne servait personne :
//
//   - les fichiers Compose montent `../../web_packet`, c'est-à-dire la SOURCE,
//     en lecture seule (dev et pre-prod) ;
//   - `deploy.sh` ne transfère que les binaires — `cmd/vaultaire_server`,
//     `cmd/vaultaire_client`, `cmd/vaultaire_ctl` — et le code arrive sur
//     l'hôte par `git pull` ;
//   - seul un test lisait la copie, et jugeait donc une version périmée.
//
// Elle nuisait, en revanche : une modification de gabarit paraissait sans effet
// tant qu'`auto-compil.sh` n'avait pas tourné, ce qui a déjà envoyé un
// diagnostic dans le mur.
//
// # Pourquoi une variable d'environnement
//
// Le chemin est relatif au répertoire de travail du processus. Cela convient au
// service systemd et aux conteneurs, où ce répertoire est fixé — mais pas à
// quelqu'un qui lance le binaire depuis ailleurs, ni à un test.
//
// `VAULTAIRE_WEB_PACKET` permet de le désigner explicitement, sans rien changer
// pour les déploiements existants qui n'y touchent pas.
const (
	// racineParDefaut est le chemin employé quand rien n'est déclaré.
	racineParDefaut = "web_packet/sso_WEB_page"

	// VariableRacineWeb nomme la variable d'environnement de contournement.
	VariableRacineWeb = "VAULTAIRE_WEB_PACKET"
)

// racineWeb rend la racine des ressources du portail.
//
// Résolue une fois, à la première demande : le répertoire de travail ne change
// pas en cours d'exécution, et relire l'environnement à chaque requête coûterait
// sans rien apporter.
var racineWeb = resoudreRacineWeb()

func resoudreRacineWeb() string {
	if v := strings.TrimSpace(os.Getenv(VariableRacineWeb)); v != "" {
		return filepath.Clean(v)
	}
	return racineParDefaut
}

// CheminGabarit rend le chemin d'un gabarit.
func CheminGabarit(nom string) string {
	return filepath.Join(racineWeb, "templates", nom)
}

// RepertoireGabarits rend le répertoire des gabarits.
func RepertoireGabarits() string {
	return filepath.Join(racineWeb, "templates")
}

// RepertoireStatiques rend le répertoire des CSS, JS et images.
func RepertoireStatiques() string {
	return filepath.Join(racineWeb, "static")
}

// VerifierRessourcesWeb contrôle au démarrage que les ressources sont là.
//
// # Pourquoi échouer tôt plutôt que page par page
//
// Sans ce contrôle, un répertoire absent ne se manifeste qu'à la première
// visite, par une erreur de gabarit sur une page — et l'administrateur cherche
// du côté de cette page, pas du côté du déploiement. Le serveur, lui, a
// démarré sans rien signaler.
//
// Le défaut est journalisé et non fatal : l'annuaire, LDAP et l'API n'ont pas
// besoin du portail, et arrêter tout le service parce que des fichiers HTML
// manquent serait disproportionné.
func VerifierRessourcesWeb() bool {
	ok := true
	for _, d := range []string{RepertoireGabarits(), RepertoireStatiques()} {
		info, err := os.Stat(d)
		if err != nil || !info.IsDir() {
			absolu, _ := filepath.Abs(d)
			logs.Write_Log("ERROR", "web: ressources introuvables — "+absolu+
				" (répertoire de travail incorrect, ou "+VariableRacineWeb+" à déclarer)")
			ok = false
		}
	}
	return ok
}
