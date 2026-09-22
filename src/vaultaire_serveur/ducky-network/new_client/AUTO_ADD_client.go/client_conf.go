package autoaddclientgo

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	clusterdatabase "vaultaire/cluster/cluster_database"
	clusterstorage "vaultaire/cluster/cluster_storage"
)

// NomConfClient est le fichier de configuration que l'agent lit au démarrage.
// Déposé dans le répertoire recopié par SCP, puis déplacé par le script
// d'installation vers /etc/vaultaire_client/.
const NomConfClient = "client_conf.json"

// serveurConf reprend le format de l'agent (vaultaire_client/config).
type serveurConf struct {
	IP       string `json:"ip"`
	Port     int    `json:"port"`
	Hostname string `json:"hostname,omitempty"`
	Role     string `json:"role,omitempty"`
}

type confClient struct {
	Servers []serveurConf `json:"servers"`
}

// noeudsPourInstallation est une variable pour les tests.
var noeudsPourInstallation = func(db *sql.DB) ([]clusterstorage.Node, error) {
	return clusterdatabase.NoeudsPourAgents(db, nil)
}

// ServeursPourInstallation rend les CORES qu'un agent neuf doit connaître.
//
// # Les cores seulement
//
// La liste d'installation est le dernier recours de l'agent : ce qu'il essaie
// quand tout ce qu'il a appris a échoué. Un proxy n'y a pas sa place — il ne
// relaie pas encore (TO-DO 38) et, relais fait, il resterait un intermédiaire
// dont la panne ne doit pas couper une machine de tout core. Les proxies
// arrivent par la découverte (04_04), qui les classe.
//
// Mêmes nœuds que la 04_04 (en ligne, exposés aux agents, empreinte connue),
// dans le même ordre, avec l'adresse et le port PUBLICS s'ils sont déclarés.
func ServeursPourInstallation(db *sql.DB) ([]serveurConf, error) {
	noeuds, err := noeudsPourInstallation(db)
	if err != nil {
		return nil, err
	}
	vus := map[string]bool{}
	var out []serveurConf
	for _, n := range noeuds {
		if n.Role != "core" {
			continue
		}
		s := serveurConf{IP: n.AdresseEffective(), Port: n.PortEffectif(), Hostname: n.Hostname, Role: n.Role}
		cle := fmt.Sprintf("%s:%d", s.IP, s.Port)
		if s.IP == "" || s.Port <= 0 || vus[cle] {
			continue
		}
		vus[cle] = true
		out = append(out, s)
	}
	return out, nil
}

// EcrireConfClient écrit client_conf.json dans le répertoire du client.
//
// Rend le nombre de cores écrits. Zéro core — aucun nœud exposé et en ligne —
// n'écrit RIEN : le script d'installation se rabat alors sur l'adresse du core
// qui l'exécute (SSH_CONNECTION), qui est au moins joignable depuis la machine.
// Écrire une liste vide laisserait un agent sans aucune adresse.
func EcrireConfClient(db *sql.DB, repertoire string) (int, error) {
	serveurs, err := ServeursPourInstallation(db)
	if err != nil {
		return 0, err
	}
	chemin := filepath.Join(repertoire, NomConfClient)
	if len(serveurs) == 0 {
		_ = os.Remove(chemin) // un fichier d'une installation précédente serait périmé
		return 0, nil
	}
	data, err := json.MarshalIndent(confClient{Servers: serveurs}, "", "    ")
	if err != nil {
		return 0, err
	}
	if err := os.MkdirAll(repertoire, 0o700); err != nil {
		return 0, err
	}
	if err := os.WriteFile(chemin, append(data, '\n'), 0o600); err != nil {
		return 0, err
	}
	return len(serveurs), nil
}
