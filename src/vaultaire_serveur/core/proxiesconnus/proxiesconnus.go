// Package proxiesconnus tient la liste des adresses des proxies du cluster.
//
// # Pourquoi une liste commune
//
// Deux écoutes du core ont besoin de reconnaître un proxy ENREGISTRÉ :
//
//   - Ducky, pour lui accorder un plafond de connexions à sa mesure — tous les
//     agents qu'il relaie arrivent de son adresse ;
//   - LDAP/LDAPS (TO-DO 72), pour la même raison, et surtout pour ne croire
//     l'en-tête PROXY qu'il envoie — l'adresse réelle du client — que de lui.
//
// La liste vivait dans le paquet Ducky. Deux relectures de la même table, à
// deux cadences, auraient pu répondre différemment à la même question pendant
// trente secondes : un proxy cru par l'une, refusé par l'autre.
//
// # Ce qui fait foi
//
// Une ligne de cluster_nodes au rôle « proxy », en ligne. Enregistrer un nœud
// exige une identité de type vaultaire_proxy, donc une clé d'enrôlement de ce
// type : ce n'est pas une porte qu'une source quelconque s'ouvre elle-même.
//
// La liste est relue toutes les 30 secondes et gardée en mémoire : elle est
// consultée à chaque connexion acceptée, et ne doit jamais attendre la base.
package proxiesconnus

import (
	"database/sql"
	"net"
	"strings"
	"sync"
	"time"

	db "vaultaire/core/database"
	"vaultaire/core/logs"
)

// Periode est l'intervalle de relecture.
const Periode = 30 * time.Second

var (
	mu       sync.RWMutex
	adresses = map[string]bool{}
	une      sync.Once
)

// EstUnProxy dit si une adresse IP est celle d'un proxy enregistré en ligne.
//
// L'adresse est normalisée : « ::ffff:10.0.0.1 » et « 10.0.0.1 » désignent la
// même machine, et un proxy ne doit pas perdre sa qualité selon la pile réseau
// qui l'a vu arriver.
func EstUnProxy(ip string) bool {
	ip = normaliser(ip)
	if ip == "" {
		return false
	}
	mu.RLock()
	defer mu.RUnlock()
	return adresses[ip]
}

// Demarrer lance, une fois, la relecture périodique. Sans effet ensuite.
func Demarrer() {
	une.Do(func() {
		go func() {
			defer func() {
				if r := recover(); r != nil {
					logs.Write_Log("ERROR", "proxies: suivi des proxies arrêté sur panique")
				}
			}()
			for {
				if base := db.GetDatabase(); base != nil {
					if liste, err := lire(base); err == nil {
						Remplacer(liste)
					} else {
						logs.Write_Log("WARNING", "proxies: adresses des proxies illisibles : "+err.Error())
					}
				}
				time.Sleep(Periode)
			}
		}()
	})
}

// Remplacer pose la liste. Exportée pour les tests des paquets qui s'en
// servent.
func Remplacer(liste []string) {
	nouv := make(map[string]bool, len(liste))
	for _, a := range liste {
		if a = normaliser(a); a != "" {
			nouv[a] = true
		}
	}
	mu.Lock()
	adresses = nouv
	mu.Unlock()
}

// lire rend les adresses IP des proxies en ligne : celle vue au dernier
// enregistrement et, si elle est une IP, l'adresse publique déclarée.
func lire(base *sql.DB) ([]string, error) {
	rows, err := base.Query(`SELECT ip_address, COALESCE(adresse_publique, '')
		FROM cluster_nodes WHERE role = 'proxy' AND status = 'online'`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var ip, pub string
		if err := rows.Scan(&ip, &pub); err != nil {
			return nil, err
		}
		for _, a := range []string{ip, pub} {
			if a = normaliser(a); a != "" {
				out = append(out, a)
			}
		}
	}
	return out, rows.Err()
}

// normaliser rend la forme canonique d'une IP, ou "" si ce n'en est pas une.
func normaliser(a string) string {
	ip := net.ParseIP(strings.TrimSpace(a))
	if ip == nil {
		return ""
	}
	if v4 := ip.To4(); v4 != nil {
		return v4.String()
	}
	return ip.String()
}
