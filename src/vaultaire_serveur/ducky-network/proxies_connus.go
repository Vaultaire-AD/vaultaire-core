package duckynetwork

import (
	"database/sql"
	"net"
	"strings"
	"sync"
	"time"

	db "vaultaire/core/database"
	"vaultaire/core/logs"
)

// Plafond de connexions Ducky pour les PROXIES du cluster.
//
// Le plafond par adresse (20) protège le core d'une source qui ouvrirait des
// milliers de connexions. Mais depuis le relais (TO-DO 38), tous les agents
// qu'un proxy sert arrivent de l'adresse DU PROXY : sans exception, un proxy
// serait coupé au vingt-et-unième agent, en silence.
//
// L'exception ne vaut que pour les adresses d'un proxy ENREGISTRÉ et en ligne
// (cluster_nodes, rôle proxy). Enregistrer un nœud exige une identité de type
// vaultaire_proxy, donc une clé d'enrôlement de ce type : ce n'est pas une
// porte qu'une source quelconque s'ouvre elle-même. Le plafond global (2000)
// reste, lui, commun à tous.
//
// La liste est relue toutes les 30 secondes et gardée en mémoire : le plafond
// est consulté à chaque accept(), sous le verrou du limiteur, et ne doit
// jamais attendre la base.

// PlafondParProxy est le nombre de connexions simultanées admises depuis
// l'adresse d'un proxy.
const PlafondParProxy = 1000

const periodeProxies = 30 * time.Second

var (
	proxiesMu    sync.RWMutex
	adressesProx = map[string]bool{}
	proxiesUne   sync.Once
)

// plafondPourSource est branché sur le limiteur Ducky.
func plafondPourSource(source string) int {
	proxiesMu.RLock()
	defer proxiesMu.RUnlock()
	if adressesProx[source] {
		return PlafondParProxy
	}
	return 0
}

// demarrerSuiviProxies lance, une fois, la relecture périodique.
func demarrerSuiviProxies() {
	proxiesUne.Do(func() {
		duckyLimiter.DefinirPlafondPour(plafondPourSource)
		go func() {
			defer func() {
				if r := recover(); r != nil {
					logs.Write_Log("ERROR", "ducky: suivi des proxies arrêté sur panique")
				}
			}()
			for {
				if base := db.GetDatabase(); base != nil {
					if liste, err := lireAdressesProxies(base); err == nil {
						remplacerAdressesProxies(liste)
					} else {
						logs.Write_Log("WARNING", "ducky: adresses des proxies illisibles : "+err.Error())
					}
				}
				time.Sleep(periodeProxies)
			}
		}()
	})
}

func remplacerAdressesProxies(liste []string) {
	nouv := make(map[string]bool, len(liste))
	for _, a := range liste {
		nouv[a] = true
	}
	proxiesMu.Lock()
	adressesProx = nouv
	proxiesMu.Unlock()
}

// lireAdressesProxies rend les adresses IP des proxies en ligne : celle vue au
// dernier enregistrement et, si elle est une IP, l'adresse publique déclarée.
func lireAdressesProxies(base *sql.DB) ([]string, error) {
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
			a = strings.TrimSpace(a)
			if net.ParseIP(a) != nil {
				out = append(out, a)
			}
		}
	}
	return out, rows.Err()
}
