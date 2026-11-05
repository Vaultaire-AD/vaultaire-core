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
// # Quelle adresse — TO-DO 184
//
// Celle sous laquelle les cores VOIENT le proxy, et elle seule :
//
//   - adresse_vue, la source TCP de la session Ducky par laquelle il bat,
//     écrite par le core qui reçoit le battement (TO-DO 176) ;
//   - la source des sessions AUTHENTIFIÉES du proxy dans le registre de CE
//     core — vue à l'instant, sans attendre la relecture ;
//   - ip_address, ce que le proxy DÉCLARE, seulement tant qu'aucune adresse vue
//     n'est connue (proxy pas encore revenu battre depuis la mise à jour).
//
// L'adresse d'exposition (cluster expose, adresse_publique) n'y entre PLUS :
// c'est celle des CLIENTS. Derrière un NAT — proxy et core en conteneurs —
// les deux diffèrent, et la recette du 12/10 l'a montré : la confiance exigeait
// d'exposer l'adresse vue par le core, ce qui cassait l'accès des clients.
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
	"vaultaire/ducky-network/sessionmgr"
)

// Periode est l'intervalle de relecture.
const Periode = 30 * time.Second

var (
	mu       sync.RWMutex
	adresses = map[string]bool{}
	// proprietaires : les identifiants des proxies en ligne, pour reconnaître
	// leurs sessions dans le registre de ce core.
	proprietaires []string
	une           sync.Once
)

// sourcesVivantes rend les adresses des sessions authentifiées d'un proxy dans
// le registre de ce core. Variable : les tests s'en passent.
var sourcesVivantes = func(proprietaire string) []string {
	return sessionmgr.Sessions.AdressesDe(proprietaire)
}

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
	connue := adresses[ip]
	qui := proprietaires
	mu.RUnlock()
	if connue {
		return true
	}
	// Un proxy qui vient de se connecter à CE core, ou dont l'adresse vue a
	// changé depuis la dernière relecture : sa session le dit déjà.
	for _, p := range qui {
		for _, a := range sourcesVivantes(p) {
			if normaliser(a) == ip {
				return true
			}
		}
	}
	return false
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
					if liste, qui, err := lire(base); err == nil {
						Remplacer(liste)
						poserProprietaires(qui)
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

func poserProprietaires(qui []string) {
	mu.Lock()
	proprietaires = qui
	mu.Unlock()
}

// lire rend les adresses de confiance des proxies en ligne et leurs
// identifiants (voir « Quelle adresse »).
func lire(base *sql.DB) ([]string, []string, error) {
	rows, err := base.Query(`SELECT ip_address, adresse_vue, owner_client_id
		FROM cluster_nodes WHERE role = 'proxy' AND status = 'online'`)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	var out, qui []string
	for rows.Next() {
		var declaree, vue, proprietaire string
		if err := rows.Scan(&declaree, &vue, &proprietaire); err != nil {
			return nil, nil, err
		}
		if a := AdresseDeConfiance(declaree, vue); a != "" {
			out = append(out, a)
		}
		if strings.TrimSpace(proprietaire) != "" {
			qui = append(qui, proprietaire)
		}
	}
	return out, qui, rows.Err()
}

// AdresseDeConfiance : l'adresse vue si elle est connue, sinon la déclarée.
// Jamais l'adresse d'exposition (TO-DO 184).
func AdresseDeConfiance(declaree, vue string) string {
	if v := normaliser(vue); v != "" {
		return v
	}
	return normaliser(declaree)
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
