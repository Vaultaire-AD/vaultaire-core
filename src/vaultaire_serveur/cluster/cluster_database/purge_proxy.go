package clusterdatabase

import (
	"database/sql"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

// Purge d'un proxy en maintenance — TO-DO 176.
//
// # Ce qu'un proxy « tient », et qui peut le fermer
//
// Un proxy ne tient aucune session Ducky à lui : il relaie, en TCP, celles des
// machines qui l'ont choisi. Ces sessions vivent dans la mémoire des CORES
// derrière lui, chacune avec, pour adresse source, celle du proxy. La purge
// d'un proxy est donc faite par CHAQUE core, sur la part de ses sessions qui
// arrive par ce proxy — avec le même purgeur que celle d'un core (TO-DO 147).
//
// # Par quelle adresse on les reconnaît
//
// Celle que le proxy déclare (ip_address) est souvent celle de son réseau
// Docker ; celle que le core VOIT est la source TCP de la connexion par
// laquelle il bat — adresse_vue, réécrite à chaque battement. Les deux sont
// essayées, plus, côté core, celles de la session de contrôle du proxy dans
// son propre registre.

// FenetrePurgeProxy : combien de temps une demande de purge de proxy reste à
// exécuter. Chaque core la voit à son battement (trente secondes), attend la
// grâce (une minute) puis étale (une minute par défaut) : un quart d'heure
// couvre un battement manqué et l'étalement maximal de la commande.
const FenetrePurgeProxy = 15 * time.Minute

// NoterAdresseVue écrit l'adresse source par laquelle un nœud vient de battre.
//
// Seulement si elle change : le battement revient toutes les trente secondes
// sur chaque nœud, une écriture identique ne dirait rien.
func NoterAdresseVue(db *sql.DB, proprietaire, adresse string) error {
	if db == nil || strings.TrimSpace(proprietaire) == "" {
		return nil
	}
	ip := HoteDeLAdresse(adresse)
	if ip == "" {
		return nil
	}
	_, err := db.Exec(`UPDATE cluster_nodes SET adresse_vue = ?
	                    WHERE owner_client_id = ? AND adresse_vue <> ?`, ip, proprietaire, ip)
	return err
}

// HoteDeLAdresse rend l'hôte d'une adresse « hôte:port » — ou l'adresse telle
// quelle, quand elle n'a pas de port.
func HoteDeLAdresse(adresse string) string {
	a := strings.TrimSpace(adresse)
	if a == "" {
		return ""
	}
	if h, _, err := net.SplitHostPort(a); err == nil {
		return h
	}
	return strings.Trim(a, "[]")
}

// PurgeDeProxy : ce qu'un core lit d'une purge de proxy à exécuter.
type PurgeDeProxy struct {
	Hostname     string
	Proprietaire string
	Adresses     []string // déclarée, puis vue — sans vide ni doublon
	// AccesAgents : les « hôte:port » par lesquels les AGENTS joignent le
	// proxy — l'accès exposé, puis l'adresse et le port déclarés (TO-DO 216).
	// La 04_17 de la purge les nomme, pour que l'agent les quitte.
	AccesAgents []string
	Demandee    time.Time
	Etalement   time.Duration
}

// PurgesDeProxiesEnCours rend les purges de proxies demandées depuis moins de
// FenetrePurgeProxy, sur des proxies toujours en maintenance.
//
// Pas de condition sur purge_terminee_le : la fin est écrite par le PREMIER
// core qui termine sa part, et les autres doivent faire la leur. C'est la
// mémoire du processus (cluster/purge.go) qui empêche de rejouer.
func PurgesDeProxiesEnCours(db *sql.DB) ([]PurgeDeProxy, error) {
	if db == nil {
		return nil, nil
	}
	rows, err := db.Query(`SELECT hostname, owner_client_id, ip_address, adresse_vue,
	                              purge_demandee_le, purge_etalement_s,
	                              adresse_publique, ducky_port, port_public
	                         FROM cluster_nodes
	                        WHERE role = 'proxy' AND maintenance = TRUE
	                          AND purge_demandee_le IS NOT NULL
	                          AND purge_demandee_le > DATE_SUB(NOW(), INTERVAL ? SECOND)`,
		int64(FenetrePurgeProxy/time.Second))
	if err != nil {
		return nil, fmt.Errorf("lecture des purges de proxies : %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []PurgeDeProxy
	for rows.Next() {
		var p PurgeDeProxy
		var declaree, vue, publique string
		var etalement, port, portPublic int
		if err := rows.Scan(&p.Hostname, &p.Proprietaire, &declaree, &vue, &p.Demandee, &etalement,
			&publique, &port, &portPublic); err != nil {
			return nil, fmt.Errorf("lecture des purges de proxies : %w", err)
		}
		p.Adresses = adressesDistinctes(declaree, vue)
		p.AccesAgents = AccesPourAgents(declaree, publique, port, portPublic)
		p.Etalement = time.Duration(etalement) * time.Second
		out = append(out, p)
	}
	return out, rows.Err()
}

// AccesPourAgents rend les « hôte:port » sous lesquels un agent peut connaître
// un nœud : l'accès effectif (celui des listes 04_04 — adresse et port publics
// s'ils sont déclarés), puis l'adresse et le port que le nœud déclare lui-même
// (celui d'une liste statique d'installation). Sans doublon ; vide sans port.
func AccesPourAgents(ip, publique string, port, portPublic int) []string {
	adresse := strings.TrimSpace(publique)
	if adresse == "" {
		adresse = strings.TrimSpace(ip)
	}
	effectif := port
	if portPublic > 0 {
		effectif = portPublic
	}
	vus := map[string]bool{}
	var out []string
	ajouter := func(h string, p int) {
		h = strings.TrimSpace(h)
		if h == "" || p <= 0 {
			return
		}
		a := net.JoinHostPort(h, strconv.Itoa(p))
		if !vus[a] {
			vus[a] = true
			out = append(out, a)
		}
	}
	ajouter(adresse, effectif)
	ajouter(ip, port)
	return out
}

func adressesDistinctes(adresses ...string) []string {
	vues := map[string]bool{}
	var out []string
	for _, a := range adresses {
		h := strings.ToLower(HoteDeLAdresse(a))
		if h == "" || vues[h] {
			continue
		}
		vues[h] = true
		out = append(out, h)
	}
	return out
}

// TerminerPartDePurge ajoute la part d'un core au compte d'une purge de proxy.
//
// Chaque core ADDITIONNE ses fermetures ; la date de fin est celle de la
// dernière part écrite. Seulement si la demande est toujours celle-là.
func TerminerPartDePurge(db *sql.DB, hostname string, demandee time.Time, fermees int) error {
	if db == nil {
		return nil
	}
	_, err := db.Exec(`UPDATE cluster_nodes
	                      SET purge_terminee_le = NOW(), purge_fermees = purge_fermees + ?
	                    WHERE hostname = ? AND role = 'proxy' AND purge_demandee_le = ?`,
		fermees, hostname, demandee)
	return err
}
