package hosthandler

import (
	"database/sql"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"vaultaire/core/clienttype"
	"vaultaire/core/logs"
	"vaultaire/core/storage"
	"vaultaire/ducky-network/trame"
)

// Les services d'un type, pour le relais HTTPS d'un proxy — 04_15 → 04_16
// (TO-DO 72).
//
// # Pourquoi une trame à part, et pas la 04_04
//
// La 04_04 part vers CHAQUE agent du parc. Y ajouter les Nexus apprendrait à
// tout poste où sont les dépôts — le commentaire de handleListCores refuse
// déjà d'y mettre le JSON des capacités pour la même raison : ne pas décrire
// l'infrastructure à toutes les machines. La 04_15 n'est émise que par un
// vaultaire_proxy (catalogue des types), et seul un relais en a l'usage.
//
// # Le format
//
//	demande  : <type de service>
//	réponse  : <type>\n<nombre>\n<hôte:port>\n…
//
// Le type est RÉPÉTÉ dans la réponse : un proxy qui suit deux types reçoit deux
// réponses, et doit savoir laquelle est laquelle sans compter sur l'ordre
// d'arrivée. Le nombre est vérifié contre les lignes, comme en 04_04.

// ServiceJoignable est une ligne de la réponse.
type ServiceJoignable struct {
	Hostname string
	Adresse  string // hôte:port
	Priorite int
}

// handleListServices : 04_15 -> 04_16.
func handleListServices(db *sql.DB, t storage.Trames_struct_client, content string) (string, error) {
	typ := strings.TrimSpace(strings.SplitN(content, "\n", 2)[0])

	var services []ServiceJoignable
	if typeDeServiceRelayable(typ) {
		var err error
		services, err = servicesEnLigne(db, typ)
		if err != nil {
			logs.Write_LogCode("ERROR", logs.CodeDBQuery,
				"04_15 : services "+typ+" illisibles : "+err.Error())
			services = nil
		}
	} else {
		// Pas de refus de connexion : le type est une donnée de configuration
		// du proxy, pas une tentative. Une liste vide, et une ligne qui dit
		// pourquoi — c'est ici qu'on la cherchera.
		logs.Write_Log("WARNING", fmt.Sprintf(
			"04_15 : %s demande les services de type %q, qui n'est pas un service relayable",
			t.ClientSoftwareID, typ))
	}

	contenu := []string{typ, strconv.Itoa(len(services))}
	for _, s := range services {
		contenu = append(contenu, s.Adresse)
	}
	return trame.ReponseClient("04_16", t.Destination_Server, t.SessionIntegritykey, contenu...), nil
}

// typeDeServiceRelayable : un type de service du catalogue, sauf le proxy.
//
// Le proxy ne s'enregistre pas comme service (il déclare une machine, 04_01),
// et relayer vers un proxy pourrait boucler.
func typeDeServiceRelayable(typ string) bool {
	return typ != clienttype.Proxy && clienttype.IsService(typ)
}

// servicesEnLigne lit les services d'un type en ligne et exposés.
//
// `expose_aux_agents` est respecté : c'est le geste qui retire un nœud de la
// rotation — maintenance d'un Nexus, dépôt pas encore synchronisé.
func servicesEnLigne(db *sql.DB, typ string) ([]ServiceJoignable, error) {
	if db == nil {
		return nil, fmt.Errorf("connexion base indisponible")
	}
	rows, err := db.Query(`SELECT hostname, ip_address, priorite FROM cluster_nodes
		WHERE role = ? AND status = 'online' AND expose_aux_agents = TRUE`, typ)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []ServiceJoignable
	for rows.Next() {
		var s ServiceJoignable
		var point string
		if err := rows.Scan(&s.Hostname, &point, &s.Priorite); err != nil {
			return nil, err
		}
		adresse, err := AdresseDeService(point)
		if err != nil {
			logs.Write_Log("WARNING", fmt.Sprintf(
				"04_15 : service %s écarté, point d'accès %q inutilisable : %v", s.Hostname, point, err))
			continue
		}
		s.Adresse = adresse
		out = append(out, s)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	TrierServices(out)
	return out, nil
}

// AdresseDeService rend « hôte:port » depuis le point d'accès déclaré en 04_09.
//
// Un Nexus déclare son URL publique (« https://nexus.acme.lan:8843 ») : c'est
// ce qu'un humain lit. Le relais, lui, compose une connexion TCP. Sans port,
// celui du schéma : 443 pour https, 80 pour http. Un point d'accès déjà sous
// la forme hôte:port est gardé tel quel.
func AdresseDeService(point string) (string, error) {
	point = strings.TrimSpace(point)
	if point == "" {
		return "", fmt.Errorf("point d'accès vide")
	}
	if !strings.Contains(point, "://") {
		if h, p, err := net.SplitHostPort(point); err == nil && h != "" && p != "" {
			return net.JoinHostPort(h, p), nil
		}
		return "", fmt.Errorf("ni URL ni hôte:port")
	}
	u, err := url.Parse(point)
	if err != nil {
		return "", err
	}
	hote, port := u.Hostname(), u.Port()
	if hote == "" {
		return "", fmt.Errorf("URL sans hôte")
	}
	if port == "" {
		switch strings.ToLower(u.Scheme) {
		case "https":
			port = "443"
		case "http":
			port = "80"
		default:
			return "", fmt.Errorf("schéma %q sans port par défaut", u.Scheme)
		}
	}
	return net.JoinHostPort(hote, port), nil
}

// TrierServices ordonne les services : priorité explicite croissante, puis
// les services sans priorité (0), puis le nom.
//
// Un ORDRE FIXE, sans rotation : garder le même client sur le même dépôt évite
// de promener un « docker pull » entre deux Nexus pas encore synchronisés. La
// règle du zéro est celle de cluster_nodes.priorite pour les cores.
func TrierServices(s []ServiceJoignable) {
	sort.SliceStable(s, func(i, j int) bool {
		pi, pj := s[i].Priorite, s[j].Priorite
		if (pi == 0) != (pj == 0) {
			return pi != 0
		}
		if pi != pj {
			return pi < pj
		}
		return s[i].Hostname < s[j].Hostname
	})
}
