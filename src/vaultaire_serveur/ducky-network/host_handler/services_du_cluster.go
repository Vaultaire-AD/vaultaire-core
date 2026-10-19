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
// (TO-DO 72) — et, pour un AGENT, les dépôts de mise à jour (TO-DO 114).
//
// # Pourquoi une trame à part, et pas la 04_04
//
// La 04_04 part vers CHAQUE agent du parc. Y ajouter les Nexus apprendrait à
// tout poste où sont les dépôts — le commentaire de handleListCores refuse
// déjà d'y mettre le JSON des capacités pour la même raison : ne pas décrire
// l'infrastructure à toutes les machines. La 04_15 est une DEMANDE : seul la
// reçoit qui la pose, et le catalogue des types dit qui peut la poser.
//
// # Ce qu'un agent peut demander (TO-DO 114)
//
// Le proxy demande les services de n'importe quel type relayable. L'agent, un
// seul : les Nexus, où il prendra ses paquets de mise à jour. Le reste de la
// carte — les interfaces web, un futur service — ne le regarde pas. Une
// demande d'un autre type rend une liste VIDE et une ligne de journal, comme
// un type inconnu du proxy : ce n'est pas une attaque à refuser bruyamment,
// c'est une demande à laquelle on n'a rien à répondre.
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
func handleListServices(db *sql.DB, t storage.Trames_struct_client, content string,
	session *storage.DuckySession) (string, error) {
	typ := strings.TrimSpace(strings.SplitN(content, "\n", 2)[0])
	demandeur := ""
	if session != nil {
		demandeur = session.BoundClientType
	}

	var services []ServiceJoignable
	if !TypeDemandable(demandeur, typ) {
		logs.Write_Log("WARNING", fmt.Sprintf(
			"04_15 : %s (%s) demande les services de type %q, que ce type de client ne peut pas demander",
			t.ClientSoftwareID, demandeur, typ))
	} else if typeDeServiceRelayable(typ) {
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

// TypeDemandable dit si un client de ce type peut demander les services de ce
// type. Un agent : les Nexus seulement. Les autres types qui ont la 04_15 —
// le proxy — : tout type relayable, filtré ensuite par typeDeServiceRelayable.
// Un demandeur de type inconnu (session sans type lié) : rien.
func TypeDemandable(demandeur, typ string) bool {
	switch demandeur {
	case clienttype.Client:
		return typ == clienttype.Nexus
	case "":
		return false
	}
	return true
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
// rotation — dépôt pas encore synchronisé, par exemple. La maintenance aussi
// (TO-DO 147) : un nœud en maintenance sort de TOUTES les listes.
func servicesEnLigne(db *sql.DB, typ string) ([]ServiceJoignable, error) {
	if db == nil {
		return nil, fmt.Errorf("connexion base indisponible")
	}
	rows, err := db.Query(`SELECT hostname, ip_address, priorite FROM cluster_nodes
		WHERE role = ? AND status = 'online' AND expose_aux_agents = TRUE AND maintenance = FALSE`, typ)
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

// NexusEnrole : un Nexus du cluster, pour le versement des paquets (TO-DO
// 206). Tous, et pas seulement ceux qu'on annonce aux agents : un Nexus qu'on
// synchronise avant de l'exposer doit déjà porter les paquets le jour où il
// entre en rotation.
type NexusEnrole struct {
	Nom          string
	URL          string // https://hôte:port, vide si le point d'accès est inutilisable
	EnLigne      bool
	ExposeAgents bool
	Maintenance  bool
	Probleme     string
}

// NexusDuCluster lit les Nexus enrôlés, triés comme pour les agents.
func NexusDuCluster(db *sql.DB) ([]NexusEnrole, error) {
	if db == nil {
		return nil, fmt.Errorf("connexion base indisponible")
	}
	rows, err := db.Query(`SELECT hostname, ip_address, status, expose_aux_agents, maintenance, priorite
		FROM cluster_nodes WHERE role = ?`, clienttype.Nexus)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	type ligne struct {
		n        NexusEnrole
		priorite int
	}
	var lignes []ligne
	for rows.Next() {
		var l ligne
		var point, statut string
		if err := rows.Scan(&l.n.Nom, &point, &statut, &l.n.ExposeAgents, &l.n.Maintenance, &l.priorite); err != nil {
			return nil, err
		}
		l.n.EnLigne = statut == "online"
		if adresse, err := AdresseDeService(point); err != nil {
			l.n.Probleme = fmt.Sprintf("point d'accès %q inutilisable : %v", point, err)
		} else {
			l.n.URL = "https://" + adresse
		}
		lignes = append(lignes, l)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	sort.SliceStable(lignes, func(i, j int) bool {
		pi, pj := lignes[i].priorite, lignes[j].priorite
		if (pi == 0) != (pj == 0) {
			return pi != 0
		}
		if pi != pj {
			return pi < pj
		}
		return lignes[i].n.Nom < lignes[j].n.Nom
	})
	out := make([]NexusEnrole, 0, len(lignes))
	for _, l := range lignes {
		out = append(out, l.n)
	}
	return out, nil
}
