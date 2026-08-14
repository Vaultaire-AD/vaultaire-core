package hosthandler

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	dbgroups "vaultaire/core/database/db_groups"

	clusterdatabase "vaultaire/cluster/cluster_database"
	clusterstorage "vaultaire/cluster/cluster_storage"
	"vaultaire/core/logs"
	"vaultaire/core/storage"
	"vaultaire/ducky-network/sendmessage"
)

// HandleHostTrame traite les trames 04_xx (Cluster / Service discovery) et retourne la réponse à envoyer.
func HandleHostTrame(db *sql.DB, tramesContent storage.Trames_struct_client, duckysession *storage.DuckySession) (string, error) {
	if len(tramesContent.Message_Order) < 2 {
		return "", fmt.Errorf("trame 04 invalide")
	}
	sub := tramesContent.Message_Order[1]
	content := strings.TrimSpace(tramesContent.Content)

	switch sub {
	case "01":
		return handleRegisterHost(db, tramesContent, content)
	case "03":
		return handleListCores(db, tramesContent, duckysession)
	case "05":
		return handleProxyMetrics(db, tramesContent, content, duckysession)
	case "07":
		return handleHostHeartbeat(db, tramesContent, content, duckysession)

	// Clients SERVICE. Distincts de 04_01/04_07, qui déclarent une machine :
	// un service déclare une fonction. Voir service_registry.go.
	case "09":
		return handleRegisterService(db, tramesContent, content, duckysession)
	case "12":
		return handleServiceHeartbeat(db, tramesContent, duckysession)
	case "14":
		return handleDeregisterService(db, tramesContent, duckysession)
	default:
		return "", fmt.Errorf("sous-trame 04_%s non gérée", sub)
	}
}

// handleRegisterHost : 04_01 -> 04_02
//
//	Content : hostname\nfqdn\nip\nrole\ndomain[\nport[\nempreinte]]
//	ex.     : proxy1\nproxy1.vaultaire.fr\n10.0.0.2\nproxy\nproxy.vaultaire.fr\n7070\nSHA256:…
//
// # Le port et l'empreinte sont en QUEUE, et facultatifs
//
// En queue plutôt qu'insérés : un nœud resté à l'ancienne version envoie cinq
// lignes, et les insérer au milieu aurait fait lire son domaine comme un port.
// Facultatifs pour la même raison — leur absence vaut « non déclaré », et le
// nœud est alors omis de la liste distribuée plutôt que d'y figurer avec un port
// deviné ou sans de quoi le reconnaître.
//
// L'empreinte est celle que le nœud sert lui-même aux agents. LUI SEUL peut la
// déclarer : personne d'autre ne détient sa clé privée, donc personne d'autre ne
// saurait dire si elle correspond. Le core ne la vérifie pas — il ne le peut
// pas — il vérifie sa FORME, ce qui suffit à écarter une valeur qui ne
// correspondra jamais à rien.
//
// Un port hors de 1-65535 est REFUSÉ et non corrigé : une valeur aberrante vient
// d'une configuration fausse, et l'accepter en la ramenant à une borne
// produirait un nœud enregistré sur une adresse que personne n'écoute.
func handleRegisterHost(db *sql.DB, tramesContent storage.Trames_struct_client, content string) (string, error) {
	lines := strings.Split(content, "\n")
	if len(lines) < 5 {
		return "", fmt.Errorf("register_host: contenu invalide (attendu hostname, fqdn, ip, role, domain)")
	}
	hostname := strings.TrimSpace(lines[0])
	fqdn := strings.TrimSpace(lines[1])
	ip := strings.TrimSpace(lines[2])
	role := strings.TrimSpace(lines[3])
	domain := strings.TrimSpace(lines[4])
	if hostname == "" || ip == "" || role == "" {
		return "", fmt.Errorf("register_host: hostname, ip et role requis")
	}
	if fqdn == "" {
		fqdn = hostname
	}

	port := 0
	if len(lines) > 5 {
		if texte := strings.TrimSpace(lines[5]); texte != "" {
			p, err := strconv.Atoi(texte)
			if err != nil || p < 1 || p > 65535 {
				return "", fmt.Errorf("register_host: port invalide (%q)", texte)
			}
			port = p
		}
	}
	if port == 0 {
		logs.Write_Log("WARNING", "register_host: "+hostname+
			" ne déclare aucun port — il ne sera pas annoncé aux agents")
	}

	empreinte := ""
	if len(lines) > 6 {
		empreinte = strings.TrimSpace(lines[6])
		if empreinte != "" && !strings.HasPrefix(empreinte, "SHA256:") {
			return "", fmt.Errorf("register_host: empreinte de forme inattendue (%q)", empreinte)
		}
	}
	if empreinte == "" {
		logs.Write_Log("WARNING", "register_host: "+hostname+
			" ne déclare aucune empreinte — il ne sera pas annoncé aux agents, "+
			"qui n'auraient pas de quoi reconnaître sa clé")
	}

	// Les VERSIONS, en huitième et neuvième ligne, facultatives.
	//
	// `version_code` recevait jusqu'ici la chaîne « vaultaire_proxy » écrite en
	// dur ici même : la colonne annonçait une version et portait un type, que
	// `role` porte déjà. Elle reçoit maintenant ce que le nœud déclare de
	// lui-même.
	//
	// Vide = non déclaré, et c'est affiché tel quel. Un nœud dont on ne connaît
	// pas la version est exactement ce qu'on veut repérer avant un déploiement.
	versionNoeud, versionSDK := "", ""
	if len(lines) > 7 {
		versionNoeud = strings.TrimSpace(lines[7])
	}
	if len(lines) > 8 {
		versionSDK = strings.TrimSpace(lines[8])
	}

	// Créer le groupe/domaine si inexistant (ex: proxy.vaultaire.fr)
	groupName := role
	if domain != "" {
		parts := strings.SplitN(domain, ".", 2)
		if len(parts) > 0 && parts[0] != "" {
			groupName = parts[0]
		}
	}
	_, err := dbgroups.GetGroupIDByName(db, groupName)
	if err != nil {
		_, errCreate := dbgroups.CreateGroup(db, groupName, domain)
		if errCreate != nil {
			logs.Write_Log("WARNING", "host_handler: CreateGroup failed: "+errCreate.Error())
		}
	}

	node := clusterstorage.Node{
		Hostname:     hostname,
		FQDN:         fqdn,
		IPAddress:    ip,
		Role:         role,
		Status:       "online",
		VersionCode:  versionNoeud,
		Capabilities: "{}",
		Port:         port,
		Empreinte:    empreinte,
		VersionSDK:   versionSDK,
	}
	if err := clusterdatabase.RegisterNode(db, node); err != nil {
		return "", fmt.Errorf("register_host: %w", err)
	}
	logs.Write_Log("INFO", "host registered: "+hostname+" role="+role+" ip="+ip+
		" port="+strconv.Itoa(port))
	return "04_02\nserver_central\n" + tramesContent.SessionIntegritykey + "\n" + tramesContent.Username + "\n" + tramesContent.ClientSoftwareID + "\nok\n" + hostname, nil
}

// getTramesFromRequest retourne sessionKey, username, clientID pour construire la réponse.
func getTramesFromRequest(t storage.Trames_struct_client) (sessionKey, username, clientID string) {
	return t.SessionIntegritykey, t.Username, t.ClientSoftwareID
}

// handleListCores : 04_03 -> 04_04 (nœuds joignables, dans l'ordre)
//
// # Ce qui a changé
//
// La version antérieure rendait `GetActiveNodesByRole(db, "core")` — les cores
// seuls, sans port, dans l'ordre du plan d'exécution. Trois manques :
//
//   - PAS DE PORT. Une liste d'adresses sans port n'est pas une liste de nœuds
//     joignables : l'agent devait supposer que tout le parc écoute au même
//     endroit ;
//   - PAS DE PROXY. Un proxy déployé n'apparaissait nulle part, donc aucun agent
//     n'y passait, donc il ne servait à rien ;
//   - PAS D'ORDRE. Deux requêtes successives pouvaient rendre deux ordres, et
//     tout le parc basculait ensemble sur un nœud que rien n'avait désigné.
//
// # Le format de ligne
//
//	<hostname>|<ip>|<port>|<role>|<priorite>|<empreinte>
//
// `version_code` et `capabilities` en sont RETIRÉS. Le premier vaut
// « vaultaire_proxy » ou « vaultaire_serveur » — c'est le rôle, déjà présent. Le
// second est un JSON libre que personne ne lit, et qui décrirait l'infrastructure
// à toutes les machines du parc.
//
// L'EMPREINTE, elle, est ce qui rend la découverte utilisable. Sans elle,
// l'agent apprendrait une adresse et devrait accepter la clé de ce nœud en
// aveugle à la première connexion. C'est l'arbitrage 3 : la confiance s'étend
// depuis une confiance existante — cette réponse arrive sur une session dont la
// clé du core a déjà été vérifiée, et ce core atteste ses pairs.
//
// La limite est assumée et écrite : TOUT CORE DE CONFIANCE PEUT AJOUTER DE LA
// CONFIANCE. Un core compromis fait apprendre au parc l'empreinte de son choix
// — mais un core compromis détient déjà les clés du domaine, et l'empreinte
// n'est pas ce qui le retient.
//
// La ligne se lit par position et non par préfixe, contrairement à `03_09` :
// chaque champ est obligatoire et le nombre est fixe, donc rien à reconnaître.
func handleListCores(db *sql.DB, tramesContent storage.Trames_struct_client, duckysession *storage.DuckySession) (string, error) {
	nodes, err := clusterdatabase.NoeudsPourAgents(db)
	if err != nil {
		return "", err
	}

	lines := make([]string, 0, len(nodes))
	for _, n := range nodes {
		lines = append(lines, fmt.Sprintf("%s|%s|%d|%s|%d|%s",
			n.Hostname, n.IPAddress, n.Port, n.Role, n.Priorite, n.Empreinte))
	}
	body := strings.Join(lines, "\n")

	if len(nodes) == 0 {
		// Une liste vide n'est pas une erreur, mais elle mérite d'être dite : sur
		// un parc en service, elle signifie qu'aucun nœud n'a déclaré son port —
		// donc que la migration de schéma est passée sans qu'aucun cœur ne se
		// soit réenregistré depuis. C'est exactement ce qu'on cherchera quand les
		// agents ne trouveront personne.
		logs.Write_Log("WARNING",
			"04_04 : aucun nœud joignable à annoncer à "+tramesContent.ClientSoftwareID+
				" (aucun en ligne, exposé, avec un port ET une empreinte déclarés)")
	}

	sk, un, cid := getTramesFromRequest(tramesContent)
	return "04_04\nserver_central\n" + sk + "\n" + un + "\n" + cid + "\n" + strconv.Itoa(len(nodes)) + "\n" + body, nil
}

// handleProxyMetrics : 04_05 -> 04_06 (enregistrement en BDD proxy_metrics)
// Content: proxy_hostname\nproxy_ip\nmetric_type\nmetric_value\nextra_json
func handleProxyMetrics(db *sql.DB, tramesContent storage.Trames_struct_client, content string, duckysession *storage.DuckySession) (string, error) {
	lines := strings.Split(content, "\n")
	if len(lines) < 4 {
		return "", fmt.Errorf("proxy_metrics: contenu invalide")
	}
	proxyHostname := strings.TrimSpace(lines[0])
	proxyIP := strings.TrimSpace(lines[1])
	metricType := strings.TrimSpace(lines[2])
	metricValueStr := strings.TrimSpace(lines[3])
	extraJSON := ""
	if len(lines) > 4 {
		extraJSON = strings.TrimSpace(strings.Join(lines[4:], "\n"))
	}
	metricValue, err := strconv.ParseFloat(metricValueStr, 64)
	if err != nil {
		return "", fmt.Errorf("proxy_metrics: metric_value invalide: %s", metricValueStr)
	}
	_, err = db.Exec(
		`INSERT INTO proxy_metrics (proxy_hostname, proxy_ip, metric_type, metric_value, extra) VALUES (?, ?, ?, ?, ?)`,
		proxyHostname, proxyIP, metricType, metricValue, emptyOrJSON(extraJSON),
	)
	if err != nil {
		return "", err
	}
	clientID := tramesContent.ClientSoftwareID
	return "04_06\nserver_central\n" + tramesContent.SessionIntegritykey + "\n" + tramesContent.Username + "\n" + clientID + "\nack", nil
}

func emptyOrJSON(s string) interface{} {
	if s == "" {
		return nil
	}
	var j json.RawMessage
	if json.Unmarshal([]byte(s), &j) != nil {
		return nil
	}
	return s
}

// handleHostHeartbeat : 04_07 -> 04_08 (mise à jour last_heartbeat par hostname ou IP)
// Content: hostname (ou ip en fallback)
func handleHostHeartbeat(db *sql.DB, tramesContent storage.Trames_struct_client, content string, duckysession *storage.DuckySession) (string, error) {
	hostname := strings.TrimSpace(content)
	if hostname == "" {
		return "", fmt.Errorf("heartbeat: hostname vide")
	}
	if err := clusterdatabase.UpdateHeartbeat(db, hostname); err != nil {
		return "", err
	}
	clientID := tramesContent.ClientSoftwareID
	return "04_08\nserver_central\n" + tramesContent.SessionIntegritykey + "\n" + tramesContent.Username + "\n" + clientID + "\nack", nil
}

// SendHostResponse envoie la réponse 04_xx au client.
func SendHostResponse(response string, tramesContent storage.Trames_struct_client, duckysession *storage.DuckySession) error {
	return sendmessage.SendMessage(response, tramesContent.ClientSoftwareID, duckysession)
}
