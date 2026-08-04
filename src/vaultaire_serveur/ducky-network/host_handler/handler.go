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
	default:
		return "", fmt.Errorf("sous-trame 04_%s non gérée", sub)
	}
}

// handleRegisterHost : 04_01 -> 04_02
// Content: hostname\nfqdn\nip\nrole\ndomain (ex: proxy1\nproxy1.vaultaire.fr\n10.0.0.2\nproxy\nproxy.vaultaire.fr)
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
		VersionCode:  "vaultaire_proxy",
		Capabilities: "{}",
	}
	if err := clusterdatabase.RegisterNode(db, node); err != nil {
		return "", fmt.Errorf("register_host: %w", err)
	}
	logs.Write_Log("INFO", "host registered: "+hostname+" role="+role+" ip="+ip)
	return "04_02\nserver_central\n" + tramesContent.SessionIntegritykey + "\n" + tramesContent.Username + "\n" + tramesContent.ClientSoftwareID + "\nok\n" + hostname, nil
}

// getTramesFromRequest retourne sessionKey, username, clientID pour construire la réponse.
func getTramesFromRequest(t storage.Trames_struct_client) (sessionKey, username, clientID string) {
	return t.SessionIntegritykey, t.Username, t.ClientSoftwareID
}

// handleListCores : 04_03 -> 04_04 (liste des Cores en ligne)
func handleListCores(db *sql.DB, tramesContent storage.Trames_struct_client, duckysession *storage.DuckySession) (string, error) {
	nodes, err := clusterdatabase.GetActiveNodesByRole(db, "core")
	if err != nil {
		return "", err
	}
	var lines []string
	for _, n := range nodes {
		lines = append(lines, fmt.Sprintf("%s|%s|%s|%s", n.Hostname, n.IPAddress, n.VersionCode, n.Capabilities))
	}
	body := strings.Join(lines, "\n")
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
