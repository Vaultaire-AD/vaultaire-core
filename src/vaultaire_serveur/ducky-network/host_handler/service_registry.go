package hosthandler

// Enregistrement d'un client SERVICE dans le cluster — trames 04_09 à 04_14.
//
// # Pourquoi ne pas réutiliser 04_01
//
// `register_host` déclare une MACHINE : hostname, fqdn, ip, role, domaine. Un
// service déclare une FONCTION : son type, sa version, son point d'accès. Ce ne
// sont pas les mêmes données, et les confondre coûterait plus que la duplication
// de quelques lignes.
//
// Il y a une seconde raison, plus importante : la restriction par sous-trame
// resterait sans effet. Un `vaultaire_proxy` peut émettre 04_01 mais pas 04_09 ;
// pour l'interface web c'est l'inverse. Un enregistrement unique effacerait cette
// distinction et rendrait le catalogue moins précis qu'il ne peut l'être.

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"vaultaire/core/clienttype"
	"vaultaire/core/logs"
	"vaultaire/core/storage"
)

// serviceStaleAfter borne la fraîcheur d'un battement de cœur.
//
// Au-delà, le service est considéré hors ligne. La valeur est délibérément
// supérieure à la période d'émission attendue : marquer hors ligne un service qui
// a raté un seul battement transformerait une latence réseau en incident.
const serviceStaleAfter = 3 * time.Minute

// handleRegisterService : 04_09 -> 04_10, ou 04_11 en cas d'erreur.
//
// Contenu attendu : version\nendpoint\ncapabilities
func handleRegisterService(db *sql.DB, trames storage.Trames_struct_client, content string, session *storage.DuckySession) (string, error) {
	lines := strings.Split(content, "\n")
	if len(lines) < 2 {
		return serviceError(trames, "invalid_request",
			"attendu version, endpoint, puis capacités facultatives"), nil
	}
	version := strings.TrimSpace(lines[0])
	endpoint := strings.TrimSpace(lines[1])
	capabilities := ""
	if len(lines) >= 3 {
		capabilities = strings.TrimSpace(lines[2])
	}
	if version == "" || endpoint == "" {
		return serviceError(trames, "invalid_request", "version et endpoint requis"), nil
	}

	// Le type vient de la SESSION, jamais du contenu de la trame.
	//
	// Il a été figé à la poignée de main, à partir d'un identifiant machine déjà
	// prouvé. Le relire ici depuis la trame laisserait un service déclarer ce
	// qu'il veut être.
	clientType := session.BoundClientType
	if !clienttype.IsService(clientType) {
		logs.Write_Log("SECURITY", fmt.Sprintf(
			"cluster: %s (type %q) tente de s'enregistrer comme service",
			trames.ClientSoftwareID, clientType))
		return serviceError(trames, "unknown_service", "ce type de client n'est pas un service"), nil
	}

	// capabilities est de l'INVENTAIRE, pas un droit.
	//
	// Ce qu'un service peut émettre est décidé par son type au catalogue. Un
	// champ déclaratif qui accorderait quoi que ce soit serait une élévation de
	// privilèges offerte au client.
	capsJSON, err := encodeCapabilities(capabilities)
	if err != nil {
		return serviceError(trames, "invalid_request", "capacités illisibles"), nil
	}

	// hostname et fqdn portent l'identifiant machine du service : c'est la seule
	// chose qui l'identifie de façon stable, et les deux colonnes sont uniques.
	hostname := trames.ClientSoftwareID
	if _, err := db.Exec(
		`INSERT INTO cluster_nodes
		   (hostname, fqdn, ip_address, role, status, version_code, capabilities, last_heartbeat)
		 VALUES (?, ?, ?, ?, 'online', ?, ?, ?)
		 ON DUPLICATE KEY UPDATE
		   ip_address     = VALUES(ip_address),
		   role           = VALUES(role),
		   status         = 'online',
		   version_code   = VALUES(version_code),
		   capabilities   = VALUES(capabilities),
		   last_heartbeat = VALUES(last_heartbeat)`,
		hostname, hostname, endpoint, clientType, version, capsJSON, time.Now().UTC()); err != nil {
		logs.Write_LogCode("ERROR", logs.CodeDBQuery, "cluster: enregistrement de service échoué : "+err.Error())
		return serviceError(trames, "server_error", "enregistrement impossible"), nil
	}

	logs.Write_Log("INFO", fmt.Sprintf(
		"cluster: service %s (%s) enregistré en version %s sur %s",
		hostname, clientType, version, endpoint))

	return fmt.Sprintf("04_10\n%s\n%s\n%s\n%s",
		trames.Destination_Server, trames.SessionIntegritykey, hostname, clientType), nil
}

// handleServiceHeartbeat : 04_12 -> 04_13.
//
// Un service qui cesse de battre est marqué hors ligne au prochain balayage.
// Sans ce signal, un arrêt ne se découvrirait qu'au premier appel qui échoue,
// c'est-à-dire par l'utilisateur plutôt que par l'exploitant.
func handleServiceHeartbeat(db *sql.DB, trames storage.Trames_struct_client, session *storage.DuckySession) (string, error) {
	if !clienttype.IsService(session.BoundClientType) {
		return serviceError(trames, "unknown_service", "ce type de client n'est pas un service"), nil
	}

	res, err := db.Exec(
		`UPDATE cluster_nodes
		    SET last_heartbeat = ?, status = 'online'
		  WHERE hostname = ?`,
		time.Now().UTC(), trames.ClientSoftwareID)
	if err != nil {
		logs.Write_LogCode("ERROR", logs.CodeDBQuery, "cluster: battement de cœur échoué : "+err.Error())
		return serviceError(trames, "server_error", "battement non enregistré"), nil
	}
	if n, _ := res.RowsAffected(); n == 0 {
		// Le service bat sans s'être enregistré : le core a peut-être été
		// réinstallé sous lui. On le lui dit plutôt que d'ignorer, pour qu'il
		// rejoue son 04_09 au lieu de battre dans le vide indéfiniment.
		return serviceError(trames, "unknown_service", "service non enregistré, rejouez 04_09"), nil
	}

	return fmt.Sprintf("04_13\n%s\n%s", trames.Destination_Server, trames.SessionIntegritykey), nil
}

// handleDeregisterService : 04_14, sans réponse.
//
// Sortie propre à l'arrêt. Sans elle, un arrêt planifié serait indistinguable
// d'une panne pendant toute la fenêtre de battement de cœur.
func handleDeregisterService(db *sql.DB, trames storage.Trames_struct_client, session *storage.DuckySession) (string, error) {
	if !clienttype.IsService(session.BoundClientType) {
		return "", nil
	}
	if _, err := db.Exec(
		`UPDATE cluster_nodes SET status = 'offline' WHERE hostname = ?`,
		trames.ClientSoftwareID); err != nil {
		logs.Write_LogCode("ERROR", logs.CodeDBQuery, "cluster: sortie de service échouée : "+err.Error())
		return "", nil
	}
	logs.Write_Log("INFO", "cluster: service "+trames.ClientSoftwareID+" sorti proprement")
	return "", nil
}

// MarkStaleServicesOffline bascule hors ligne les services qui ne battent plus.
//
// Appelée périodiquement. Le passage hors ligne est fait par le SERVEUR et non
// déduit à la lecture : une vue calculée à la volée donnerait une réponse
// différente selon l'instant de la requête, et l'historique ne garderait aucune
// trace du moment où le service a cessé de répondre.
func MarkStaleServicesOffline(db *sql.DB) error {
	if db == nil {
		return fmt.Errorf("connexion base indisponible")
	}
	cutoff := time.Now().UTC().Add(-serviceStaleAfter)
	res, err := db.Exec(
		`UPDATE cluster_nodes
		    SET status = 'offline'
		  WHERE status = 'online' AND last_heartbeat < ?`, cutoff)
	if err != nil {
		return fmt.Errorf("balayage des services hors ligne : %w", err)
	}
	if n, _ := res.RowsAffected(); n > 0 {
		logs.Write_Log("WARNING", fmt.Sprintf(
			"cluster: %d service(s) basculé(s) hors ligne, sans battement depuis %s", n, serviceStaleAfter))
	}
	return nil
}

// encodeCapabilities normalise les capacités déclarées en JSON.
//
// Accepte une liste séparée par des virgules — la forme attendue — ou du JSON
// déjà formé, pour qu'un service qui en produit naturellement n'ait pas à le
// défaire. La colonne est de type JSON : y écrire autre chose ferait échouer
// l'insertion sur MariaDB.
func encodeCapabilities(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "[]", nil
	}
	if strings.HasPrefix(raw, "[") || strings.HasPrefix(raw, "{") {
		if !json.Valid([]byte(raw)) {
			return "", fmt.Errorf("JSON invalide")
		}
		return raw, nil
	}
	var caps []string
	for _, part := range strings.Split(raw, ",") {
		if p := strings.TrimSpace(part); p != "" {
			caps = append(caps, p)
		}
	}
	encoded, err := json.Marshal(caps)
	if err != nil {
		return "", err
	}
	return string(encoded), nil
}

// serviceError construit une trame 04_11.
func serviceError(trames storage.Trames_struct_client, code, message string) string {
	return fmt.Sprintf("04_11\n%s\n%s\n%s\n%s",
		trames.Destination_Server, trames.SessionIntegritykey, code, message)
}
