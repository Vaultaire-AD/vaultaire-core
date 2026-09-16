package hosthandler

// Purge des services définitivement partis.
//
// # Deux étapes, et pas une seule
//
// Un service qui cesse de battre passe d'abord HORS LIGNE — c'est
// MarkStaleServicesOffline, après quelques minutes. Il disparaît des vues du
// cluster mais son client reste intact : un redémarrage d'hôte, une coupure
// réseau ou une maintenance le ramènent sans qu'il ait rien perdu.
//
// Ce n'est qu'après un délai bien plus long, configurable, que la SUPPRESSION
// intervient : la ligne cluster_nodes et le client lui-même. Le service devra
// alors se réenrôler avec une nouvelle clé.
//
// Les deux étapes existent parce qu'elles répondent à deux questions
// différentes. « Est-ce que ce service répond en ce moment ? » se pose en
// minutes et n'a aucune conséquence. « Est-ce que ce service existe encore ? »
// se pose en heures et détruit une identité — mélanger les deux ferait d'une
// coupure réseau de dix minutes la perte d'un enrôlement.

import (
	"database/sql"
	"fmt"
	"strings"
	"time"

	"vaultaire/core/clienttype"
	dbclients "vaultaire/core/database/db_clients"
	dbsettings "vaultaire/core/database/db_settings"
	"vaultaire/core/logs"
)

// SettingServicePurgeHours est le délai avant qu'un service hors ligne soit
// considéré comme définitivement parti.
const SettingServicePurgeHours = "service_purge_hours"

// Bornes et défaut du délai de purge.
//
// 24 heures par défaut : cela absorbe un redémarrage d'hôte, une coupure
// prolongée ou une maintenance nocturne sans rien détruire, tout en évitant
// qu'un service réellement retiré ne traîne indéfiniment dans l'annuaire.
//
// 0 DÉSACTIVE la purge. C'est une sortie volontaire : un parc où les services
// sont créés et détruits à la main n'a aucune raison de subir une suppression
// automatique, et il vaut mieux la débrayer explicitement que la contourner en
// mettant une valeur absurde.
const (
	PurgeHoursDefault = 24
	PurgeHoursMin     = 0
	PurgeHoursMax     = 24 * 365
)

// PurgeDelay retourne le délai configuré, ou zéro si la purge est désactivée.
func PurgeDelay(db *sql.DB) time.Duration {
	hours := dbsettings.GetInt(db, SettingServicePurgeHours,
		PurgeHoursMin, PurgeHoursMax, PurgeHoursDefault)
	return time.Duration(hours) * time.Hour
}

// SetPurgeDelay écrit le délai de purge.
func SetPurgeDelay(db *sql.DB, hours int, updatedBy string) error {
	return dbsettings.SetInt(db, SettingServicePurgeHours, hours,
		PurgeHoursMin, PurgeHoursMax, updatedBy)
}

// PurgeDepartedServices supprime les services sans battement depuis le délai.
//
// La suppression porte sur la ligne cluster_nodes ET sur le client : c'est le
// même départ, et n'en retirer qu'une moitié laisserait soit une machine
// fantôme dans l'annuaire, soit un client dont plus rien ne dit à quoi il sert.
//
// # Pourquoi le filtre sur le rôle
//
// cluster_nodes mélange deux populations. Les HÔTES s'y enregistrent en 04_01
// avec un rôle libre — « proxy », « api » —, les SERVICES en 04_09 avec leur
// type de client comme rôle. Seuls les seconds sont des clients au sens de
// l'annuaire : supprimer un hôte de la même façon retirerait une ligne
// id_logiciels qui ne lui correspond pas, ou pire, celle d'un homonyme.
//
// Le filtre porte donc sur la liste des types de service du catalogue, qui est
// exactement l'ensemble des rôles écrits par 04_09.
func PurgeDepartedServices(db *sql.DB) error {
	if db == nil {
		return fmt.Errorf("connexion base indisponible")
	}
	delay := PurgeDelay(db)
	if delay <= 0 {
		return nil // purge désactivée
	}

	serviceTypes := clienttype.ServiceNames()
	if len(serviceTypes) == 0 {
		return nil
	}
	placeholders := strings.TrimSuffix(strings.Repeat("?,", len(serviceTypes)), ",")
	args := make([]any, 0, len(serviceTypes)+1)
	for _, t := range serviceTypes {
		args = append(args, t)
	}
	args = append(args, time.Now().UTC().Add(-delay))

	// On relève les candidats AVANT de supprimer : il faut leur identifiant pour
	// retirer aussi le client, et un DELETE ne le rend pas.
	rows, err := db.Query(
		`SELECT hostname FROM cluster_nodes
		  WHERE role IN (`+placeholders+`)
		    AND status = 'offline'
		    AND last_heartbeat < ?`, args...)
	if err != nil {
		return fmt.Errorf("relevé des services partis : %w", err)
	}
	var departed []string
	for rows.Next() {
		var hostname string
		if err := rows.Scan(&hostname); err != nil {
			closeRows(rows)
			return fmt.Errorf("lecture d'un service parti : %w", err)
		}
		departed = append(departed, hostname)
	}
	if err := rows.Err(); err != nil {
		closeRows(rows)
		return fmt.Errorf("parcours des services partis : %w", err)
	}
	closeRows(rows)

	for _, hostname := range departed {
		// La ligne cluster d'abord. Si la suppression du client échoue ensuite,
		// le service disparaît des vues mais son identité subsiste : il pourra
		// se reconnecter et se réenregistrer. L'ordre inverse laisserait une
		// ligne cluster pointant vers un client qui n'existe plus.
		if _, err := db.Exec(`DELETE FROM cluster_nodes WHERE hostname = ?`, hostname); err != nil {
			logs.Write_LogCode("ERROR", logs.CodeDBQuery,
				"cluster: suppression de la ligne de "+hostname+" échouée : "+err.Error())
			continue
		}
		if err := dbclients.Command_DELETE_ClientWithComputeurID(db, hostname); err != nil {
			logs.Write_Log("WARNING", fmt.Sprintf(
				"cluster: service %s retiré du cluster mais son client subsiste : %v", hostname, err))
			continue
		}
		logs.Write_Log("SECURITY", fmt.Sprintf(
			"cluster: service %s supprimé — sans battement de cœur depuis %s. "+
				"Il devra se réenrôler avec une nouvelle clé.", hostname, delay))
	}
	return nil
}

func closeRows(rows *sql.Rows) {
	if err := rows.Close(); err != nil {
		logs.Write_Log("ERROR", "cluster: fermeture du curseur : "+err.Error())
	}
}
