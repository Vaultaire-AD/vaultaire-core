package commandcluster

import (
	"database/sql"
	"fmt"
	"strconv"
	"strings"
	clusterdatabase "vaultaire/cluster/cluster_database"
	"vaultaire/core/database"
	"vaultaire/core/logs"
	"vaultaire/core/permission"
	hosthandler "vaultaire/ducky-network/host_handler"
)

// Cluster_Command fournit une vue simple de l'état du cluster via la CLI admin.
//
// Syntaxe:
//
//	cluster -h
//	cluster list
//	cluster list <role>
func Cluster_Command(args []string, sender_groupsIDs []int, sender_Username string) string {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		return `cluster - Commandes de supervision du cluster

cluster list
  Liste tous les nœuds connus.

cluster list core
  Liste uniquement les nœuds de rôle "core".

cluster purge-delay
  Affiche le délai avant suppression d'un service définitivement parti.

cluster purge-delay <heures>
  Modifie ce délai. 0 désactive la purge.

Un service qui cesse de battre passe d'abord HORS LIGNE en quelques minutes :
il disparaît des vues mais garde son identité, un redémarrage le ramène. Ce
n'est qu'après ce délai que son client est SUPPRIMÉ, et il devra alors se
réenrôler avec une nouvelle clé.
`
	}

	actionKey := "read:get:client"
	ok, msg := permission.CheckPermissionsMultipleDomains(sender_groupsIDs, actionKey, []string{"*"})
	if !ok {
		logs.Write_Log("WARNING", fmt.Sprintf("Permission refused: user=%s action=%s reason=%s", sender_Username, actionKey, msg))
		return "Permission refusée : " + msg
	}
	logs.Write_Log("INFO", fmt.Sprintf("Permission used: user=%s action=%s (cluster command)", sender_Username, actionKey))

	db := database.GetDatabase()

	switch args[0] {
	case "purge-delay":
		return purgeDelay(db, args[1:], sender_groupsIDs, sender_Username)

	case "list":
		if len(args) > 1 {
			role := strings.ToLower(args[1])
			nodes, err := clusterdatabase.GetActiveNodesByRole(db, role)
			if err != nil {
				return "Erreur récupération nœuds: " + err.Error()
			}
			if len(nodes) == 0 {
				return "Aucun nœud actif pour le rôle " + role
			}
			var b strings.Builder
			fmt.Fprintf(&b, "Nœuds actifs pour le rôle %s:\n", role)
			for _, n := range nodes {
				fmt.Fprintf(&b, "- %s (%s) [%s] last=%s\n", n.Hostname, n.IPAddress, n.Status, n.LastHeartbeat.Format("15:04:05"))
			}
			return b.String()
		}

		nodes, err := clusterdatabase.GetAllNodes(db)
		if err != nil {
			return "Erreur récupération nœuds: " + err.Error()
		}
		if len(nodes) == 0 {
			return "Aucun nœud dans la table cluster_nodes."
		}
		var b strings.Builder
		b.WriteString("Nœuds du cluster:\n")
		for _, n := range nodes {
			fmt.Fprintf(&b, "- [%s] %s (%s) role=%s version=%s last=%s\n",
				n.Status, n.Hostname, n.IPAddress, n.Role, n.VersionCode, n.LastHeartbeat.Format("15:04:05"))
		}
		return b.String()

	default:
		return "Commande cluster invalide. Utilisez 'cluster -h' pour l'aide."
	}
}

// purgeDelay lit ou écrit le délai avant suppression d'un service parti.
//
// La LECTURE se contente du droit de consultation déjà vérifié plus haut.
// L'ÉCRITURE en exige un autre : allonger le délai laisse traîner des identités,
// le raccourcir en détruit plus vite. C'est une décision qui engage le parc, pas
// une consultation.
func purgeDelay(db *sql.DB, args []string, senderGroupIDs []int, senderUsername string) string {
	if len(args) == 0 {
		delay := hosthandler.PurgeDelay(db)
		if delay <= 0 {
			return "Purge des services désactivée : un service hors ligne conserve son identité indéfiniment."
		}
		return fmt.Sprintf(
			"Délai avant suppression d'un service parti : %s.\n"+
				"Passé ce délai sans battement de cœur, son client est supprimé et il devra se réenrôler.",
			delay)
	}

	hours, err := strconv.Atoi(strings.TrimSpace(args[0]))
	if err != nil {
		return fmt.Sprintf("« %s » n'est pas un nombre d'heures.", args[0])
	}

	const writeAction = "write:update:client"
	ok, reason := permission.CheckPermissionsMultipleDomains(senderGroupIDs, writeAction, []string{"*"})
	if !ok {
		logs.Write_Log("WARNING", fmt.Sprintf(
			"Permission refused: user=%s action=%s (cluster purge-delay) reason=%s",
			senderUsername, writeAction, reason))
		return "Permission refusée : " + reason
	}

	if err := hosthandler.SetPurgeDelay(db, hours, senderUsername); err != nil {
		return "Enregistrement impossible : " + err.Error()
	}
	if hours == 0 {
		return "Purge des services désactivée. Aucun client de service ne sera plus supprimé automatiquement."
	}
	return fmt.Sprintf("Délai porté à %d heure(s).", hours)
}
