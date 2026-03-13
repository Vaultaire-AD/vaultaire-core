package commandcluster

import (
	"fmt"
	"strings"
	clusterdatabase "vaultaire/cluster/cluster_database"
	"vaultaire/serveur/database"
	"vaultaire/serveur/logs"
	"vaultaire/serveur/permission"
)

// Cluster_Command fournit une vue simple de l'état du cluster via la CLI admin.
//
// Syntaxe:
//   cluster -h
//   cluster list
//   cluster list <role>
func Cluster_Command(args []string, sender_groupsIDs []int, sender_Username string) string {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		return `cluster - Commandes de supervision du cluster

cluster list
  Liste tous les nœuds connus.

cluster list core
  Liste uniquement les nœuds de rôle "core".
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

