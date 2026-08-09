package commandcluster

import (
	"fmt"
	"strings"

	"vaultaire/core/action"
	commandaction "vaultaire/core/command/commandaction"
	"vaultaire/core/command/display"
)

// Cluster_Command donne une vue de l'état du cluster.
//
//	cluster list                  tous les nœuds
//	cluster list <role>           nœuds actifs d'un rôle
//	cluster purge-delay           lit le délai de purge
//	cluster purge-delay <heures>  le règle
//
// # Deux droits nouveaux, et pourquoi
//
// La commande empruntait `read:get:client` et `write:update:client` sur « * ».
// Voir l'état du cluster exigeait donc le droit de lire TOUTES les machines de
// TOUS les domaines, et régler le délai de purge emportait celui de les
// modifier. Deux responsabilités très différentes portées par la même clé.
//
// Elle exige maintenant `read:cluster` et `write:cluster`. Ces clés ne sont
// accordées à personne tant qu'on ne les accorde pas : après mise à jour, la
// commande répond « permission refusée » en nommant la clé manquante.
func Cluster_Command(args []string, sender_groupsIDs []int, sender_Username string) string {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		return aide()
	}

	appelant := action.Appelant{Username: sender_Username, GroupIDs: sender_groupsIDs}

	switch args[0] {
	case "purge-delay":
		return purgeDelay(args[1:], appelant)

	case "list":
		p := action.Params{}
		if len(args) > 1 {
			p["role"] = strings.ToLower(args[1])
		}
		res, err := action.Executer("cluster.list_nodes", appelant, p)
		if err != nil {
			return commandaction.MessageDErreur(err)
		}
		d, ok := res.Donnees.(action.NoeudsCluster)
		if !ok || len(d.Noeuds) == 0 {
			return res.Message
		}
		return display.DisplayClusterNodes(d.Role, d.Noeuds)

	default:
		return "Commande cluster invalide. Utilisez « cluster -h »."
	}
}

// purgeDelay lit ou règle le délai avant suppression d'un service parti.
//
// Deux actions distinctes et non un paramètre optionnel : la lecture se
// contente de `read:cluster`, l'écriture exige `write:cluster`. Les confondre
// donnerait à qui consulte le droit de modifier — allonger le délai laisse
// traîner des identités, le raccourcir en détruit plus vite.
func purgeDelay(args []string, appelant action.Appelant) string {
	nom := "cluster.get_purge_delay"
	p := action.Params{}
	if len(args) > 0 {
		nom = "cluster.set_purge_delay"
		p["hours"] = strings.TrimSpace(args[0])
	}

	res, err := action.Executer(nom, appelant, p)
	if err != nil {
		return commandaction.MessageDErreur(err)
	}
	return res.Message
}

func aide() string {
	return fmt.Sprintf(`cluster — supervision du cluster.

  cluster list                  tous les nœuds enregistrés
  cluster list <role>           nœuds actifs d'un rôle
  cluster purge-delay           délai avant suppression d'un service parti
  cluster purge-delay <heures>  règle ce délai (0 désactive la purge)

Un service qui cesse de battre est marqué hors ligne immédiatement. Ce n'est
qu'après le délai ci-dessus que son client est SUPPRIMÉ, et il devra alors se
réenrôler avec une nouvelle clé.

Droits : %s pour consulter, %s pour régler le délai.`,
		"read:cluster", "write:cluster")
}
