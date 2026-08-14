package display

import (
	"strings"

	clusterstorage "vaultaire/cluster/cluster_storage"
)

// DisplayClusterNodes affiche les nœuds du cluster.
//
// L'ancienne version bâtissait ses lignes à la main avec fmt.Fprintf et des
// tirets : les colonnes ne s'alignaient pas dès qu'un nom d'hôte dépassait ses
// voisins. Le module table.go calcule les largeurs sur le contenu.
func DisplayClusterNodes(role string, noeuds []clusterstorage.Node) string {
	if len(noeuds) == 0 {
		if role != "" {
			return "Aucun nœud actif pour le rôle " + role + ".\n"
		}
		return "Aucun nœud dans le cluster.\n"
	}

	tb := NouvelleTable("ÉTAT", "HÔTE", "ADRESSE", "RÔLE", "VERSION", "SDK", "DERNIER BATTEMENT")
	for _, n := range noeuds {
		tb.Ajouter(
			Valeur(n.Status),
			Valeur(n.Hostname),
			Valeur(n.IPAddress),
			Valeur(n.Role),
			// VERSION porte désormais ce que le nœud DÉCLARE de lui-même. Elle
			// contenait la chaîne « vaultaire_proxy » écrite en dur côté core,
			// c'est-à-dire le type — que la colonne RÔLE affiche déjà.
			Valeur(n.VersionCode),
			// SDK est vide pour un core : il n'embarque pas le socle réseau.
			// Une colonne vide sur cette ligne-là est donc juste, et non un
			// manque.
			Valeur(n.VersionSDK),
			// Heure seule et non date complète : les battements se comptent en
			// secondes, et une date entière noierait l'information utile.
			n.LastHeartbeat.Format("15:04:05"),
		)
	}

	titre := "Nœuds du cluster"
	if role != "" {
		titre = "Nœuds actifs pour le rôle " + strings.TrimSpace(role)
	}
	return titre + "\n\n" + tb.String()
}
