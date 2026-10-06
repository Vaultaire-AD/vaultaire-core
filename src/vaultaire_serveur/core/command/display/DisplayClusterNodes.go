package display

import (
	"fmt"
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

	tb := NouvelleTable("ÉTAT", "HÔTE", "ACCÈS AGENTS", "VU PAR LE NŒUD", "ROT.",
		"SERT EN PRIORITÉ", "RÔLE", "RELAIS", "TRAFIC", "VERSION", "SDK",
		"DERNIER BATTEMENT")
	for _, n := range noeuds {
		// Deux colonnes d'adresse, et c'est le point de la vue.
		//
		// ACCÈS AGENTS est ce que le parc reçoit ; VU PAR LE NŒUD est ce que la
		// machine croit être. N'en montrer qu'une obligerait à choisir entre
		// « ce qui est distribué » et « ce que la machine rapporte », alors que
		// c'est précisément leur ÉCART qu'on cherche quand une connexion ne
		// passe pas.
		//
		// La seconde colonne n'est remplie que lorsqu'elle diffère : la répéter
		// sur tous les nœuds correctement adressés — le cas courant — noierait
		// les quelques lignes où elle dit quelque chose.
		acces := clusterstorage.AdresseAffichee(n.AdresseEffective(), n.PortEffectif())
		if n.ExpositionDeclaree() {
			acces += " *"
		}
		interne := ""
		if n.ExpositionDeclaree() {
			interne = clusterstorage.AdresseAffichee(n.IPAddress, n.Port)
		}

		tb.Ajouter(
			Valeur(n.Status),
			Valeur(n.Hostname),
			Valeur(acces),
			Valeur(interne),
			// Un nœud hors rotation reste EN LIGNE et n'est annoncé à personne.
			// Sans cette colonne, il se lit comme parfaitement sain dans la
			// vue, et on cherche ailleurs pourquoi les agents ne l'atteignent
			// jamais.
			Valeur(rotationLisible(n.ExposeAuxAgents)),
			// Vide vaut « tout le parc, sans préférence » : c'est le cas d'un
			// nœud sans affinité, et l'écrire sur chaque ligne d'un cluster
			// mono-site remplirait la colonne de bruit.
			Valeur(strings.Join(n.GroupesAffins, ", ")),
			Valeur(n.Role),
			// RELAIS et TRAFIC : ce que le nœud a remonté de lui-même
			// (04_05, TO-DO 108).
			//
			// Vides sur un core — il ne relaie rien — et sur un proxy dont la
			// dernière mesure est trop ancienne. Une mesure périmée affichée
			// sans son âge se lirait comme l'état courant.
			Valeur(relaisLisible(n.Relais)),
			Valeur(traficLisible(n.Relais)),
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

	legende := "\n* adresse déclarée par un administrateur — c'est elle que reçoivent les agents.\n" +
		"  « VU PAR LE NŒUD » n'est renseigné que lorsqu'il diffère.\n" +
		"  ROT. « out » : le nœud n'est annoncé à aucun agent (vlt cluster rotation <nœud> in).\n" +
		"  « SERT EN PRIORITÉ » vide = tout le parc, sans préférence. C'est une préférence\n" +
		"  et non une exclusivité : les agents des autres groupes gardent ce nœud, en queue.\n" +
		"  RELAIS « a/t » : connexions actives / relayées depuis le démarrage du proxy ;\n" +
		"  « ✗n » compte celles qui ne sont pas passées (aucune cible joignable, ou plafond).\n" +
		"  RELAIS et TRAFIC vides : ce nœud ne relaie rien, ou n'a rien remonté depuis\n" +
		"  plus de trois minutes. Ces mesures sont MONTRÉES, elles n'ordonnent pas la liste\n" +
		"  servie aux agents — un nœud décide de ce qu'il déclare.\n"

	return titre + "\n\n" + tb.String() + legende
}

// relaisLisible rend les connexions d'un nœud en une colonne étroite.
//
//	« 3/128 »      trois connexions en cours, cent vingt-huit depuis le démarrage
//	« 3/128 ✗7 »   et sept qui ne sont pas passées
//
// Le compteur d'écarts n'apparaît QUE s'il est non nul : un « ✗0 » sur chaque
// ligne d'un cluster sain noierait les rares lignes où il dit quelque chose.
func relaisLisible(m *clusterstorage.MetriquesRelais) string {
	if m == nil {
		return ""
	}
	ligne := fmt.Sprintf("%d/%d", m.Actives, m.Total)
	if ecartees := m.Ecartees(); ecartees > 0 {
		ligne += fmt.Sprintf(" ✗%d", ecartees)
	}
	return ligne
}

// traficLisible rend le trafic cumulé des deux sens.
//
// Les deux sens ensemble : le détail montant/descendant tient dans la fiche du
// nœud, et deux colonnes de plus dans une table qui en porte déjà douze la
// rendraient illisible sur un terminal ordinaire.
func traficLisible(m *clusterstorage.MetriquesRelais) string {
	if m == nil {
		return ""
	}
	return clusterstorage.OctetsLisibles(m.Octets())
}

// rotationLisible rend l'appartenance à la rotation en deux caractères.
//
// « in » / « out » plutôt que « oui » / « non » : la colonne répond à « est-il
// dans la liste servie », pas à « est-il exposé sur le réseau ». Le second sens
// ferait croire à un contrôle d'accès, ce que ce drapeau n'est pas.
func rotationLisible(expose bool) string {
	if expose {
		return "in"
	}
	return "out"
}
