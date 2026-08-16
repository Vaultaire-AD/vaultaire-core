package display

import (
	"strconv"
	"strings"

	clusterdatabase "vaultaire/cluster/cluster_database"
	clusterstorage "vaultaire/cluster/cluster_storage"
)

// DisplayCiblesClient rend, dans l'ordre, les nœuds qu'une machine joindra.
//
// # Ce que cette vue répond
//
// « Cette machine ne joint pas le bon proxy — pourquoi ? »
//
// L'ordre dépend de quatre critères et trois filtres, aucun visible depuis la
// machine. Sans cette vue, il faut lire l'état du cluster, les groupes du poste
// et les affinités de chaque nœud, puis refaire le tri de tête — c'est-à-dire
// refaire à la main le calcul dont on cherche l'erreur.
//
// # Pourquoi la liste des ÉCARTÉS est affichée aussi
//
// Un nœud écarté ne laisse aucune trace : il n'apparaît simplement pas. Quand un
// proxy fraîchement déployé ne sert personne, la question n'est pas « dans quel
// ordre » mais « pourquoi pas du tout », et la réponse est invisible partout
// ailleurs.
func DisplayCiblesClient(computeurID string, cibles []clusterdatabase.CibleClient,
	groupesClient []int, ecartes []string) string {

	var b strings.Builder

	b.WriteString("Nœuds que " + computeurID + " joindra, dans l'ordre\n\n")

	if len(cibles) == 0 {
		b.WriteString("Aucun. Cette machine ne peut s'authentifier que par les serveurs\n" +
			"inscrits dans sa configuration locale.\n\n")
		b.WriteString(sectionEcartes(ecartes))
		return b.String()
	}

	tb := NouvelleTable("#", "HÔTE", "ADRESSE", "RÔLE", "AFFIN", "PRIO.", "POURQUOI CE RANG")
	for _, c := range cibles {
		n := c.Noeud
		tb.Ajouter(
			strconv.Itoa(c.Rang),
			Valeur(n.Hostname),
			Valeur(clusterstorage.AdresseAffichee(n.AdresseEffective(), n.PortEffectif())),
			Valeur(n.Role),
			Valeur(ouiNon(n.Affin)),
			Valeur(prioriteLisible(n.Priorite)),
			Valeur(c.Motif),
		)
	}
	b.WriteString(tb.String())

	b.WriteString("\nL'agent parcourt cette liste de haut en bas et s'arrête au premier qui répond.\n")

	// Sans groupe, aucune affinité ne peut jouer. Le dire évite de conclure que
	// le mécanisme est en panne alors que la machine n'a simplement été mise
	// dans aucun groupe.
	if len(groupesClient) == 0 {
		b.WriteString("\nCette machine n'appartient à AUCUN groupe : aucune affinité ne peut\n" +
			"jouer pour elle, l'ordre ne tient qu'au rôle et à la priorité.\n")
	}

	b.WriteString("\n" + sectionEcartes(ecartes))
	return b.String()
}

// sectionEcartes rend la liste des nœuds qu'aucun agent ne reçoit.
func sectionEcartes(ecartes []string) string {
	if len(ecartes) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("Nœuds annoncés à PERSONNE :\n")
	for _, e := range ecartes {
		b.WriteString("  " + e + "\n")
	}
	return b.String()
}

// ouiNon rend un booléen lisible dans un tableau.
func ouiNon(v bool) string {
	if v {
		return "oui"
	}
	return ""
}

// prioriteLisible rend zéro sous la forme qui dit ce qu'il veut dire.
//
// « 0 » se lit comme la priorité la plus haute, alors qu'elle vaut « sans
// préférence » et se range APRÈS les valeurs explicites. C'est le piège du
// champ, et l'afficher tel quel le tend à chaque lecture.
func prioriteLisible(p int) string {
	if p <= 0 {
		return "—"
	}
	return strconv.Itoa(p)
}
