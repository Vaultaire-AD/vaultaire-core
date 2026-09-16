package clusterdatabase

import (
	"database/sql"
	"fmt"

	clusterstorage "vaultaire/cluster/cluster_storage"
	dbclients "vaultaire/core/database/db_clients"
)

// « Qui cette machine va-t-elle joindre, et dans quel ordre ? »
//
// # Pourquoi cette question méritait sa propre fonction
//
// L'ordre dépend de quatre choses — le rôle du nœud, son affinité avec les
// groupes de CETTE machine, sa priorité, son nom — et de trois filtres qui
// peuvent l'écarter en silence : hors ligne, hors rotation, sans empreinte.
//
// Un administrateur qui constate qu'un poste ne joint pas le bon proxy n'a
// aucun moyen de le voir. Il peut lire l'état du cluster, les groupes du poste
// et les affinités de chaque nœud, puis refaire le tri de tête. C'est exactement
// le calcul que le core fait déjà, et le refaire à la main est le meilleur moyen
// de se tromper au moment où l'on cherche une erreur.
//
// # La même fonction que 04_04, et c'est le point
//
// Cette vue ne recalcule rien : elle appelle NoeudsPourAgents avec les groupes de
// la machine, comme le fait le gestionnaire de trames. Une seconde implémentation
// finirait par diverger, et la vue affirmerait un ordre que le parc ne suit pas —
// pire que pas de vue du tout, puisqu'on cesserait de chercher ailleurs.

// CibleClient est un nœud tel que ce client le recevra, avec son rang.
type CibleClient struct {
	// Rang commence à 1 : c'est un ordre de tentative, pas un indice.
	Rang int
	Noeud clusterstorage.Node
	// Motif explique la place, en clair.
	Motif string
}

// CiblesDuClient rend la liste ordonnée qu'un client recevrait en 04_04.
//
// Rend aussi les groupes de la machine : sans eux, une liste sans aucun nœud
// affin se lit comme « les affinités ne marchent pas », alors que la cause
// ordinaire est que la machine n'est dans aucun groupe.
func CiblesDuClient(db *sql.DB, computeurID string) (cibles []CibleClient, groupesClient []int, err error) {
	if db == nil {
		return nil, nil, fmt.Errorf("connexion base indisponible")
	}

	clientID, err := dbclients.Get_ClientID_By_ComputerID(db, computeurID)
	if err != nil {
		return nil, nil, fmt.Errorf("machine %s introuvable : %w", computeurID, err)
	}

	groupesClient, err = dbclients.Command_GET_GroupIDsFromClientID(db, clientID)
	if err != nil {
		return nil, nil, fmt.Errorf("groupes de la machine %s illisibles : %w", computeurID, err)
	}

	noeuds, err := NoeudsPourAgents(db, groupesClient)
	if err != nil {
		return nil, nil, err
	}

	// Les groupes affins sont renseignés pour l'affichage. Ils ne servent pas au
	// tri — il est déjà fait — mais à répondre à « pourquoi celui-là d'abord ».
	for i := range noeuds {
		if noms, errG := NomsDesGroupesDuNoeud(db, noeuds[i].ID); errG == nil {
			noeuds[i].GroupesAffins = noms
		}
	}

	cibles = make([]CibleClient, 0, len(noeuds))
	for i, n := range noeuds {
		cibles = append(cibles, CibleClient{Rang: i + 1, Noeud: n, Motif: motifDuRang(n)})
	}
	return cibles, groupesClient, nil
}

// motifDuRang dit en clair ce qui place ce nœud là.
//
// Le motif nomme le critère qui a DÉCIDÉ, pas tous ceux qui s'appliquent : une
// phrase qui répète les quatre critères sur chaque ligne ne se lit plus, et
// c'est le premier qui départage qui intéresse.
func motifDuRang(n clusterstorage.Node) string {
	role := "core"
	if n.Role == "proxy" {
		role = "proxy"
	}

	switch {
	case n.Affin && n.Priorite > 0:
		return fmt.Sprintf("%s affin à un groupe de cette machine, priorité %d", role, n.Priorite)
	case n.Affin:
		return role + " affin à un groupe de cette machine"
	case n.Priorite > 0:
		return fmt.Sprintf("%s, priorité %d", role, n.Priorite)
	default:
		return role + ", sans priorité déclarée"
	}
}

// NoeudsEcartes rend les nœuds que ce client NE recevra PAS, avec la raison.
//
// # Pourquoi l'absence mérite autant d'attention que la présence
//
// Un nœud écarté ne produit aucune trace du côté de l'agent : il n'apparaît tout
// simplement pas dans sa liste. Quand un proxy fraîchement déployé ne sert
// personne, la question n'est pas « dans quel ordre » mais « pourquoi pas du
// tout » — et les quatre causes possibles sont invisibles depuis la vue
// ordinaire du cluster.
func NoeudsEcartes(db *sql.DB) ([]string, error) {
	if db == nil {
		return nil, fmt.Errorf("connexion base indisponible")
	}

	noeuds, err := GetAllNodes(db)
	if err != nil {
		return nil, err
	}

	var ecartes []string
	for _, n := range noeuds {
		motif := motifDExclusion(n)
		if motif == "" {
			continue
		}
		ecartes = append(ecartes, n.Hostname+" — "+motif)
	}
	return ecartes, nil
}

// motifDExclusion rend la raison pour laquelle un nœud n'est annoncé à personne,
// ou une chaîne vide s'il l'est.
//
// L'ordre des tests suit celui du filtre de NoeudsPourAgents : un nœud peut
// cumuler les causes, et n'en corriger qu'une laisserait le nœud toujours
// absent, ce qui se lit comme « la correction n'a rien fait ». La PREMIÈRE est
// nommée, et la suivante apparaîtra une fois celle-là levée.
func motifDExclusion(n clusterstorage.Node) string {
	switch {
	case n.Role != "core" && n.Role != "proxy":
		return "rôle " + n.Role + " : seuls les cores et les proxies sont annoncés"
	case n.Status != "online":
		return "hors ligne — il ne bat plus"
	case !n.ExposeAuxAgents:
		return "hors rotation (vlt cluster rotation " + n.Hostname + " in)"
	case n.PortEffectif() <= 0:
		return "aucun port déclaré, ni par lui ni par un administrateur"
	case n.Empreinte == "":
		return "aucune empreinte de clé : l'annoncer ferait accepter sa clé en aveugle"
	default:
		return ""
	}
}
