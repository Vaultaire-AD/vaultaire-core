package action

import (
	"fmt"
	"strings"

	"vaultaire/core/database"
	dbdomains "vaultaire/core/database/db_domains"
	"vaultaire/core/domain"
	"vaultaire/core/storage"
)

// Arborescence des domaines et de leurs groupes — la commande `eyes`.
//
// # Ce qu'elle est vraiment
//
// La même donnée que `get -g` — des groupes et leur domaine — présentée en
// arbre au lieu d'un tableau. Une seule forme existe : `eyes -g`.
//
// Elle exige donc `read:get:group`, exactement comme `get -g`. Deux
// présentations de la même information ne doivent pas demander deux droits
// différents : celui qui a le droit de lire la liste des groupes n'apprend rien
// de plus en la voyant en arbre.
//
// # La clé write:eyes n'est plus employée
//
// Elle figure toujours dans permission.specialActions, et son retrait est une
// modification à part : elle a pu être accordée dans des permissions
// existantes, et l'ôter du vocabulaire ferait échouer leur relecture. Elle
// n'est simplement plus interrogée.
//
// Le nom disait d'ailleurs le contraire de ce qu'elle gardait : `write:` pour
// une commande qui ne fait que lire.
//
// # Le filtre change ce que voit un délégué
//
// L'arborescence complète révèle la STRUCTURE de l'annuaire — quels domaines
// existent, comment ils s'emboîtent. Le filtre ne garde que les groupes du
// périmètre de l'appelant ; les domaines qui n'en contiennent aucun
// disparaissent donc de l'arbre, puisqu'il est bâti à partir des groupes.
//
// Un délégué de paris voit l'arborescence de paris, et non plus celle de toute
// l'organisation.

// EnregistrerActionsArborescence ajoute la lecture de l'arborescence.
func EnregistrerActionsArborescence(r *Registre) {
	r.MustEnregistrer(Definition{
		Nom:     "domain.list_tree",
		CleRBAC: "read:get:group",
		Portee:  PorteeGlobale,
		// Même souplesse que group.list : le droit sur un domaine ouvre la
		// vue, le filtre la réduit.
		PorteeOuverte: true,
		Filtre:        filtrerArborescence,
		Resume:        "arborescence des domaines et de leurs groupes",
		Executer:      listerArborescence,
	})

	r.MustEnregistrer(Definition{
		Nom:     "domain.list_groups",
		CleRBAC: "read:get:group",
		// Portée du domaine demandé. Il n'existe pas de PorteeDomaine : un
		// domaine EST un domaine, la portée est donc lui-même.
		Portee:          porteeDomaine,
		UnDomaineSuffit: true,
		// Le filtre n'est PAS inutile : la liste descend dans les
		// sous-domaines, que le droit sur le domaine demandé ne couvre pas
		// toujours. Un délégué de paris.fr sans propagation (« 0:paris.fr »)
		// voyait les groupes de rh.paris.fr — ceux que `eyes -g` lui masquait.
		Filtre:   filtrerArborescence,
		Resume:   "groupes situés sous un domaine",
		Executer: listerGroupesDuDomaine,
	})
}

// porteeDomaine exige le droit sur le domaine demandé lui-même.
//
// Contrairement aux autres portées, aucune résolution n'est nécessaire : le
// paramètre EST le domaine. Un domaine vide retombe sur le droit global, comme
// partout — ne pas savoir sur quoi porte la demande n'autorise rien.
func porteeDomaine(p Params) ([]string, error) {
	d := p.Get("domain")
	if d == "" {
		return []string{"*"}, nil
	}
	return []string{d}, nil
}

// filtrerArborescence réduit les groupes au périmètre, puis rebâtit l'arbre.
//
// Le filtre porte sur les GROUPES et non sur les nœuds de l'arbre : c'est la
// liste plate qui est filtrée, l'arbre étant reconstruit ensuite. Filtrer
// l'arbre lui-même obligerait à décider quoi faire d'un domaine dont seuls
// certains groupes sont visibles — question qui ne se pose pas si l'arbre naît
// déjà filtré.
func filtrerArborescence(donnees any, perim Perimetre) (any, int) {
	groupes, ok := donnees.([]storage.GroupDomain)
	if !ok {
		return donnees, 0
	}
	garde := make([]storage.GroupDomain, 0, len(groupes))
	for _, g := range groupes {
		if perim.AutoriseUnDes([]string{g.DomainName}) {
			garde = append(garde, g)
		}
	}
	return garde, len(groupes) - len(garde)
}

func listerArborescence(_ Appelant, _ Params) (Resultat, error) {
	groupes, err := dbdomains.GetAllGroupsWithDomains(database.GetDatabase())
	if err != nil {
		return Resultat{}, fmt.Errorf("lecture des domaines : %w", err)
	}
	// Les données rendues sont la liste PLATE, pas l'arbre.
	//
	// C'est ce qui permet au filtre de s'appliquer — il ne saurait pas réduire
	// une structure récursive sans décider du sort des nœuds intermédiaires.
	// L'appelant construit l'arbre à partir de ce qu'il a le droit de voir.
	return Resultat{
		Message: fmt.Sprintf("%d groupe(s) répartis en domaines.", len(groupes)),
		Donnees: groupes,
	}, nil
}

// ArbreDepuis bâtit l'arborescence à partir de groupes déjà filtrés.
//
// Exportée pour que les façades construisent l'arbre après filtrage plutôt
// qu'avant : l'inverse afficherait des branches que l'appelant n'a pas le
// droit de voir.
func ArbreDepuis(groupes []storage.GroupDomain) *storage.DomainNode {
	return domain.BuildDomainTree(groupes)
}

func listerGroupesDuDomaine(_ Appelant, p Params) (Resultat, error) {
	nom := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(p.Get("domain")), "."))
	if nom == "" {
		return Resultat{}, fmt.Errorf("nom de domaine requis")
	}
	tous, err := dbdomains.GetAllGroupsWithDomains(database.GetDatabase())
	if err != nil {
		return Resultat{}, fmt.Errorf("lecture des groupes du domaine %q : %w", nom, err)
	}
	// Des GROUPES avec leur domaine, et non des noms de domaines : l'ancienne
	// version appelait GetGroupsUnderDomain en mode « domaines », si bien que
	// « Groupes sous X » listait… des domaines. Le domaine de chaque groupe sert
	// aussi au filtre de périmètre.
	var groupes []storage.GroupDomain
	for _, g := range tous {
		d := strings.ToLower(strings.TrimSuffix(g.DomainName, "."))
		if g.GroupName == "" || d == "" {
			continue
		}
		if d == nom || strings.HasSuffix(d, "."+nom) {
			groupes = append(groupes, g)
		}
	}
	if len(groupes) == 0 {
		return Resultat{Message: "Domaine " + nom + " : aucun groupe associé."}, nil
	}
	return Resultat{
		Message: fmt.Sprintf("%d groupe(s) sous %s.", len(groupes), nom),
		Donnees: groupes,
	}, nil
}
