package localusermanagement

import (
	"fmt"
	"sort"
	"strings"
)

// L'effacement définitif des groupes vidés.
//
// # Pourquoi une commande LOCALE et non `vlt purge groups`
//
// La spécification proposait une commande du core. C'est un écart assumé, et il
// vaut mieux qu'il soit écrit ici que découvert plus tard.
//
// Une commande du core aurait supposé une trame de plus, allant du serveur vers
// l'agent, autorisant une écriture dans `/etc/group` à distance. C'est une
// frontière de privilège neuve — donc une clé RBAC, une action, un point d'entrée
// de plus dans le catalogue des trames — pour un geste dont le bénéfice est de la
// propreté : le vidage a DÉJÀ coupé les droits, l'effacement ne retire que des
// lignes sans membre.
//
// Le rapport entre ce qu'on ajoute et ce qu'on gagne ne le justifie pas. La
// commande est donc locale, sur la machine concernée, où elle demande le même
// privilège que tout ce qui touche `/etc/group` : root.

// GroupeOrphelin est un groupe créé par Vaultaire, vidé, et effaçable.
type GroupeOrphelin struct {
	Nom string
	GID int
}

// GroupesOrphelins liste les groupes que l'agent a créés et qui ne comptent plus
// aucun membre.
//
// Ne modifie rien. C'est ce que la commande affiche AVANT d'agir : personne ne
// doit découvrir après coup ce qui a été effacé d'un fichier système.
//
// # Le critère est « vide », pas « disparu du domaine »
//
// L'agent ne garde pas la dernière liste annoncée : la carte dit ce qu'il a
// créé, pas ce que le domaine contient à l'instant. Un groupe encore annoncé
// mais sans aucun membre figure donc ici.
//
// Ce n'est pas un défaut, parce que la règle de calcul du GID est SANS ÉTAT : la
// synchronisation suivante recrée le groupe avec exactement le même numéro. Le
// pire cas est un aller-retour visible dans le journal, pas une divergence.
//
// Le critère inverse aurait coûté plus cher qu'il ne rapporte : il faudrait
// persister la dernière annonce, donc un troisième fichier d'état, qui pourrait
// à son tour être périmé.
func GroupesOrphelins() ([]GroupeOrphelin, error) {
	crees, err := ChargerGroupesCrees()
	if err != nil {
		return nil, fmt.Errorf("état des groupes illisible : %w", err)
	}

	var out []GroupeOrphelin
	for nom, gid := range crees {
		gidLocal, existe, err := gidDuGroupe(nom)
		if err != nil {
			// Une ligne illisible n'est pas proposée à l'effacement : on
			// n'efface pas ce qu'on n'a pas su lire.
			continue
		}
		if !existe {
			// Déjà parti — effacé à la main, ou par un autre outil. Rien à
			// proposer, mais la carte le porte encore : le prochain passage de
			// synchronisation la remettra d'aplomb.
			continue
		}
		if gidLocal != gid {
			// Le numéro a changé sous nos pieds. Ce n'est plus le groupe que
			// l'agent avait créé, quel que soit son nom.
			continue
		}
		vide, err := groupeEstVide(nom)
		if err != nil || !vide {
			continue
		}
		out = append(out, GroupeOrphelin{Nom: nom, GID: gid})
	}

	sort.Slice(out, func(i, j int) bool { return out[i].Nom < out[j].Nom })
	return out, nil
}

// PurgerGroupesOrphelins efface les lignes des groupes rendus par
// GroupesOrphelins.
//
// Rend les noms effacés. La liste est recalculée ici plutôt que reçue en
// paramètre : entre l'affichage et la confirmation, une synchronisation a pu
// repeupler un groupe, et effacer sur la foi d'une liste périmée retirerait des
// droits à quelqu'un qui vient de les recevoir.
func PurgerGroupesOrphelins() ([]string, error) {
	orphelins, err := GroupesOrphelins()
	if err != nil {
		return nil, err
	}
	if len(orphelins) == 0 {
		return nil, nil
	}

	noms := make([]string, 0, len(orphelins))
	for _, o := range orphelins {
		noms = append(noms, o.Nom)
	}
	return EffacerGroupesVides(noms)
}

// groupeEstVide dit si un groupe n'a plus aucun membre secondaire.
//
// # Ce que cette fonction NE voit pas
//
// Les membres PRIMAIRES. Un compte dont `/etc/passwd` porte ce GID en groupe
// principal n'apparaît pas dans la ligne de `/etc/group` : c'est ainsi qu'Unix
// fonctionne, et un groupe peut donc sembler vide tout en étant le groupe
// principal de quelqu'un.
//
// L'agent n'attribue jamais un groupe du domaine comme groupe principal — il
// crée pour chaque compte un groupe primaire de son propre nom, dans la plage
// des UID. Le cas ne peut donc pas venir de lui. Il pourrait venir d'un
// administrateur qui l'aurait fait à la main ; c'est précisément pourquoi
// l'effacement demande une confirmation humaine sur la machine, plutôt que de
// se déclencher tout seul.
func groupeEstVide(nom string) (bool, error) {
	contenu, err := lireGroupes()
	if err != nil {
		return false, err
	}
	for _, ligne := range strings.Split(contenu, "\n") {
		if !strings.HasPrefix(ligne, nom+":") {
			continue
		}
		champs := strings.Split(ligne, ":")
		if len(champs) < 4 {
			return false, fmt.Errorf("ligne de groupe %q malformée", nom)
		}
		return strings.TrimSpace(champs[3]) == "", nil
	}
	return false, nil
}
