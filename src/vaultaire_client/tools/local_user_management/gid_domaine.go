package localusermanagement

import "fmt"

// Le GID d'un groupe du domaine — la MÊME règle que côté serveur.
//
// # Pourquoi elle est écrite deux fois
//
// L'agent et le serveur sont des modules Go distincts : l'agent n'importe pas le
// serveur, et aucune compilation ne peut tenir les deux copies liées. C'est la
// même situation que le préfixe `groups:` de la trame 03_02, et que
// `IntervalleRapportAgent`.
//
// # Pourquoi l'agent recalcule au lieu de recevoir le nombre
//
// La trame 03_09 porte les `id_group`, pas les GID. Envoyer le numéro déjà
// calculé aurait laissé un serveur en imposer un arbitraire — dont **0**, qui est
// `root`. Le serveur est authentifié, il n'est pas infaillible : une injection
// SQL sur la table `groups`, un bogue, une base restaurée de travers suffiraient.
//
// La règle appartient donc au code des deux côtés, et le réseau ne transporte
// que des identifiants. Les tests jumeaux figent les constantes aux deux bouts.
const (
	// BaseGIDDomaine ouvre la plage des groupes du domaine.
	//
	// Au-dessus de UIDMax, et il DOIT le rester : `ProvisionVaultaireUser` donne
	// à chaque compte un groupe primaire dont le GID vaut l'UID, donc 5000–60000
	// est déjà pris en entier. Un test le vérifie plutôt que de le laisser à la
	// vigilance de qui toucherait à l'une des deux plages.
	BaseGIDDomaine = 100000

	// IDGroupMax borne ce que la formule accepte, côté agent aussi.
	IDGroupMax = 60000

	// GIDMaxDomaine est la borne haute effective.
	GIDMaxDomaine = BaseGIDDomaine + IDGroupMax
)

// GIDDeGroupe rend le GID d'un groupe du domaine à partir de son identifiant.
func GIDDeGroupe(idGroup int) (int, error) {
	if idGroup <= 0 {
		return 0, fmt.Errorf("identifiant de groupe invalide (%d) : "+
			"un GID ne peut pas en être dérivé", idGroup)
	}
	if idGroup > IDGroupMax {
		return 0, fmt.Errorf("identifiant de groupe %d au-delà de la borne %d : "+
			"le GID sortirait de la plage réservée aux groupes du domaine "+
			"(%d-%d)", idGroup, IDGroupMax, BaseGIDDomaine, GIDMaxDomaine)
	}
	return BaseGIDDomaine + idGroup, nil
}

// EstGIDDeDomaine dit si un GID appartient à la plage des groupes du domaine.
//
// Sert au diagnostic et aux garde-fous : un groupe que l'agent croit avoir créé
// mais dont le GID sort de la plage n'a pas été créé par lui.
func EstGIDDeDomaine(gid int) bool {
	return gid > BaseGIDDomaine && gid <= GIDMaxDomaine
}
