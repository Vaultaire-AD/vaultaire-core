package dbgroups

import "fmt"

// Le GID d'un groupe du domaine, sur les machines du parc.
//
// # Pourquoi le serveur calcule, et pas la machine
//
// Un GID choisi localement serait DIFFÉRENT sur chaque machine. Sur un partage
// NFS, où seuls des nombres circulent, deux machines du même domaine liraient
// alors des droits différents sur les mêmes fichiers : le groupe « comptabilité »
// serait 5100 ici et 5103 là, et le second poste verrait les fichiers du premier
// comme appartenant à un groupe inconnu.
//
// C'est exactement le problème que `uid.map` résout pour les utilisateurs, et il
// ne se résout pas machine par machine : le seul point qui voit tout le domaine
// est le serveur.
//
// # Pourquoi une formule et pas une allocation
//
// `id_group` est déjà unique et stable en base. En dériver le GID donne une
// règle SANS ÉTAT : une machine réinstallée retrouve les mêmes numéros sans rien
// avoir à recopier, et deux machines qui découvrent les groupes dans un ordre
// différent obtiennent le même résultat.
//
// Une table d'allocation aurait ajouté un état à sauvegarder, à migrer, et à
// réparer le jour où il diverge de la table `groups`.
const (
	// BaseGIDDomaine ouvre la plage des groupes du domaine.
	//
	// PAS dans 5000–60000 : `ProvisionVaultaireUser` crée pour chaque compte un
	// groupe primaire dont le GID vaut l'UID. Cette plage est donc déjà
	// entièrement consommée, et y placer les groupes du domaine garantirait la
	// collision — deux groupes différents portant le même numéro, donc des droits
	// qui s'appliquent au mauvais.
	//
	// 60001–65533 est libre mais étroit (5 500 groupes) et bute sur 65534, que
	// `nogroup` occupe sur la plupart des distributions. Les GID sont des entiers
	// 32 bits : 100000 laisse la place et reste lisible dans un `ls -n`.
	BaseGIDDomaine = 100000

	// IDGroupMax borne ce que la formule accepte.
	//
	// La table `groups` en est très loin. La borne n'existe pas parce qu'on
	// craint de l'atteindre, mais pour que l'hypothèse soit VÉRIFIÉE au lieu
	// d'être supposée : sans elle, un `id_group` aberrant — colonne corrompue,
	// import raté, compteur d'auto-incrément remis à une valeur folle —
	// produirait un GID silencieusement hors de la plage annoncée.
	IDGroupMax = 60000

	// GIDMaxDomaine est la borne haute effective, nommée pour être lisible dans
	// les journaux et les messages d'erreur.
	GIDMaxDomaine = BaseGIDDomaine + IDGroupMax
)

// GIDDeGroupe rend le GID d'un groupe du domaine à partir de son identifiant.
//
// L'erreur n'est pas décorative : un appelant qui l'ignorerait écrirait un GID
// nul dans `/etc/group`, c'est-à-dire le groupe `root`.
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
