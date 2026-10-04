package candidate

import (
	"fmt"
	"strings"
	"vaultaire/core/identifiant"
	ldaptools "vaultaire/core/ldap/LDAP-TOOLS"
	ldapinterface "vaultaire/core/ldap/LDAP_SEARCH-REQUEST/newmodule/candidate/ldap_interface"
)

type GroupEntry struct {
	Name    string
	BaseDN  string
	Members []string
	// Dates telles que la base les rend ; la mise au format LDAP se fait au
	// moment de servir l'attribut — point 126.
	Created_at  string
	Modified_at string
	// EntryUUID : l'identifiant stable du groupe, colonne `entry_uuid` — point
	// 129. Vide, l'attribut n'est pas servi.
	EntryUUID string
}

func (g GroupEntry) DN() string {
	return fmt.Sprintf("cn=%s,ou=groups,%s", g.Name, ldaptools.ToRootDN(g.BaseDN))
}

// Domaines — voir ldapinterface.LDAPEntry.
//
// Un groupe n'a qu'un domaine, et `BaseDN` porte ici le SIEN — le résolveur y
// place `g.DomainName`, lu en base, et non le domaine demandé par le client.
// C'est exactement le cas que le filtre d'autorisation doit pouvoir écarter.
func (g GroupEntry) Domaines() []string {
	if g.BaseDN == "" {
		return nil
	}
	return []string{g.BaseDN}
}

// Restreinte — voir ldapinterface.LDAPEntry.
//
// # `member` n'a rien à retirer, et ce n'est pas un oubli — TO-DO 132
//
// `member` nomme des comptes, et la question est la même que pour `memberOf` :
// l'appelant pourrait-il lire chacun d'eux comme entrée ? Oui, par
// construction, et voici pourquoi.
//
// Un compte est rendu si l'un AU MOINS de ses rattachements est lisible, et ses
// rattachements sont les domaines des groupes dont il est membre. Tout membre de
// CE groupe a donc le domaine de ce groupe parmi les siens. Or ce groupe n'est
// arrivé jusqu'ici que parce que son domaine est lisible — c'est `Domaines()`,
// ci-dessus, qui en a décidé. Chaque DN de `member` désigne ainsi un compte que
// l'appelant peut lire.
//
// Ce raisonnement tient à UNE chose : que `BaseDN` soit le domaine PROPRE du
// groupe, lu en base, et jamais celui que le client a demandé. Un test de
// sentinelle du paquet scope le vérifie sur chaque GroupEntry construite
// (`TestLeDomaineDUnGroupeEstLeSien`).
//
// Si la règle de visibilité d'un compte devenait un jour plus stricte — « tous
// ses rattachements » au lieu d'« au moins un » —, c'est ICI qu'il faudrait
// filtrer, en portant le rattachement de chaque membre comme `Appartenance`
// porte le domaine de chaque groupe.
func (g GroupEntry) Restreinte(func(domaine string) bool) ldapinterface.LDAPEntry {
	return g
}

// ObjectClasses — ce que l'entrée déclare ÊTRE.
//
// `posixGroup` a été retiré (point 123), pour la même raison que `posixAccount`
// côté comptes : il était déclaré sans qu'aucun attribut POSIX — `gidNumber`,
// `memberUid` — ne soit servi. Les clients qui comptent restent servis :
// Keycloak cherche `groupOfNames`, Nextcloud cherche `group`.
//
// `organizationalUnit` a été retiré à son tour (point 125) : un groupe n'EST pas
// une unité d'organisation, et l'annoncer était exactement la même faute que
// `posixGroup`. Aucun client connu ne cherche les groupes par cette classe —
// Keycloak emploie `groupOfNames`, Nextcloud `group` — et les vraies unités
// d'organisation, elles, continuent de l'annoncer (voir OUEntry).
func (g GroupEntry) ObjectClasses() []string {
	return []string{
		"top",
		"groupOfNames",
		"group", // <- ajouté pour Nextcloud
	}
}

// Méthode complète pour gérer "*", "+", TypesOnly
func (g GroupEntry) GetAttributes(requested []string, typesOnly bool) map[string][]string {
	all := map[string][]string{
		"dn": {g.DN()},
		"cn": {g.Name},
		// "ou":          {"groups"},
		"displayname": {g.Name},
		"member":      g.Members,
		"objectclass": g.ObjectClasses(),
	}

	// Les horodatages — point 126, même raisonnement que côté comptes.
	//
	// Ils comptent autant ici : un groupe dont la composition change n'écrit pas
	// sa propre ligne, l'appartenance vit dans une table à part. C'est pour cela
	// que l'ajout et le retrait d'un membre marquent explicitement le groupe
	// comme modifié (schematools.ToucherLigne).
	if t := ldaptools.VersGeneralizedTime(g.Created_at); t != "" {
		all[ldaptools.AttrCreeLe] = []string{t}
	}
	if t := ldaptools.VersGeneralizedTime(g.Modified_at); t != "" {
		all[ldaptools.AttrModifieLe] = []string{t}
	}

	// L'identifiant stable — point 129, même règle que côté comptes : servi
	// seulement s'il a la forme d'un UUID, absent sinon. Un groupe supprimé puis
	// recréé sous le même nom en porte un autre : pour un client qui tient un
	// cache, ce sont bien deux groupes.
	if identifiant.EstUnUUID(g.EntryUUID) {
		all[AttrEntryUUID] = []string{g.EntryUUID}
	}

	result := make(map[string][]string)
	includeAll := len(requested) == 0 || contains(requested, "*")
	includeOperational := contains(requested, "+")

	for k, v := range all {
		// Un attribut OPÉRATIONNEL ne sort que demandé, nommément ou par « + ».
		//
		// La branche était inerte tant qu'aucun attribut de groupe ne l'était ; les
		// horodatages du point 126 le sont, et c'est ce qui la rend vivante. La
		// version inversée qui s'y trouvait les aurait diffusés sur TOUTES les
		// recherches, y compris « 1.1 », qui veut dire « aucun attribut ».
		if isOperational(k) && !includeOperational && !contains(requested, k) {
			continue
		}

		if includeAll || contains(requested, k) || (includeOperational && isOperational(k)) {
			if typesOnly {
				result[k] = []string{}
			} else {
				result[k] = v
			}
		}
	}

	return result
}

func (g GroupEntry) GetAttribute(attr string) []string {
	attr = strings.ToLower(attr)
	res := g.GetAttributes([]string{attr}, false)
	return res[attr]
}
