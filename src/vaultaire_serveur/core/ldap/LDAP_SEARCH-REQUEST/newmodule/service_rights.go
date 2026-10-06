package newmodule

import (
	"sort"
	"strings"

	"vaultaire/core/clienttype"
	candidate "vaultaire/core/ldap/LDAP_SEARCH-REQUEST/newmodule/candidate"
	"vaultaire/core/permission"
)

// Droits de service exposés en LDAP : l'attribut opérationnel
// vaultaireServiceRights.
//
// # Pourquoi en LDAP aussi
//
// Un service raccordé par le réseau Ducky reçoit les clés de son compte dans la
// trame 08_02. Un service raccordé par LDAP — Nexus en mode ldap, ou n'importe
// quelle application qui ne parle que LDAP — n'a pas cette trame. Sans cet
// attribut, il devrait déduire les droits des NOMS de groupe, donc tenir chez
// lui une seconde politique que la matrice du core ne montre pas. L'attribut
// ramène la décision dans le core : on accorde read:nexus dans l'interface web,
// et les deux chemins le voient.
//
// # Ce qui est exposé
//
// Uniquement les clés que le catalogue des types déclare comme apprenables par
// un service (clienttype.UserRights), jamais le reste du RBAC : un client LDAP
// n'a pas à apprendre qu'un compte peut réinitialiser des mots de passe.
//
// # À qui
//
//   - au compte lui-même (le cas de Nexus : il lie la session de l'utilisateur
//     puis lit sa propre entrée) ;
//   - à un compte qui porte read:get:user sur le domaine de l'entrée (un compte
//     de service LDAP configuré pour lire les autres).
//
// À personne d'autre : pour eux, l'attribut est simplement absent.
//
// # Coût
//
// Calculé seulement quand l'attribut est demandé NOMMÉMENT. « + » ne le
// déclenche pas : des navigateurs d'annuaire l'envoient sur des recherches de
// sous-arbre entières, et chaque entrée coûterait alors plusieurs requêtes. Une
// recherche ordinaire ne fait aucune requête de plus.

// clesDeService est l'union des clés que les services peuvent apprendre.
func clesDeService() []string {
	vues := map[string]bool{}
	var out []string
	for _, d := range clienttype.All() {
		for _, k := range d.UserRights {
			if !vues[k] {
				vues[k] = true
				out = append(out, k)
			}
		}
	}
	sort.Strings(out)
	return out
}

// droitsServiceDemandes dit si la requête demande l'attribut.
func droitsServiceDemandes(attrs []string) bool {
	for _, a := range attrs {
		a = strings.TrimSpace(a)
		if strings.EqualFold(a, candidate.AttrServiceRights) {
			return true
		}
	}
	return false
}

// Points d'injection, remplacés par les tests.
var (
	groupesDe  = permission.GetGroupIDsForUser
	aLAction   = permission.HasActionAnywhere
	peutLireEn = func(lecteur, domaine string) bool {
		ids, action, err := permission.PrePermissionCheck(lecteur, "read:get:user")
		if err != nil {
			return false
		}
		ok, _ := permission.CheckPermissionsMultipleDomains(ids, action, []string{domaine})
		return ok
	}
)

// droitsService rend les clés de service du compte de l'entrée, si le compte
// lié a le droit de les lire. Nil sinon.
func droitsService(lie string, e candidate.UserEntry) []string {
	cible := e.User.Username
	if cible == "" || lie == "" {
		return nil
	}
	if !strings.EqualFold(lie, cible) && !peutLireEn(lie, e.BaseDN) {
		return nil
	}
	ids, err := groupesDe(cible)
	if err != nil {
		return nil
	}
	var out []string
	for _, k := range clesDeService() {
		if aLAction(ids, k) {
			out = append(out, k)
		}
	}
	return out
}
