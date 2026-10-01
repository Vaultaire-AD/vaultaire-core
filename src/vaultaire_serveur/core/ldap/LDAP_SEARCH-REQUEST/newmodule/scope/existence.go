package scope

import (
	"database/sql"
	"strings"

	dbdomains "vaultaire/core/database/db_domains"
	domainpkg "vaultaire/core/domain"
	ldaptools "vaultaire/core/ldap/LDAP-TOOLS"
	"vaultaire/core/ldap/LDAP_SEARCH-REQUEST/newmodule/candidate"
	"vaultaire/core/logs"
)

// AncetreExistant examine un baseObject et rend deux choses : le serveur sert-il
// cet endroit, et quel est le plus proche ancêtre qu'il sert.
//
// # À quoi cela sert
//
// À répondre `noSuchObject` (32) plutôt qu'un succès sans entrée — point 124.
// Les deux réponses se ressemblaient, et un client ne pouvait plus distinguer
// « ce DN n'existe pas » de « ce DN existe et est vide ». C'est pourtant la
// distinction sur laquelle s'appuient les outils qui vérifient une existence
// avant d'écrire ou de synchroniser.
//
// Le premier retour alimente `matchedDN` (RFC 4511 §4.1.9), qui dit au client OÙ
// le chemin se rompt. Il est toujours un ancêtre STRICT du DN demandé : renvoyer
// le DN lui-même ferait boucler les bibliothèques qui remontent l'arbre.
//
// # Ce qui est vérifié : le DOMAINE, et rien d'autre
//
// Deux choses volontairement NON vérifiées, et chacune a coûté cher à
// l'écriture :
//
//  1. La FORME du DN. Une première version n'acceptait que `ou=users` et
//     `ou=groups`. Or le résolveur ignore complètement la partie unité
//     d'organisation d'un baseObject en scope `one` et `sub` — il travaille sur
//     le domaine. Refuser les autres formes aurait rendu `noSuchObject` à
//     `cn=Users,dc=…`, qui est le conteneur du préréglage « Active Directory »
//     de Keycloak, et à `ou=people,dc=…` : des clients qui fonctionnaient.
//
//  2. La FEUILLE — tel compte, tel groupe. Une requête de moins sur le chemin
//     chaud, et surtout pas d'ORACLE : une feuille qui existe mais que les droits
//     de l'appelant cachent doit rendre exactement la même réponse qu'une feuille
//     absente. Le gestionnaire s'en charge en rendant 32 dès qu'aucune entrée ne
//     ressort, quelle qu'en soit la raison.
func AncetreExistant(db *sql.DB, baseObject string) (ancetre string, baseValide bool) {
	servis, err := dbdomains.GetAllDomainNames(db)
	if err != nil {
		// Une lecture en échec REFUSE. La réponse sera `noSuchObject` : c'est faux,
		// mais fermé. L'inverse ferait passer une base en difficulté pour un
		// annuaire complet, et un client qui synchronise là-dessus peut supprimer
		// des comptes.
		logs.Write_Log("ERROR", "ldap: domaines servis illisibles : "+err.Error())
		return "", false
	}
	return ancetreExistant(baseObject, servi(servis))
}

// estServi dit si le serveur sert un domaine donné.
//
// Une fonction, et non un appel direct à la base : c'est ce qui rend la RÈGLE
// éprouvable sans base de données. Le point 124 est fait de cette règle, pas de
// la requête SQL.
type estServi func(domaine string) bool

// servi construit le prédicat à partir des domaines des groupes.
//
// # Pourquoi ce critère et pas `DomainExists`
//
// `DomainExists` teste une ÉGALITÉ sur `domain_group.domain_name`. Une première
// version s'en servait, et elle aurait coupé les parcs les plus ordinaires : si
// les groupes vivent dans `dev.acme.lan` et `svc.acme.lan`, alors `acme.lan`
// n'est égal à rien — alors même que le RootDSE l'annonce comme `namingContext`
// (`ToRootDN` ne garde que deux labels) et que `GetGroupsUnderDomain` le sert par
// suffixe. Le serveur aurait répondu « cet objet n'existe pas » pour la base
// qu'il venait lui-même d'annoncer.
//
// Le critère est donc celui que le résolveur emploie pour CHARGER : un domaine
// est servi s'il porte des groupes, ou si l'un de ses sous-domaines en porte.
//
// Une différence assumée avec le résolveur : celui-ci fabrique en plus les deux
// unités d'organisation `users` et `groups` pour n'importe quel domaine, servi ou
// non. Une recherche sur un domaine inventé rendait donc deux entrées inventées.
// C'est précisément ce que ce contrôle arrête — au prix d'un changement visible :
// un annuaire sans aucun groupe ne sert plus rien du tout, et le dit.
func servi(domainesDeGroupes []string) estServi {
	return func(domaine string) bool {
		cible := domainpkg.NormaliserDomaine(domaine)
		if cible == "" {
			return false
		}
		for _, d := range domainesDeGroupes {
			d = domainpkg.NormaliserDomaine(d)
			if d == cible || strings.HasSuffix(d, "."+cible) {
				return true
			}
		}
		return false
	}
}

func ancetreExistant(baseObject string, sert estServi) (ancetre string, baseValide bool) {
	baseObject = strings.TrimSpace(baseObject)
	if baseObject == "" {
		return "", false
	}

	domaine := ldaptools.ConvertLDAPBaseToDomainName(baseObject)
	if domaine == "" {
		// Aucun composant `dc=` : ce n'est pas une base de cet annuaire. Rien à
		// désigner comme ancêtre — la racine elle-même n'est pas sur ce chemin.
		return "", false
	}

	trouve, ok := plusLongDomaineServi(domaine, sert)
	if !ok {
		return "", false
	}
	// L'ancêtre est le DN du domaine servi le plus profond, dans les deux cas.
	//
	// # Pourquoi celui-là et pas le parent du DN demandé
	//
	// La RFC 4511 §4.1.9 demande le nom de la plus basse ENTRÉE présente dans
	// l'annuaire. Découper le DN demandé d'un cran rendait des DN qui ne sont
	// aucune entrée : `dc=lan` pour une base `dc=acme,dc=lan`, ou
	// `cn=Users,dc=acme,dc=lan` pour un compte placé sous ce conteneur — le
	// serveur ne sert ni l'un ni l'autre, et un client qui remonte l'arbre par
	// `matchedDN` part dans le vide.
	//
	// Le DN d'un domaine servi, lui, est bien une entrée : c'est ce que rend une
	// recherche `base` dessus. Et il est toujours un ancêtre du DN demandé,
	// puisqu'il est composé de ses propres composants `dc=`.
	ancetreDuDomaine := candidate.DomainEntry{DNName: trouve}.DN()

	if !strings.EqualFold(trouve, domaine) {
		// Le domaine demandé n'est pas servi, mais l'un de ses parents l'est. C'est
		// exactement ce que `matchedDN` sert à dire.
		return ancetreDuDomaine, false
	}

	// Le domaine est servi : la base est valide, quelle que soit la forme du reste
	// du DN. L'ancêtre rendu servira si aucune entrée n'en ressort.
	//
	// Sauf s'il EST la base demandée : « cet objet n'existe pas, le plus proche
	// qui existe est ce même objet » fait boucler un client qui remonte l'arbre.
	// Le cas ne devrait pas se produire — une recherche sur un domaine servi rend
	// toujours quelque chose — mais la garde coûte une comparaison.
	if strings.EqualFold(ancetreDuDomaine, baseObject) {
		return "", true
	}
	return ancetreDuDomaine, true
}

// plusLongDomaineServi remonte de label en label jusqu'à trouver un domaine que
// le serveur sert.
//
// « admin.enov.local » non servi mais « enov.local » servi rend « enov.local » :
// c'est ce qu'il faut pour `matchedDN`.
func plusLongDomaineServi(domaine string, sert estServi) (string, bool) {
	for reste := domaine; reste != ""; {
		if sert(reste) {
			return reste, true
		}
		i := strings.Index(reste, ".")
		if i < 0 {
			return "", false
		}
		reste = reste[i+1:]
	}
	return "", false
}
