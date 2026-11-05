package scope

import (
	"database/sql"
	"sort"
	"strings"

	domainpkg "vaultaire/core/domain"
	ldaptools "vaultaire/core/ldap/LDAP-TOOLS"
	ldapjournal "vaultaire/core/ldap/LDAP_Journal"
	"vaultaire/core/ldap/LDAP_SEARCH-REQUEST/newmodule/candidate"
	ldapinterface "vaultaire/core/ldap/LDAP_SEARCH-REQUEST/newmodule/candidate/ldap_interface"
)

// L'ARBRE DES DN — TO-DO 245.
//
// La portée d'une recherche était calculée sur le DOMAINE tiré des `dc=` de la
// base : `ou=users`, `ou=groups`, `uid=…`, `cn=…` étaient ignorés, et rien ne
// vérifiait que le DN d'une entrée rendue était sous la base. Comme les comptes
// et les groupes ont un DN aplati à la racine (point 120), l'arbre qu'un client
// reconstruit était faux : sous `ou=users`, une recherche `one` rendait
// `ou=users` et `ou=groups` ; sous un compte, de même ; sous un sous-domaine,
// des entrées qui n'étaient pas sous lui. Apache Directory Studio en tirait un
// arbre sans fin, sans un seul compte.
//
// La règle, désormais, dépend de la NATURE de la base :
//
//   - une feuille (compte, groupe) n'a pas d'enfant : `one` est vide, `sub` est
//     l'entrée elle-même ;
//   - une unité d'organisation : le domaine est chargé en entier, puis seules
//     les entrées DANS LA PORTÉE (RFC 4511 § 4.5.1.2) sont gardées. Les DN étant
//     aplatis, `one` sous `ou=users` rend tous les comptes du domaine et de ses
//     sous-domaines — ce que JumpServer attendait, sans `onelevel_subtree` ;
//   - un domaine : `one` rend ses enfants dans l'arbre — les deux OU quand il
//     est la racine, et ses sous-domaines ; `sub` garde la règle documentée
//     (`vaultaireLDAP.md`, étape 2 : la recherche sous un sous-domaine rend ses
//     comptes et ses groupes), et y ajoute l'entrée de la base et celles des
//     sous-domaines, qui manquaient.

// natureDeBase dit ce que désigne un baseObject.
type natureDeBase int

const (
	baseDomaine natureDeBase = iota // dc=…,dc=… seulement
	baseOU                          // ou=users|groups,dc=…
	baseFeuille                     // uid=… ou cn=… : un compte, un groupe
)

// natureDe classe une base par son premier RDN.
func natureDe(baseObject string) natureDeBase {
	premier := strings.TrimSpace(strings.SplitN(baseObject, ",", 2)[0])
	switch {
	case len(premier) > 3 && strings.EqualFold(premier[:3], "ou="):
		return baseOU
	case len(premier) > 3 && strings.EqualFold(premier[:3], "dc="):
		return baseDomaine
	default:
		return baseFeuille
	}
}

// normaliserDN rend un DN comparable : attributs et valeurs en minuscules,
// espaces autour des séparateurs retirés. Les DN de Vaultaire ne portent ni
// virgule échappée ni valeur multi-RDN : cette forme suffit à les comparer.
func normaliserDN(dn string) string {
	parts := strings.Split(dn, ",")
	for i, p := range parts {
		p = strings.TrimSpace(p)
		if k, v, ok := strings.Cut(p, "="); ok {
			p = strings.TrimSpace(k) + "=" + strings.TrimSpace(v)
		}
		parts[i] = strings.ToLower(p)
	}
	return strings.Join(parts, ",")
}

// dnParent rend le DN parent d'un DN normalisé, "" pour un DN d'un seul RDN.
func dnParent(dn string) string {
	_, parent, ok := strings.Cut(dn, ",")
	if !ok {
		return ""
	}
	return parent
}

// dansLaPortee dit si un DN est dans la portée d'une base (RFC 4511 § 4.5.1.2).
// Les deux DN sont normalisés.
func dansLaPortee(dn, base string, scope int) bool {
	switch scope {
	case 0:
		return dn == base
	case 1:
		return dnParent(dn) == base
	default:
		return dn == base || strings.HasSuffix(dn, ","+base)
	}
}

// DansLaPortee ne garde que les entrées dont le DN est dans la portée.
func DansLaPortee(entries []ldapinterface.LDAPEntry, baseObject string, scope int) []ldapinterface.LDAPEntry {
	base := normaliserDN(baseObject)
	var gardees []ldapinterface.LDAPEntry
	for _, e := range entries {
		if dansLaPortee(normaliserDN(e.DN()), base, scope) {
			gardees = append(gardees, e)
		}
	}
	return gardees
}

// sousDomaines rend les domaines de l'arbre sous `domaine` : `directs` les
// seuls enfants, sinon tous les descendants. Les domaines intermédiaires
// comptent — `dev.acme.lan` existe dans l'arbre dès que `web.dev.acme.lan` porte
// un groupe, comme pour le contrôle d'existence (voir AncetreExistant).
func sousDomaines(servis []string, domaine string, directs bool) []string {
	cible := domainpkg.NormaliserDomaine(domaine)
	if cible == "" {
		return nil
	}
	vus := map[string]struct{}{}
	for _, d := range servis {
		d = domainpkg.NormaliserDomaine(d)
		if !strings.HasSuffix(d, "."+cible) {
			continue
		}
		reste := strings.TrimSuffix(d, "."+cible)
		labels := strings.Split(reste, ".")
		// Chaque niveau entre `d` et la cible : « web.dev » sous acme.lan donne
		// dev.acme.lan, puis web.dev.acme.lan.
		for i := len(labels) - 1; i >= 0; i-- {
			vus[strings.Join(labels[i:], ".")+"."+cible] = struct{}{}
			if directs {
				break
			}
		}
	}
	liste := make([]string, 0, len(vus))
	for d := range vus {
		liste = append(liste, d)
	}
	sort.Strings(liste)
	return liste
}

// entreesDeDomaines fabrique les entrées `domain` d'une liste de domaines.
// `Feuille` dit si le domaine n'a lui-même aucun sous-domaine : c'est ce que
// rend `hasSubordinates` (une OU n'existe que sous la racine).
func entreesDeDomaines(servis, domaines []string) []ldapinterface.LDAPEntry {
	out := make([]ldapinterface.LDAPEntry, 0, len(domaines))
	for _, d := range domaines {
		out = append(out, candidate.DomainEntry{
			DNName:  d,
			Feuille: len(sousDomaines(servis, d, true)) == 0 && !estRacine(d),
		})
	}
	return out
}

// estRacine dit si un domaine est celui sous lequel les DN sont aplatis : ses
// deux OU sont ses enfants dans l'arbre.
func estRacine(domaine string) bool {
	return strings.EqualFold(ldaptools.ToDN(domaine), ldaptools.ToRootDN(domaine))
}

// ousDuDomaine rend les deux unités d'organisation, enfants de la racine.
func ousDuDomaine(domaine string) []ldapinterface.LDAPEntry {
	return []ldapinterface.LDAPEntry{
		candidate.OUEntry{Name: "users", BaseDN: domaine},
		candidate.OUEntry{Name: "groups", BaseDN: domaine},
	}
}

// EntreeDeBase rend l'entrée que désigne un baseObject, comme une recherche
// `base` la rendrait — vide si elle n'existe pas.
//
// Le gestionnaire s'en sert quand une recherche `one` ou `sub` ne rend rien :
// une base qui existe et que le compte peut lire, mais sans enfant, est un
// SUCCÈS sans entrée, pas `noSuchObject` (TO-DO 245 — `one` sous un compte).
func EntreeDeBase(db *sql.DB, baseObject string, j *ldapjournal.Operation) ([]ldapinterface.LDAPEntry, error) {
	return resolveBaseScope(db, baseObject, j)
}
