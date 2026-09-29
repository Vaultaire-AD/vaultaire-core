package candidate

import (
	"fmt"
	"strings"
	ldaptools "vaultaire/core/ldap/LDAP-TOOLS"
	ldapstorage "vaultaire/core/ldap/LDAP_Storage"
)

type UserEntry struct {
	User   ldapstorage.User
	BaseDN string
	Groups []string
	// Nouveaux champs pour compatibilité Nextcloud
	DisplayName string   // Firstname + Lastname
	GivenName   string   // Firstname
	Sn          string   // Lastname
	Uid         string   // Username
	MemberOf    []string // Groupes

	// Rattachements : les domaines où vit RÉELLEMENT le compte, c'est-à-dire ceux
	// des groupes par lesquels il a été trouvé. Sert au contrôle d'accès, et à
	// rien d'autre — voir Domaines().
	//
	// Distinct de BaseDN, qui est le domaine dont le DN est composé : `ToRootDN`
	// ne garde que les deux derniers labels, si bien qu'un compte de
	// « admin.enov.local » et un compte de « enov.local » portent le MÊME DN.
	// Confondre les deux champs revient à n'avoir aucun contrôle.
	Rattachements []string

	// ServiceRights : clés RBAC de service (read:nexus…) accordées au compte.
	// Renseigné par la recherche UNIQUEMENT quand l'attribut est demandé nommément et
	// que le compte lié a le droit de le lire — voir newmodule/service_rights.go.
	ServiceRights []string
}

// AttrServiceRights est le nom (en minuscules) de l'attribut opérationnel qui
// porte les droits de service d'un compte.
const AttrServiceRights = "vaultaireservicerights"

func (u UserEntry) DN() string {
	return fmt.Sprintf("uid=%s,ou=users,%s", u.User.Username, ldaptools.ToRootDN(u.BaseDN))
}

// Domaines — voir ldapinterface.LDAPEntry.
//
// Rend `Rattachements`, et RIEN d'autre. Surtout pas `BaseDN` en secours :
// BaseDN est le domaine qui compose le DN, et sur ce chemin c'est celui que le
// client a DEMANDÉ, pas celui où vit le compte. S'en servir pour décider des
// droits autoriserait tout compte par construction — le filtre ne verrait jamais
// que le domaine qui vient d'être autorisé. C'était le défaut de la première
// version de ce correctif.
//
// Une liste vide écarte l'entrée. C'est ce qui doit arriver à une UserEntry
// construite sans renseigner ses rattachements : l'oubli rend le compte
// invisible, il ne le diffuse pas.
func (u UserEntry) Domaines() []string {
	return u.Rattachements
}

// ObjectClasses — ce que l'entrée déclare ÊTRE.
//
// # posixAccount a été retiré — point 123
//
// Il était déclaré, et pas un seul attribut POSIX n'était servi : ni uidNumber,
// ni gidNumber, ni homeDirectory, ni loginShell, ni gecos. Un client RFC 2307 —
// sssd, nslcd, un NAS en mode « LDAP Unix » — trouvait donc l'entrée sur
// `(objectClass=posixAccount)`, puis échouait à construire le compte. L'erreur
// apparaissait loin de sa cause, et la cause était ici.
//
// Ce qui change pour les clients : SEULE la réponse à un filtre sur cette classe.
// Aucun attribut ne disparaît, puisque aucun n'était servi. Un client qui filtre
// sur `person`, `inetOrgPerson`, `user`, `objectClass=*`, ou simplement sur `uid`
// / `cn` / `mail` ne voit aucune différence — c'est-à-dire Keycloak, Nextcloud,
// JumpServer et les équipements réseau.
//
// Servir POSIX pour de bon reste possible ; ce serait un lot à part, avec une
// source STABLE pour uidNumber et gidNumber — un compteur en base, jamais un
// hachage du nom, deux comptes qui collisionnent partageraient l'UID donc les
// fichiers. Et il faudrait accepter qu'un poste puisse alors s'authentifier par
// sssd, hors du chemin Vaultaire : donc hors second facteur et hors révocation.
//
// Ce qu'il ne faut pas refaire, c'est annoncer sans servir : cela fait chercher
// chez le client un défaut qui est ici.
func (u UserEntry) ObjectClasses() []string {
	return []string{"inetOrgPerson", "organizationalPerson", "person", "user"}
}

func (u UserEntry) GetAttributes(requested []string, typesOnly bool) map[string][]string {
	// Tous les attributs possibles pour l'utilisateur
	all := map[string][]string{
		"uid":            {u.User.Username},
		"samaccountname": {u.User.Username},
		"cn":             {u.User.Firstname + " " + u.User.Lastname},
		"displayname":    {u.User.Firstname + " " + u.User.Lastname},
		"givenname":      {u.User.Firstname},
		"sn":             {u.User.Lastname},
		"mail":           {u.User.Email},
		"memberof":       u.Groups,
		"dn":             {u.DN()},
		// "ou":             {"users"},
		"objectclass": u.ObjectClasses(),
		"entryuuid":   {fmt.Sprintf("%s", u.User.Username)},
		"nsuniqueid":  {fmt.Sprintf("vaultaire-%s", u.User.Username)},
		"objectguid":  {fmt.Sprintf("vaultaire-%s", u.User.Username)},
		"guid":        {fmt.Sprintf("vaultaire-%s", u.User.Username)},
		"ipauniqueid": {fmt.Sprintf("vaultaire-%s", u.User.Username)},
	}
	// Un attribut sans valeur n'existe pas en LDAP (RFC 4512 §2.5) : absent
	// plutôt que vide.
	if len(u.ServiceRights) > 0 {
		all[AttrServiceRights] = u.ServiceRights
	}

	// LES HORODATAGES — point 126.
	//
	// C'est sur `modifyTimestamp` que s'appuie la synchronisation INCRÉMENTALE de
	// Keycloak. Sans lui, seule la synchronisation complète fonctionne : elle
	// relit tout l'annuaire à chaque passage, et bute sur `sizeLimitExceeded`
	// au-delà de dix mille entrées.
	//
	// Opérationnels, comme les identifiants ci-dessus : ils ne sortent que
	// demandés nommément ou par « + ». C'est ce que dit la RFC 4511 §4.5.1, et
	// c'est ce que fait Keycloak, qui les nomme.
	//
	// Absents si la base n'a pas su les rendre — une date fausse est pire qu'une
	// date absente ici : un client incrémental qui lit une date aberrante saute
	// des entrées ou les relit toutes, sans qu'aucune erreur ne le dise.
	if t := ldaptools.VersGeneralizedTime(u.User.Created_at); t != "" {
		all[ldaptools.AttrCreeLe] = []string{t}
	}
	if t := ldaptools.VersGeneralizedTime(u.User.Modified_at); t != "" {
		all[ldaptools.AttrModifieLe] = []string{t}
	}

	result := make(map[string][]string)
	includeAll := len(requested) == 0 || contains(requested, "*")
	includeOperational := contains(requested, "+")

	for k, v := range all {
		// Un attribut OPÉRATIONNEL ne sort que s'il a été demandé : soit
		// nommément, soit par « + ». RFC 4511 §4.5.1 — « * » désigne les
		// attributs UTILISATEUR, pas les attributs opérationnels.
		//
		// Ce bloc faisait l'inverse : il entrait dans la branche « non demandé »
		// puis ajoutait quand même l'attribut dès qu'il portait une valeur. Comme
		// entryuuid, nsuniqueid, objectguid, guid et ipauniqueid en portent
		// toujours une, ils partaient à CHAQUE recherche, quoi que le client ait
		// demandé — y compris sur « 1.1 », qui veut dire « aucun attribut ».
		//
		// Deux conséquences : des identifiants internes diffusés sans qu'on les
		// demande, et les clients qui utilisent « 1.1 » pour un simple test
		// d'existence recevaient cinq attributs à analyser.
		if isOperational(k) && !includeOperational && !contains(requested, k) {
			continue
		}

		// « * », un nom explicite, ou « + » pour un opérationnel.
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

func (u UserEntry) GetAttribute(attr string) []string {
	attr = strings.ToLower(attr)
	res := u.GetAttributes([]string{attr}, false)
	return res[attr]
}

// helpers
func contains(list []string, s string) bool {
	for _, item := range list {
		if strings.EqualFold(item, s) {
			return true
		}
	}
	return false
}

func isOperational(attr string) bool {
	switch strings.ToLower(attr) {
	case "entryuuid", "nsuniqueid", "objectguid", "guid", "ipauniqueid", AttrServiceRights,
		ldaptools.AttrCreeLe, ldaptools.AttrModifieLe:
		return true
	default:
		return false
	}
}
