package candidate

import "strings"

type SchemaEntry struct {
	CN                string
	CreateTimestamp   []string
	ModifyTimestamp   []string
	ObjectClassDefs   []string
	LdapSyntaxes      []string
	AttributeTypes    []string
	MatchingRules     []string
	MatchingRuleUse   []string
	DITContentRules   []string
	NameForms         []string
	DITStructureRules []string
}

func (s SchemaEntry) DN() string {
	return "cn=schema"
}

// Domaines — voir ldapinterface.LDAPEntry. Comme le RootDSE, le sous-schéma
// n'appartient à aucun domaine et passe par le chemin qui court-circuite le
// filtre d'autorisation.
func (s SchemaEntry) Domaines() []string {
	return nil
}

func (s SchemaEntry) ObjectClasses() []string {
	return []string{"top", "subschema"}
}

func (s SchemaEntry) GetAttributes(requested []string, typesOnly bool) map[string][]string {
	// On mappe les champs de la structure vers la réponse LDAP
	all := map[string][]string{
		"objectClass":       {"top", "subschema"},
		"cn":                {s.CN},
		"objectClasses":     s.ObjectClassDefs,
		"attributeTypes":    s.AttributeTypes,
		"createTimestamp":   s.CreateTimestamp,
		"modifyTimestamp":   s.ModifyTimestamp,
		"ldapSyntaxes":      s.LdapSyntaxes,
		"matchingRules":     s.MatchingRules,
		"matchingRuleUse":   s.MatchingRuleUse,
		"dITContentRules":   s.DITContentRules,
		"nameForms":         s.NameForms,
		"dITStructureRules": s.DITStructureRules,
	}

	// Filtrage sélectif
	if len(requested) == 0 || (len(requested) == 1 && requested[0] == "*") {
		return all
	}

	filtered := make(map[string][]string)
	for _, attr := range requested {
		key := strings.ToLower(attr)
		// Recherche insensible à la casse
		for k, v := range all {
			if strings.ToLower(k) == key {
				filtered[k] = v
			}
		}
	}
	return filtered
}

func (s SchemaEntry) GetAttribute(attr string) []string {
	attr = strings.ToLower(attr)
	res := s.GetAttributes([]string{attr}, false)
	if vals, ok := res[attr]; ok {
		return vals
	}
	for k, v := range res {
		if strings.EqualFold(k, attr) {
			return v
		}
	}
	return nil
}

// NewSchemaEntry construit l'entrée de schéma complète.
// Elle définit les règles de validation que les clients (Nextcloud, Windows, etc.)
// utiliseront pour interroger ton annuaire.
// La branche d'OID privés de Vaultaire — point 125.
//
// # Pourquoi elle existe
//
// Un attribut servi doit être déclaré, et une déclaration doit porter un
// `numericoid`. L'ancienne ligne écrivait `vaultaireServiceRights-oid`, qui n'en
// est pas un : un analyseur strict — Apache Directory Studio, python-ldap avec
// chargement de schéma, les outils OpenLDAP — rejette alors TOUTE la liste
// `attributeTypes`, pas seulement cette ligne. Le sous-schéma entier devenait
// inutilisable pour un caractère.
//
// # Pourquoi 99999, et ce qu'il faudra en faire
//
// 1.3.6.1.4.1 est la branche des numéros d'entreprise attribués par l'IANA.
// 99999 n'est attribué à personne : c'est la valeur qu'on emploie dans les
// exemples. Elle est donc PROVISOIRE, et c'est écrit ici pour que personne ne la
// prenne pour définitive.
//
// Le jour où Vaultaire obtient un numéro — la demande est gratuite auprès de
// l'IANA —, ces OID changent. Les clients qui ont mis le sous-schéma en cache
// devront le relire ; c'est le seul coût, et il est moindre que celui d'un
// sous-schéma qu'aucun outil ne sait lire.
//
// # Ce qui est rangé ici, et ce qui ne l'est pas
//
// Les attributs que Vaultaire invente, et ceux qu'il sert sous le NOM d'un autre
// annuaire sans en servir la sémantique. `objectGUID` est un identifiant binaire
// chez Active Directory ; ici c'est une chaîne dérivée du nom. Le déclarer sous
// l'OID d'AD prétendrait servir ce qu'AD sert. Le nom suffit aux clients — c'est
// par lui qu'ils cherchent — et l'OID dit la vérité.
//
// Les attributs dont la sémantique EST celle du standard — `cn`, `uid`, `mail`,
// `member`, `memberOf`, `sAMAccountName`, les horodatages — gardent leur OID
// officiel.
const (
	OIDBrancheVaultaire = "1.3.6.1.4.1.99999.1"

	oidServiceRights = OIDBrancheVaultaire + ".1"
	oidNsUniqueID    = OIDBrancheVaultaire + ".2"
	oidObjectGUID    = OIDBrancheVaultaire + ".3"
	oidGUID          = OIDBrancheVaultaire + ".4"
	oidIPAUniqueID   = OIDBrancheVaultaire + ".5"
	oidEntryUUID     = OIDBrancheVaultaire + ".6"

	// Les classes de compatibilité, pour la même raison que les attributs
	// ci-dessus : le NOM est celui d'Active Directory, la sémantique n'est pas la
	// sienne — voir leur déclaration.
	oidClasseUser  = OIDBrancheVaultaire + ".100"
	oidClasseGroup = OIDBrancheVaultaire + ".101"
)

// Les syntaxes employées par les déclarations ci-dessous.
const (
	synChaine     = "1.3.6.1.4.1.1466.115.121.1.15" // Directory String
	synIA5        = "1.3.6.1.4.1.1466.115.121.1.26" // IA5 String
	synDN         = "1.3.6.1.4.1.1466.115.121.1.12" // DN
	synOID        = "1.3.6.1.4.1.1466.115.121.1.38" // OID
	synHorodatage = "1.3.6.1.4.1.1466.115.121.1.24" // Generalized Time
	// La syntaxe d'une ASSERTION de sous-chaîne, qui n'est pas celle de la valeur
	// comparée : `caseIgnoreSubstringsMatch` reçoit « jo*n*doe », pas une chaîne
	// ordinaire (RFC 4517 §4.2.6). Les déclarer avec la syntaxe de la valeur était
	// faux, et invisible tant que personne ne lisait le schéma.
	synSousChaine = "1.3.6.1.4.1.1466.115.121.1.58"
)

// HorodatageDuSchema est la date du dernier changement de ce fichier.
//
// # Pourquoi une constante, et pas l'heure
//
// Les deux dates du sous-schéma étaient FIGÉES au 14 mars 2026 — le jour où
// quelqu'un les a tapées. Un client qui s'en sert pour savoir si le schéma a
// changé lisait donc toujours la même réponse, y compris après une mise à jour
// qui le change vraiment.
//
// La correction évidente — l'instant du démarrage — est pire : deux nœuds du
// cluster derrière le même nom serviraient des dates DIFFÉRENTES pour un schéma
// identique, et le même client relirait le schéma à chaque bascule et à chaque
// redémarrage. On remplacerait « ne change jamais » par « change tout le temps,
// y compris quand rien n'a changé ».
//
// Le schéma est une constante de la compilation : sa date en est une aussi. Elle
// est la même sur tous les nœuds, et elle ne bouge que lorsque le schéma bouge.
//
// # Ce qui empêche de l'oublier
//
// Un test calcule l'empreinte du schéma servi et la compare à une valeur
// enregistrée. Modifier une déclaration sans toucher à cette date fait échouer
// le test, en disant quoi faire — c'est la seule façon de tenir une date à jour
// à la main.
const HorodatageDuSchema = "20260929000000Z"

// NewSchemaEntry construit l'entrée de sous-schéma.
//
// # Ce qu'elle doit être
//
// Le reflet exact de ce que les entrées annoncent et servent. Elle ne l'était
// pas : elle déclarait `2.5.6.0` pour `top` ET pour `subschema`, donnait à
// `groupOfNames` l'OID de `residentialPerson`, et passait sous silence la moitié
// de ce qui est servi — `inetOrgPerson`, `displayName`, `givenName`, les
// identifiants d'entrée.
//
// Un test interdit désormais l'écart : chaque `objectClass` annoncée par une
// entrée, et chaque attribut qu'elle sert, doit être déclaré ici.
func NewSchemaEntry() SchemaEntry {
	return SchemaEntry{
		CN: "schema",

		// Les classes que les entrées annoncent réellement — et elles seules.
		//
		// Les OID ont été repris un par un. Deux étaient faux : `subschema`
		// portait celui de `top`, et `groupOfNames` portait `2.5.6.10`, qui est
		// `residentialPerson`. Un client qui range les classes par OID en
		// déduisait n'importe quoi.
		ObjectClassDefs: []string{
			"( 2.5.6.0 NAME 'top' ABSTRACT MUST objectClass )",
			"( 2.5.20.1 NAME 'subschema' AUXILIARY )",
			"( 2.5.6.6 NAME 'person' SUP top STRUCTURAL MUST ( sn $ cn ) )",
			"( 2.5.6.7 NAME 'organizationalPerson' SUP person STRUCTURAL )",
			"( 2.16.840.1.113730.3.2.2 NAME 'inetOrgPerson' SUP organizationalPerson STRUCTURAL " +
				"MAY ( uid $ mail $ displayName $ givenName ) )",
			"( 2.5.6.9 NAME 'groupOfNames' SUP top STRUCTURAL MUST ( member $ cn ) )",
			// `user` et `group` sont les noms d'Active Directory, servis pour les
			// clients qui cherchent par eux.
			//
			// Déclarées AUXILIAIRES, et sous la branche Vaultaire, alors qu'elles
			// sont STRUCTURELLES chez AD. Deux raisons, et la première est une
			// contrainte : la RFC 4512 §2.4.2 veut qu'une entrée ait EXACTEMENT une
			// classe structurelle. Un compte annonce déjà `inetOrgPerson`, un groupe
			// `groupOfNames` — les déclarer structurelles rendrait chaque entrée
			// invalide aux yeux du client strict qu'on cherche justement à servir.
			//
			// La seconde est la règle employée partout ici : on ne reprend l'OID
			// d'un autre annuaire que lorsqu'on en sert la sémantique. Ce n'est pas
			// le cas — ni la nature de la classe, ni les attributs obligatoires
			// d'AD ne sont ceux-ci.
			"( " + oidClasseUser + " NAME 'user' AUXILIARY MAY ( uid $ mail ) )",
			"( " + oidClasseGroup + " NAME 'group' AUXILIARY MAY member )",
			"( 2.5.6.5 NAME 'organizationalUnit' SUP top STRUCTURAL MUST ou )",
			"( 0.9.2342.19200300.100.4.13 NAME 'domain' SUP top STRUCTURAL MUST dc )",
		},

		AttributeTypes: []string{
			"( 2.5.4.0 NAME 'objectClass' EQUALITY objectIdentifierMatch SYNTAX " + synOID + " )",
			"( 2.5.4.3 NAME 'cn' EQUALITY caseIgnoreMatch ORDERING caseIgnoreOrderingMatch " +
				"SUBSTR caseIgnoreSubstringsMatch SYNTAX " + synChaine + " )",
			"( 2.5.4.4 NAME 'sn' EQUALITY caseIgnoreMatch ORDERING caseIgnoreOrderingMatch " +
				"SUBSTR caseIgnoreSubstringsMatch SYNTAX " + synChaine + " )",
			"( 2.5.4.42 NAME 'givenName' EQUALITY caseIgnoreMatch ORDERING caseIgnoreOrderingMatch " +
				"SUBSTR caseIgnoreSubstringsMatch SYNTAX " + synChaine + " )",
			"( 2.16.840.1.113730.3.1.241 NAME 'displayName' EQUALITY caseIgnoreMatch " +
				"SUBSTR caseIgnoreSubstringsMatch SYNTAX " + synChaine + " SINGLE-VALUE )",
			"( 2.5.4.11 NAME 'ou' EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch " +
				"SYNTAX " + synChaine + " )",
			"( 0.9.2342.19200300.100.1.1 NAME 'uid' EQUALITY caseIgnoreMatch " +
				"ORDERING caseIgnoreOrderingMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX " + synChaine + " )",
			"( 0.9.2342.19200300.100.1.3 NAME 'mail' EQUALITY caseIgnoreIA5Match " +
				"SUBSTR caseIgnoreIA5SubstringsMatch SYNTAX " + synIA5 + " )",
			"( 0.9.2342.19200300.100.1.25 NAME 'dc' EQUALITY caseIgnoreIA5Match " +
				"SUBSTR caseIgnoreIA5SubstringsMatch SYNTAX " + synIA5 + " SINGLE-VALUE )",
			"( 1.2.840.113556.1.4.221 NAME 'sAMAccountName' EQUALITY caseIgnoreMatch SYNTAX " +
				synChaine + " SINGLE-VALUE )",
			// memberOf portait 1.2.840.113556.1.4.8, qui est `userAccountControl` —
			// un ENTIER de drapeaux chez Active Directory. Un client qui range les
			// attributs par OID lisait donc une liste de DN comme un masque de bits.
			// L'OID était recopié de la version antérieure : « repris un par un »
			// voulait dire relus, pas vérifiés.
			"( 1.2.840.113556.1.2.102 NAME 'memberOf' EQUALITY distinguishedNameMatch SYNTAX " +
				synDN + " )",
			"( 2.5.4.31 NAME 'member' EQUALITY distinguishedNameMatch SYNTAX " + synDN + " )",
			// `dn` n'est pas un type d'attribut : c'est le nom de l'entrée. Le
			// serveur le sert malgré tout comme un attribut, parce que des clients
			// le demandent ainsi. Il est donc déclaré sous le vrai type —
			// `distinguishedName` — avec `dn` comme second nom, ce que la syntaxe
			// d'une déclaration permet.
			"( 2.5.4.49 NAME ( 'distinguishedName' 'dn' ) EQUALITY distinguishedNameMatch SYNTAX " +
				synDN + " )",
			// Les horodatages, point 126. Opérationnels : c'est ce que dit
			// `USAGE directoryOperation`, et c'est pour cela qu'ils ne sortent que
			// demandés.
			"( 2.5.18.1 NAME 'createTimestamp' EQUALITY generalizedTimeMatch " +
				"ORDERING generalizedTimeOrderingMatch SYNTAX " + synHorodatage +
				" SINGLE-VALUE NO-USER-MODIFICATION USAGE directoryOperation )",
			"( 2.5.18.2 NAME 'modifyTimestamp' EQUALITY generalizedTimeMatch " +
				"ORDERING generalizedTimeOrderingMatch SYNTAX " + synHorodatage +
				" SINGLE-VALUE NO-USER-MODIFICATION USAGE directoryOperation )",
			// entryUUID sous la branche Vaultaire, et non sous 1.3.6.1.1.16.4.
			//
			// La RFC 4530 attache à cet OID la syntaxe UUID : un client strict
			// attend donc 128 bits écrits en hexadécimal. Vaultaire y sert le nom
			// d'utilisateur — ce n'est pas un identifiant stable, c'est le point
			// 129 —, donc reprendre l'OID standard promettrait une syntaxe que la
			// valeur ne respecte pas. Le nom suffit aux clients : c'est par lui que
			// Keycloak le demande.
			"( " + oidEntryUUID + " NAME 'entryUUID' EQUALITY caseIgnoreMatch SYNTAX " +
				synChaine + " SINGLE-VALUE NO-USER-MODIFICATION USAGE directoryOperation )",
			// Les alias de compatibilité, sous la branche Vaultaire : le nom est
			// celui d'un autre annuaire, la sémantique n'est pas la sienne.
			"( " + oidNsUniqueID + " NAME 'nsUniqueId' EQUALITY caseIgnoreMatch SYNTAX " +
				synChaine + " SINGLE-VALUE NO-USER-MODIFICATION USAGE directoryOperation )",
			"( " + oidObjectGUID + " NAME 'objectGUID' EQUALITY caseIgnoreMatch SYNTAX " +
				synChaine + " SINGLE-VALUE NO-USER-MODIFICATION USAGE directoryOperation )",
			"( " + oidGUID + " NAME 'guid' EQUALITY caseIgnoreMatch SYNTAX " +
				synChaine + " SINGLE-VALUE NO-USER-MODIFICATION USAGE directoryOperation )",
			"( " + oidIPAUniqueID + " NAME 'ipaUniqueID' EQUALITY caseIgnoreMatch SYNTAX " +
				synChaine + " SINGLE-VALUE NO-USER-MODIFICATION USAGE directoryOperation )",
			// Droits de service (Nexus…) accordés au compte.
			"( " + oidServiceRights + " NAME 'vaultaireServiceRights' EQUALITY caseIgnoreMatch " +
				"SYNTAX " + synChaine + " NO-USER-MODIFICATION USAGE directoryOperation )",
		},

		CreateTimestamp: []string{HorodatageDuSchema},
		ModifyTimestamp: []string{HorodatageDuSchema},

		LdapSyntaxes: []string{
			"( " + synChaine + " DESC 'Directory String' )",
			"( " + synIA5 + " DESC 'IA5 String' )",
			"( " + synOID + " DESC 'OID' )",
			"( " + synDN + " DESC 'DN' )",
			"( " + synHorodatage + " DESC 'Generalized Time' )",
			"( " + synSousChaine + " DESC 'Substring Assertion' )",
		},

		// Les règles que les déclarations ci-dessus NOMMENT. Une règle citée mais
		// non déclarée est le même défaut que l'attribut servi et non déclaré :
		// un analyseur strict s'arrête dessus.
		MatchingRules: []string{
			"( 2.5.13.2 NAME 'caseIgnoreMatch' SYNTAX " + synChaine + " )",
			"( 2.5.13.3 NAME 'caseIgnoreOrderingMatch' SYNTAX " + synChaine + " )",
			"( 2.5.13.4 NAME 'caseIgnoreSubstringsMatch' SYNTAX " + synSousChaine + " )",
			"( 2.5.13.5 NAME 'caseExactMatch' SYNTAX " + synChaine + " )",
			"( 2.5.13.0 NAME 'objectIdentifierMatch' SYNTAX " + synOID + " )",
			"( 2.5.13.1 NAME 'distinguishedNameMatch' SYNTAX " + synDN + " )",
			"( 2.5.13.27 NAME 'generalizedTimeMatch' SYNTAX " + synHorodatage + " )",
			"( 2.5.13.28 NAME 'generalizedTimeOrderingMatch' SYNTAX " + synHorodatage + " )",
			"( 1.3.6.1.4.1.1466.109.114.2 NAME 'caseIgnoreIA5Match' SYNTAX " + synIA5 + " )",
			"( 1.3.6.1.4.1.1466.109.114.3 NAME 'caseIgnoreIA5SubstringsMatch' SYNTAX " +
				synSousChaine + " )",
		},

		MatchingRuleUse:   []string{},
		DITContentRules:   []string{},
		NameForms:         []string{},
		DITStructureRules: []string{},
	}
}
