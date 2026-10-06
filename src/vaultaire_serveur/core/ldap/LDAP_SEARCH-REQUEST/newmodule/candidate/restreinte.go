package candidate

import (
	ldapinterface "vaultaire/core/ldap/LDAP_SEARCH-REQUEST/newmodule/candidate/ldap_interface"
)

// Les entrées qui ne nomment qu'elles-mêmes — TO-DO 132.
//
// `Restreinte` retire d'une entrée ce que ses attributs désignent et que
// l'appelant n'a pas le droit de lire (voir ldapinterface.LDAPEntry). Un
// domaine, le RootDSE et le sous-schéma ne désignent aucune autre entrée de
// l'annuaire : ils se rendent tels quels.
//
// Les deux entrées qui ont une vraie réponse à donner la portent dans leur
// propre fichier : `UserEntry` (`memberOf`) et `GroupEntry` (`member`).

// Restreinte — voir ldapinterface.LDAPEntry.
func (d DomainEntry) Restreinte(func(domaine string) bool) ldapinterface.LDAPEntry { return d }

// Restreinte — voir ldapinterface.LDAPEntry. Les `namingContexts` du RootDSE
// nomment bien des domaines, mais ils sont servis sans authentification et à
// dessein : c'est ainsi qu'un client découvre où chercher (RFC 4512 §5.1).
func (r RootDSEEntry) Restreinte(func(domaine string) bool) ldapinterface.LDAPEntry { return r }

// Restreinte — voir ldapinterface.LDAPEntry.
func (s SchemaEntry) Restreinte(func(domaine string) bool) ldapinterface.LDAPEntry { return s }
