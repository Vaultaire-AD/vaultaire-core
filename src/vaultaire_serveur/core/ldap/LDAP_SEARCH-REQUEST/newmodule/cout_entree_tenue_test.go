package newmodule

import (
	"fmt"
	"runtime"
	"testing"

	"vaultaire/core/ldap/LDAP_SEARCH-REQUEST/newmodule/candidate"
	ldapinterface "vaultaire/core/ldap/LDAP_SEARCH-REQUEST/newmodule/candidate/ldap_interface"
	"vaultaire/core/ldap/LDAP_SEARCH-REQUEST/newmodule/security"
)

// CE QUE COÛTE UNE ENTRÉE TENUE — TO-DO 152.
//
// Une recherche paginée garde en mémoire, entre deux pages, les entrées qui
// restent à servir. `ldap.limites.max_paged_entries_held` borne leur nombre ;
// pour le choisir il faut savoir ce que pèse une entrée, et le savoir en le
// MESURANT — une estimation faite à la lecture de la structure oublie les
// en-têtes de chaînes, les tranches et l'interface qui emballe le tout.
//
//	go test -run '^$' -bench EntreeTenue ./core/ldap/LDAP_SEARCH-REQUEST/newmodule/
//
// La mesure porte sur ce qui est RÉELLEMENT tenu : des comptes construits
// comme le résolveur les construit — chaînes distinctes par compte, groupes
// partagés —, puis passés par le contrôle d'accès, qui en fait la copie
// restreinte que la pagination garde.
//
// Le chiffre de la page d'exploitation (docs/exploitation/ldap_bornes.md) vient
// d'ici. S'il bouge de plus de quelques dizaines d'octets, c'est qu'un champ a
// été ajouté à l'entrée : la page est à relire.

// comptesCommeLeResolveur fabrique n comptes, chacun membre de `groupes`
// groupes.
func comptesCommeLeResolveur(n, groupes int) []ldapinterface.LDAPEntry {
	// Les DN de groupe sont formatés une fois et partagés par tous les
	// membres, comme dans loadGroupsAndUsers.
	appartenances := make([]candidate.Appartenance, groupes)
	for g := range appartenances {
		appartenances[g] = candidate.Appartenance{
			DN:      fmt.Sprintf("cn=groupe-%03d,ou=groups,dc=acme,dc=lan", g),
			Domaine: "acme.lan",
		}
	}

	entrees := make([]ldapinterface.LDAPEntry, n)
	for i := range entrees {
		u := candidate.UserEntry{BaseDN: "acme.lan", Rattachements: []string{"acme.lan"}}
		u.User.ID = i
		u.User.Username = fmt.Sprintf("prenom%05d.nom%05d", i, i)
		u.User.Firstname = fmt.Sprintf("Prenom%05d", i)
		u.User.Lastname = fmt.Sprintf("Nom%05d", i)
		u.User.Email = fmt.Sprintf("prenom%05d.nom%05d@acme.lan", i, i)
		u.User.Created_at = "2026-01-15 09:30:00"
		u.User.Modified_at = "2026-09-28 14:05:12"
		u.User.EntryUUID = fmt.Sprintf("597ae2f6-16a6-4027-98f4-%012d", i)
		u.User.GroupDomain = "acme.lan"
		u.DisplayName = u.User.Firstname + " " + u.User.Lastname
		u.GivenName, u.Sn, u.Uid = u.User.Firstname, u.User.Lastname, u.User.Username
		// Chaque compte a SA tranche d'appartenances — le résolveur la compose
		// par compte —, sur des DN partagés.
		u.Groups = append([]candidate.Appartenance(nil), appartenances...)
		entrees[i] = u
	}
	return entrees
}

func tasEnService() uint64 {
	runtime.GC()
	runtime.GC()
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return m.HeapAlloc
}

func mesurerEntreeTenue(b *testing.B, groupes int) {
	const n = 50_000
	portee := security.NouvellePortee([]string{"(1:acme.lan)"})

	for i := 0; i < b.N; i++ {
		avant := tasEnService()
		// Ce que la pagination garde : la sortie du contrôle d'accès. Les
		// entrées d'origine, elles, ne sont plus référencées et sont rendues
		// par le ramasse-miettes avant la seconde mesure.
		tenues, _ := portee.Filtrer(comptesCommeLeResolveur(n, groupes))
		apres := tasEnService()
		b.ReportMetric(float64(apres-avant)/float64(len(tenues)), "octets/entrée")
		// Tenues jusqu'ici : sans cette ligne, le compilateur les tient pour
		// mortes dès leur dernier usage et la mesure porterait sur du vide.
		runtime.KeepAlive(tenues)
	}
}

func BenchmarkEntreeTenue_1Groupe(b *testing.B)   { mesurerEntreeTenue(b, 1) }
func BenchmarkEntreeTenue_5Groupes(b *testing.B)  { mesurerEntreeTenue(b, 5) }
func BenchmarkEntreeTenue_20Groupes(b *testing.B) { mesurerEntreeTenue(b, 20) }
