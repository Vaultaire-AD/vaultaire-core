package scope

import (
	"strings"
	"testing"
)

// Le point 124 : un baseObject qui ne désigne rien doit rendre `noSuchObject`
// (32), et non un succès sans entrée. Ce fichier éprouve la RÈGLE — quel domaine
// le serveur sert, et quel ancêtre il nomme quand la base n'en est pas un.

// annuaire fabrique le prédicat à partir des domaines où vivent des GROUPES.
// C'est la forme que prend la table en base : une ligne par groupe, portant son
// domaine.
func annuaire(domainesDeGroupes ...string) estServi {
	return servi(domainesDeGroupes)
}

const parentDN = "dc=enov,dc=local"

// LE test de la reprise : un domaine RACINE est servi dès qu'un de ses
// sous-domaines porte des groupes.
//
// La première version de ce correctif testait une ÉGALITÉ sur la table des
// groupes. Or un parc ordinaire range ses groupes dans `dev.acme.lan` et
// `svc.acme.lan` — et c'est `dc=acme,dc=lan` que le RootDSE annonce, parce que
// `ToRootDN` ne garde que deux labels, et c'est `dc=acme,dc=lan` que Keycloak
// reçoit comme « Users DN ». Le serveur aurait répondu « cet objet n'existe pas »
// pour la base qu'il venait lui-même d'annoncer : une panne totale, pas une
// dégradation.
func TestUneRacineEstServieParSesSousDomaines(t *testing.T) {
	a := annuaire("dev.acme.lan", "svc.acme.lan")

	ancetre, valide := ancetreExistant("dc=acme,dc=lan", a)
	if !valide {
		t.Fatalf("« dc=acme,dc=lan » refusé alors que des groupes vivent dans ses "+
			"sous-domaines — c'est pourtant le namingContext annoncé (matchedDN=%q)", ancetre)
	}

	// Et la même base avec une unité d'organisation devant, comme l'envoient les
	// clients.
	for _, base := range []string{
		"ou=users,dc=acme,dc=lan",
		"cn=Users,dc=acme,dc=lan",
		"ou=people,dc=acme,dc=lan",
	} {
		if _, valide := ancetreExistant(base, a); !valide {
			t.Errorf("%q refusé", base)
		}
	}
}

// LA FORME DU DN NE DÉCIDE DE RIEN.
//
// Une première version n'acceptait que `ou=users` et `ou=groups`. Or le résolveur
// ignore la partie unité d'organisation en scope `one` et `sub` : il travaille
// sur le domaine. Refuser les autres formes rendait `noSuchObject` à
// `cn=Users,dc=…` — le conteneur du préréglage « Active Directory » de Keycloak —
// et à `ou=people,dc=…`, sur des clients qui fonctionnaient.
func TestLaFormeDuDNNeDecideDeRien(t *testing.T) {
	a := annuaire("enov.local")

	for _, base := range []string{
		"dc=enov,dc=local",
		"ou=users,dc=enov,dc=local",
		"ou=groups,dc=enov,dc=local",
		"ou=machines,dc=enov,dc=local",
		"cn=Users,dc=enov,dc=local",
		"o=acme,dc=enov,dc=local",
		"uid=alice,ou=users,dc=enov,dc=local",
		"OU=Users,DC=Enov,DC=Local",
	} {
		if _, valide := ancetreExistant(base, a); !valide {
			t.Errorf("%q refusé : seul le domaine doit décider", base)
		}
	}
}

// Un domaine que rien ne sert n'est pas valide, et aucun ancêtre n'est nommé.
func TestUnDomaineNonServiNEstPasValide(t *testing.T) {
	ancetre, valide := ancetreExistant("dc=inconnu,dc=example", annuaire("enov.local"))
	if valide {
		t.Error("« dc=inconnu,dc=example » passe pour une base valide")
	}
	if ancetre != "" {
		t.Errorf("matchedDN = %q : aucun ancêtre n'est servi, il doit être vide", ancetre)
	}
}

// matchedDN DIT OÙ LE CHEMIN SE ROMPT.
//
// C'est toute la valeur du code 32 : sans ce champ, le client sait seulement que
// quelque chose ne va pas dans son DN, pas lequel de ses composants.
func TestMatchedDNNommeLePlusProcheAncetreServi(t *testing.T) {
	a := annuaire("enov.local")

	ancetre, valide := ancetreExistant("dc=admin,dc=enov,dc=local", a)
	if valide {
		t.Error("un sous-domaine que rien ne sert passe pour valide")
	}
	if ancetre != parentDN {
		t.Errorf("matchedDN = %q, attendu %q — le parent est servi, c'est lui qu'il faut nommer",
			ancetre, parentDN)
	}

	// Deux niveaux manquants : on remonte jusqu'à celui qui est servi.
	ancetre, _ = ancetreExistant("dc=a,dc=b,dc=enov,dc=local", a)
	if ancetre != parentDN {
		t.Errorf("matchedDN = %q après deux niveaux manquants, attendu %q", ancetre, parentDN)
	}
}

// L'ANCÊTRE EST UNE ENTRÉE QUE LE SERVEUR SERT, et un ancêtre du DN demandé.
//
// Trois erreurs sont fermées ici. Rendre le DN lui-même — « cet objet n'existe
// pas ; le plus proche qui existe est ce même objet » — fait boucler les
// bibliothèques qui remontent l'arbre. Reconstruire l'ancêtre au lieu de le
// prendre dans le DN demandé envoie vers une autre branche, parce que `ToRootDN`
// ne garde que deux labels. Et découper simplement le DN d'un cran rend des DN
// qui ne sont AUCUNE entrée : `dc=lan`, ou `cn=Users,dc=acme,dc=lan`.
//
// Le DN d'un domaine servi n'a aucun de ces trois défauts : c'est une entrée —
// une recherche `base` dessus la rend — et il est composé des propres composants
// `dc=` du DN demandé.
func TestLAncetreEstUneEntreeServie(t *testing.T) {
	a := annuaire("enov.local", "admin.enov.local")

	cas := map[string]string{
		"uid=bob,ou=users,dc=enov,dc=local":          parentDN,
		"uid=bob,ou=users,dc=admin,dc=enov,dc=local": "dc=admin,dc=enov,dc=local",
		"ou=users,dc=enov,dc=local":                  parentDN,
		"cn=Users,dc=enov,dc=local":                  parentDN,
		// La base EST le domaine servi : pas d'ancêtre, plutôt que de se désigner
		// elle-même.
		"dc=enov,dc=local": "",
	}

	for base, attendu := range cas {
		ancetre, valide := ancetreExistant(base, a)
		if !valide {
			t.Errorf("%q refusé", base)
			continue
		}
		if ancetre != attendu {
			t.Errorf("%q : matchedDN = %q, attendu %q", base, ancetre, attendu)
		}
		if ancetre != "" && strings.EqualFold(ancetre, base) {
			t.Errorf("%q : matchedDN est le DN lui-même — un client qui remonte "+
				"l'arbre bouclerait", base)
		}
		if ancetre != "" && !strings.HasSuffix(strings.ToLower(base), strings.ToLower(ancetre)) {
			t.Errorf("%q : matchedDN %q n'est pas un ancêtre du DN demandé — il "+
				"désigne une autre branche", base, ancetre)
		}
	}
}

// UN DOMAINE SANS AUCUN GROUPE N'EST PAS SERVI — et c'est un changement visible.
//
// Le résolveur fabriquait les unités d'organisation `users` et `groups` pour
// n'importe quel domaine, servi ou non : une recherche sur un domaine inventé
// rendait donc deux entrées inventées. C'est ce que le point 124 arrête.
//
// La conséquence à connaître : un annuaire qui ne porte encore AUCUN groupe ne
// sert plus rien — toute recherche autre que le RootDSE rend `noSuchObject`. Ce
// n'est pas une perte d'entrée, c'est un succès vide devenu une erreur franche.
func TestUnAnnuaireSansGroupeNeSertRien(t *testing.T) {
	vide := annuaire()

	for _, base := range []string{"dc=enov,dc=local", "ou=users,dc=enov,dc=local"} {
		ancetre, valide := ancetreExistant(base, vide)
		if valide {
			t.Errorf("%q passe pour servi alors qu'aucun groupe n'existe", base)
		}
		if ancetre != "" {
			t.Errorf("%q : matchedDN = %q, attendu vide", base, ancetre)
		}
	}
}

// Le domaine est interrogé de proche en proche, et on s'arrête au premier servi.
func TestOnSArreteAuPremierDomaineServi(t *testing.T) {
	var demandés []string
	a := func(d string) bool {
		demandés = append(demandés, d)
		return strings.EqualFold(d, "enov.local")
	}

	ancetreExistant("dc=a,dc=b,dc=enov,dc=local", a)

	attendu := []string{"a.b.enov.local", "b.enov.local", "enov.local"}
	if len(demandés) != len(attendu) {
		t.Fatalf("%d interrogation(s) : %v, attendu %v", len(demandés), demandés, attendu)
	}
	for i := range attendu {
		if !strings.EqualFold(demandés[i], attendu[i]) {
			t.Errorf("interrogation %d : %q, attendu %q", i, demandés[i], attendu[i])
		}
	}
}

// La casse d'un nom de domaine ne décide de rien, des deux côtés.
func TestLaCasseNeDecideDeRien(t *testing.T) {
	a := annuaire("Dev.Acme.Lan")

	for _, base := range []string{"dc=acme,dc=lan", "DC=Acme,DC=Lan", "dc=ACME,dc=LAN"} {
		if _, valide := ancetreExistant(base, a); !valide {
			t.Errorf("%q refusé alors que « Dev.Acme.Lan » porte des groupes", base)
		}
	}
}

// Un suffixe n'est pas un sous-domaine : « faux-acme.lan » ne rend pas
// « acme.lan » servi.
func TestUnSuffixeNEstPasUnSousDomaine(t *testing.T) {
	if _, valide := ancetreExistant("dc=acme,dc=lan", annuaire("faux-acme.lan")); valide {
		t.Error("« faux-acme.lan » fait passer « acme.lan » pour servi")
	}
}
