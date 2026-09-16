package clusterdatabase

import (
	"errors"
	"strings"
	"testing"
)

// La propriété d'une ligne de cluster_nodes.
//
// # Ce que ces tests gardent
//
// Une seule règle, et c'est celle dont dépend toute la chaîne de confiance de la
// découverte : **un nœud n'écrit que sa propre ligne**.
//
// Sans elle, un proxy enrôlé envoyait le hostname d'un core dans la trame 04_01,
// écrasait sa ligne — empreinte comprise —, et la liste servie aux agents
// annonçait dès lors l'empreinte de l'attaquant sous le nom du core. Les agents
// l'apprenaient, la plaçaient devant leurs serveurs statiques, et s'y
// connectaient pour s'authentifier.
//
// Les fonctions qui touchent la base ne sont pas éprouvées ici : elles exigent
// une base vivante. Ce qui l'est, c'est la RÈGLE de nommage du propriétaire —
// l'endroit où une erreur rouvrirait le trou sans qu'aucune requête ne change.

// TestUnCoreNEstJamaisUsurpableParUneSession.
//
// LE test de ce fichier. Les deux espaces de noms — celui des sessions et celui
// des cores — ne doivent jamais se croiser. Il ne suffit pas de le vérifier sur
// des exemples choisis : on éprouve la propriété DANS LES DEUX SENS, en passant
// le nom d'un core à la fonction qui accepte les identifiants de session.
func TestUnCoreNEstJamaisUsurpableParUneSession(t *testing.T) {
	hostnames := []string{
		"core-1", "288377fa59b5", "core.vaultaire.fr", "", "   ",
		// Un hostname qui ressemble lui-même à un identifiant de client.
		"6PAw6haNtSCa-14-08-2026",
	}
	for _, h := range hostnames {
		proprietaireCore := ProprietaireCoreLocal(h)

		if _, err := ProprietaireDepuisSession(proprietaireCore); err == nil {
			t.Errorf("ProprietaireCoreLocal(%q) = %q est accepté comme identifiant de "+
				"session : un client portant cet identifiant écrirait la ligne d'un core",
				h, proprietaireCore)
		}
	}
}

// TestChaqueCorePossedeSaPropreLigne.
//
// Sur un cluster à plusieurs cores, un propriétaire commun laisserait chacun
// écrire la ligne des autres — le défaut corrigé, sous une autre forme. Le cas
// est réel : la maquette de développement fait tourner deux cores.
func TestChaqueCorePossedeSaPropreLigne(t *testing.T) {
	a := ProprietaireCoreLocal("288377fa59b5")
	b := ProprietaireCoreLocal("a358bbd14ba1")

	if a == b {
		t.Fatalf("deux cores partagent le propriétaire %q : chacun écrirait la ligne de l'autre", a)
	}
	if ProprietaireCoreLocal("core-1") != ProprietaireCoreLocal("core-1") {
		t.Error("le propriétaire d'un core n'est pas stable d'un appel à l'autre : " +
			"il ne retrouverait pas sa ligne au redémarrage")
	}
}

// TestUnIdentifiantReserveEstRefuse : le refus est explicite et nommé.
func TestUnIdentifiantReserveEstRefuse(t *testing.T) {
	for _, id := range []string{"@core:x", "@", "@nimporte", "  @core:x  "} {
		_, err := ProprietaireDepuisSession(id)
		if !errors.Is(err, ErrProprietaireReserve) {
			t.Errorf("ProprietaireDepuisSession(%q) : erreur = %v, "+
				"ErrProprietaireReserve attendue", id, err)
		}
	}
}

// TestUneSessionSansMachineNEcritRien.
//
// FAIL-CLOSED. BoundClientSoftwareID est vide tant que la poignée de main 01_01
// n'a pas eu lieu — et pendant tout l'enrôlement, délibérément. Accepter la
// chaîne vide créerait une ligne que personne ne pourrait plus jamais mettre à
// jour, et — la colonne étant UNIQUE — la deuxième échouerait sur un conflit
// incompréhensible.
func TestUneSessionSansMachineNEcritRien(t *testing.T) {
	for _, vide := range []string{"", "   ", "\t", "\n"} {
		if _, err := ProprietaireDepuisSession(vide); err == nil {
			t.Errorf("identifiant %q accepté : une ligne sans propriétaire serait créée", vide)
		}
	}
}

// TestUnIdentifiantOrdinaireEstAccepteTelQuel.
//
// Le contraire du précédent : la règle ne doit pas être si stricte qu'elle
// refuse un client légitime. Les identifiants réels ressemblent à
// « 6PAw6haNtSCa-14-08-2026 ».
func TestUnIdentifiantOrdinaireEstAccepteTelQuel(t *testing.T) {
	cas := map[string]string{
		"6PAw6haNtSCa-14-08-2026":   "6PAw6haNtSCa-14-08-2026",
		"  6PAw6haNtSCa-14-08-2026": "6PAw6haNtSCa-14-08-2026",
		"proxy-01":                  "proxy-01",
		"web.vaultaire.fr":          "web.vaultaire.fr",
	}
	for entree, attendu := range cas {
		got, err := ProprietaireDepuisSession(entree)
		if err != nil {
			t.Errorf("%q refusé : %v", entree, err)
			continue
		}
		if got != attendu {
			t.Errorf("%q → %q, attendu %q", entree, got, attendu)
		}
	}
}

// TestLePrefixeReserveNEstPasVide.
//
// Un préfixe vide ferait que TOUT identifiant commence par lui : plus aucune
// session ne pourrait s'enregistrer. Le défaut serait total et immédiat, donc
// visible — mais le test coûte une ligne, et il documente que la valeur compte.
func TestLePrefixeReserveNEstPasVide(t *testing.T) {
	if strings.TrimSpace(PrefixeProprietaireLocal) == "" {
		t.Fatal("le préfixe réservé est vide : aucune session ne pourrait s'enregistrer")
	}
	if !strings.HasPrefix(ProprietaireCoreLocal("x"), PrefixeProprietaireLocal) {
		t.Error("le propriétaire d'un core ne porte pas le préfixe réservé : " +
			"une session pourrait revendiquer sa ligne")
	}
}
