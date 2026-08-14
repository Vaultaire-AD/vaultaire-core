package decouverte

import (
	"fmt"
	"strings"
	"testing"
)

// La découverte de nœuds joignables.
//
// # Ce que ces tests gardent
//
// Deux propriétés, et elles n'ont pas le même poids.
//
// La première est de sécurité : aucun nœud ne doit entrer dans la liste sans
// l'empreinte qui permettra de reconnaître sa clé. Sans elle, l'agent
// apprendrait une adresse et accepterait la première clé qui y répond — ce que
// le fichier d'empreintes existe précisément pour empêcher.
//
// La seconde est de disponibilité : la liste STATIQUE du fichier de
// configuration ne doit jamais être perdue. Elle est le dernier recours, et un
// agent qui la perd doit être visité à la main.

const empreinteBidon = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

func ligne(host, ip string, port int, role string, prio int, emp string) string {
	return fmt.Sprintf("%s|%s|%d|%s|%d|%s", host, ip, port, role, prio, emp)
}

// oublier remet l'état du paquet à neuf entre deux tests.
//
// L'état est global — un agent n'a qu'une liste — donc les tests se
// contamineraient sans cela, avec des échecs qui dépendraient de l'ordre
// d'exécution.
func oublier(t *testing.T) {
	t.Helper()
	mu.Lock()
	appris = nil
	recuUne = false
	mu.Unlock()
	t.Cleanup(func() {
		mu.Lock()
		appris = nil
		recuUne = false
		mu.Unlock()
	})
}

func TestAnalyserListe(t *testing.T) {
	contenu := strings.Join([]string{
		"2",
		ligne("core1", "10.0.0.1", 6666, "core", 0, empreinteBidon),
		ligne("proxy1", "10.0.0.2", 7070, "proxy", 5, empreinteBidon),
	}, "\n")

	noeuds, err := AnalyserListe(contenu)
	if err != nil {
		t.Fatalf("%v", err)
	}
	if len(noeuds) != 2 {
		t.Fatalf("%d nœud(s), attendu 2", len(noeuds))
	}
	if noeuds[0].Adresse() != "10.0.0.1:6666" {
		t.Errorf("adresse %q, attendu 10.0.0.1:6666", noeuds[0].Adresse())
	}
	if noeuds[1].Role != "proxy" || noeuds[1].Priorite != 5 {
		t.Errorf("second nœud = %+v", noeuds[1])
	}
	if noeuds[0].Empreinte != empreinteBidon {
		t.Errorf("empreinte %q perdue à l'analyse", noeuds[0].Empreinte)
	}
}

// TestUnNoeudSansEmpreinteEstRejete.
//
// LE test de sécurité de ce fichier. Un nœud annoncé sans empreinte est une
// adresse qu'on ne saurait pas reconnaître : s'y connecter reviendrait à
// accepter la première clé venue.
//
// Le core l'écarte déjà à l'émission. Ce test garde le second contrôle — celui
// de l'agent — parce que le core est authentifié, pas infaillible, et que ce qui
// est en jeu est ce que la machine acceptera comme serveur.
func TestUnNoeudSansEmpreinteEstRejete(t *testing.T) {
	cas := map[string]string{
		"empreinte vide":       "core1|10.0.0.1|6666|core|0|",
		"champ absent":         "core1|10.0.0.1|6666|core|0",
		"mauvaise fonction":    "core1|10.0.0.1|6666|core|0|MD5:xxxx",
		"chaîne quelconque":    "core1|10.0.0.1|6666|core|0|coucou",
		"minuscules":           "core1|10.0.0.1|6666|core|0|sha256:AAAA",
	}

	for nom, l := range cas {
		t.Run(nom, func(t *testing.T) {
			noeuds, err := AnalyserListe("1\n" + l)
			if err != nil {
				return // rejet au niveau de la liste : acceptable aussi
			}
			if len(noeuds) != 0 {
				t.Errorf("nœud retenu sans empreinte valable : %+v", noeuds[0])
			}
		})
	}
}

// TestUneLigneFautiveNEmportePasLesAutres : mieux vaut une liste partielle
// qu'aucune liste — un agent sans adresse est un agent qu'il faut visiter.
func TestUneLigneFautiveNEmportePasLesAutres(t *testing.T) {
	contenu := strings.Join([]string{
		"3",
		"n'importe quoi",
		ligne("core1", "10.0.0.1", 6666, "core", 0, empreinteBidon),
		"core2|10.0.0.9|0|core|0|" + empreinteBidon, // port nul
	}, "\n")

	noeuds, err := AnalyserListe(contenu)
	if err != nil {
		t.Fatalf("%v", err)
	}
	if len(noeuds) != 1 || noeuds[0].Hostname != "core1" {
		t.Fatalf("nœuds = %+v, attendu le seul core1", noeuds)
	}
}

// TestUnRoleInconnuEstRejete.
//
// Fail-closed. Un rôle inconnu vient d'un core plus récent ; s'y connecter
// reviendrait à traiter comme un serveur d'authentification quelque chose dont
// on ignore la nature.
func TestUnRoleInconnuEstRejete(t *testing.T) {
	noeuds, err := AnalyserListe("1\n" + ligne("x", "10.0.0.1", 6666, "passerelle", 0, empreinteBidon))
	if err != nil {
		t.Fatalf("%v", err)
	}
	if len(noeuds) != 0 {
		t.Errorf("nœud de rôle inconnu retenu : %+v", noeuds[0])
	}
}

// --- fusion -----------------------------------------------------------------

// TestLesStatiquesNeSontJamaisPerdus.
//
// LE test de disponibilité. Un agent qui remplacerait ses serveurs statiques par
// ceux reçus n'aurait plus rien à joindre le jour où la liste distribuée est
// vide ou fausse — et il faudrait repasser à la main sur les machines,
// c'est-à-dire exactement ce que la découverte existe pour éviter.
func TestLesStatiquesNeSontJamaisPerdus(t *testing.T) {
	oublier(t)
	Enregistrer([]Noeud{
		{Hostname: "proxy1", IP: "10.0.0.2", Port: 7070, Role: "proxy", Empreinte: empreinteBidon},
	})

	adresses := FusionnerAdresses([]string{"192.168.1.1:6666"})

	if len(adresses) != 2 {
		t.Fatalf("adresses = %v, attendu 2", adresses)
	}
	if adresses[0] != "10.0.0.2:7070" {
		t.Errorf("premier = %q : les nœuds appris passent devant", adresses[0])
	}
	if adresses[1] != "192.168.1.1:6666" {
		t.Errorf("dernier = %q : le statique doit rester en queue", adresses[1])
	}
}

func TestUnDoublonNEstEssayeQuUneFois(t *testing.T) {
	oublier(t)
	Enregistrer([]Noeud{
		{Hostname: "core1", IP: "10.0.0.1", Port: 6666, Role: "core", Empreinte: empreinteBidon},
	})

	adresses := FusionnerAdresses([]string{"10.0.0.1:6666", "10.0.0.9:6666"})
	if len(adresses) != 2 {
		t.Fatalf("adresses = %v, attendu 2 : le doublon a été essayé deux fois", adresses)
	}
}

// TestSansDecouverteLesStatiquesSuffisent : le cas d'un agent qui n'a encore
// rien reçu, ou d'un core qui n'annonce rien. Il doit rester joignable.
func TestSansDecouverteLesStatiquesSuffisent(t *testing.T) {
	oublier(t)
	adresses := FusionnerAdresses([]string{"192.168.1.1:6666"})
	if len(adresses) != 1 || adresses[0] != "192.168.1.1:6666" {
		t.Fatalf("adresses = %v", adresses)
	}
}

// --- enregistrement de la liste ---------------------------------------------

// TestUneListeVideNEcrasePasUneListePleine.
//
// Un core qui répond « aucun nœud » a peut-être une base indisponible, ou une
// migration de schéma qui vient de passer sans qu'aucun nœud ne se soit
// réenregistré. Effacer sur cette foi couperait l'agent de tout ce qu'il avait
// appris, au moment précis où le core va mal.
func TestUneListeVideNEcrasePasUneListePleine(t *testing.T) {
	oublier(t)
	Enregistrer([]Noeud{
		{Hostname: "core1", IP: "10.0.0.1", Port: 6666, Role: "core", Empreinte: empreinteBidon},
	})
	Enregistrer(nil)

	if len(Appris()) != 1 {
		t.Errorf("liste apprise = %v : une réponse vide l'a effacée", Appris())
	}
}

// TestLOrdreDuCoreEstConserve.
//
// L'agent ne retrie pas : l'ordre vient du serveur, qui seul voit le parc.
// Retrier ici substituerait la vue d'un agent à celle du cluster, et chaque
// agent le ferait avec SA version du code.
func TestLOrdreDuCoreEstConserve(t *testing.T) {
	oublier(t)
	Enregistrer([]Noeud{
		{Hostname: "zulu", IP: "10.0.0.9", Port: 6666, Role: "core", Empreinte: empreinteBidon},
		{Hostname: "alpha", IP: "10.0.0.1", Port: 6666, Role: "core", Empreinte: empreinteBidon},
	})

	adresses := FusionnerAdresses(nil)
	if len(adresses) != 2 || adresses[0] != "10.0.0.9:6666" {
		t.Errorf("adresses = %v : l'ordre du core a été modifié", adresses)
	}
}

func TestAJamaisRecuDeListe(t *testing.T) {
	oublier(t)
	if !AJamaisRecuDeListe() {
		t.Error("une liste est déclarée reçue avant toute réception")
	}
	Enregistrer(nil)
	if AJamaisRecuDeListe() {
		t.Error("une réponse vide compte comme reçue — c'est ce qui distingue " +
			"« le core n'annonce rien » de « on n'a pas encore demandé »")
	}
}

// --- composition des trames -------------------------------------------------

func TestConstruireDemandeNePorteAucunContenu(t *testing.T) {
	trame := ConstruireDemande("cle-de-session", "machine-42")
	lignes := strings.Split(trame, "\n")

	if len(lignes) != 5 {
		t.Fatalf("%d ligne(s), attendu 5 (en-tête seul, contenu vide) : %q", len(lignes), trame)
	}
	if lignes[0] != "04_03" {
		t.Errorf("ordre %q, attendu 04_03", lignes[0])
	}
	if lignes[4] != "machine-42" {
		t.Errorf("identifiant %q en cinquième ligne, attendu machine-42", lignes[4])
	}
}

func TestConstruireBattement(t *testing.T) {
	trame := ConstruireBattement("cle", "id", "proxy1")
	lignes := strings.Split(trame, "\n")
	if lignes[0] != "04_07" || lignes[5] != "proxy1" {
		t.Errorf("trame = %q", trame)
	}
}

// TestUneMetriqueNEstJamaisEnNotationExponentielle.
//
// Le core la lit avec ParseFloat, qui l'accepterait. Mais la table proxy_metrics
// est aussi lue à l'œil, et « 1.5e+03 » y est illisible.
func TestUneMetriqueNEstJamaisEnNotationExponentielle(t *testing.T) {
	n := InfosNoeud{Hostname: "proxy1", IP: "10.0.0.2"}
	for _, v := range []float64{1500, 0.000015, 1e21} {
		trame := ConstruireMetrique("cle", "id", n, "connections_total", v)
		if strings.ContainsAny(trame, "eE") &&
			strings.Contains(strings.Split(trame, "\n")[8], "e") {
			t.Errorf("valeur %v rendue en notation exponentielle : %q",
				v, strings.Split(trame, "\n")[8])
		}
	}
}
