package action

import (
	"strings"
	"testing"
)

// Tests de la troisième sémantique de portée : PorteeOuverte.
//
// # Le défaut qu'ils gardent
//
// Onze actions de liste déclaraient `Portee: PorteeGlobale`, `UnDomaineSuffit:
// true` et un filtre. L'intention se lit dans ces trois lignes : le droit sur un
// domaine ouvre la liste, le filtre la réduit au périmètre.
//
// Le résultat était l'inverse. PorteeGlobale rend la liste de domaines `["*"]`,
// et « au moins un des domaines de cette liste » n'a qu'un seul candidat : `*`.
// Ces lectures exigeaient donc le droit GLOBAL, et le filtre — soigneusement
// écrit dans chaque cas — n'était jamais atteint.
//
// Symptômes observés : `vlt get -u` répondait « Permission refusée : * :
// refusée » à un délégué qui détenait pourtant read:get:user sur son domaine,
// et la page utilisateurs du portail s'ouvrait sur « Erreur liste utilisateurs »
// — l'interface, elle, autorisait bien l'entrée par HasActionAnywhere.
//
// Le défaut est invisible en lisant une définition : il faut savoir ce que
// PorteeGlobale rend, et ce que « un seul suffit » signifie sur une liste d'un
// seul élément. D'où ces tests, et surtout le contrôle à l'enregistrement.

func rienAFaire(Appelant, Params) (Resultat, error) { return Resultat{}, nil }

func filtreFactice(donnees any, _ Perimetre) (any, int) { return donnees, 0 }

// TestPorteeOuverteInterrogeLaBonneMethode.
//
// Le champ ne vaut que s'il oriente réellement le contrôle. Un exécuteur qui
// appellerait encore AutoriseSurUnDomaine reproduirait exactement le défaut,
// sans que rien ne le signale — la définition dirait « ouverte », le contrôle
// exigerait « * ».
func TestPorteeOuverteInterrogeLaBonneMethode(t *testing.T) {
	cas := []struct {
		nom      string
		def      Definition
		attendue string // "partout" | "unDomaine" | "tous"
	}{
		{
			nom: "liste ouverte",
			def: Definition{
				Nom: "x.list", CleRBAC: "read:get:user", Portee: PorteeGlobale,
				PorteeOuverte: true, Filtre: filtreFactice,
				Resume: "t", Executer: rienAFaire,
			},
			attendue: "partout",
		},
		{
			nom: "lecture d'une entité à cheval",
			def: Definition{
				Nom: "x.get", CleRBAC: "read:get:user",
				Portee:          func(Params) ([]string, error) { return []string{"paris", "lyon"}, nil },
				UnDomaineSuffit: true,
				Resume:          "t", Executer: rienAFaire,
			},
			attendue: "unDomaine",
		},
		{
			nom: "écriture",
			def: Definition{
				Nom: "x.update", CleRBAC: "write:update:user",
				Portee: func(Params) ([]string, error) { return []string{"paris", "lyon"}, nil },
				Resume: "t", Executer: rienAFaire,
			},
			attendue: "tous",
		},
	}

	for _, c := range cas {
		t.Run(c.nom, func(t *testing.T) {
			r := NouveauRegistre()
			if err := r.Enregistrer(c.def); err != nil {
				t.Fatalf("enregistrement : %v", err)
			}
			d := &droitsFixes{autorise: true}
			e := &Executeur{Registre: r, Droits: d}

			if _, err := e.Executer(c.def.Nom, Appelant{Username: "alice"}, Params{}); err != nil {
				t.Fatalf("exécution : %v", err)
			}

			got := map[string]int{
				"tous":      len(d.appels),
				"unDomaine": len(d.appelsUnDomaine),
				"partout":   len(d.appelsPartout),
			}
			for nom, n := range got {
				if nom == c.attendue && n != 1 {
					t.Errorf("méthode %q appelée %d fois, attendu 1", nom, n)
				}
				if nom != c.attendue && n != 0 {
					t.Errorf("méthode %q appelée %d fois, attendu 0 — "+
						"le contrôle n'est pas celui que l'action déclare", nom, n)
				}
			}
		})
	}
}

// TestPorteeOuverteNeTransmetAucunDomaine.
//
// C'est la garantie qui empêche la rechute. Transmettre la liste de domaines à
// une vérification « quelque part » laisserait l'appelé libre de s'en servir —
// et c'est exactement ce qui s'est produit avec AutoriseSurUnDomaine, appelée
// avec `["*"]`.
func TestPorteeOuverteNeTransmetAucunDomaine(t *testing.T) {
	r := NouveauRegistre()
	r.MustEnregistrer(Definition{
		Nom: "x.list", CleRBAC: "read:get:user", Portee: PorteeGlobale,
		PorteeOuverte: true, Filtre: filtreFactice,
		Resume: "t", Executer: rienAFaire,
	})
	d := &droitsFixes{autorise: true}
	e := &Executeur{Registre: r, Droits: d}

	if _, err := e.Executer("x.list", Appelant{Username: "alice"}, Params{}); err != nil {
		t.Fatalf("exécution : %v", err)
	}
	if len(d.appelsPartout) != 1 {
		t.Fatalf("%d appel(s) à AutorisePartout, attendu 1", len(d.appelsPartout))
	}
	if n := len(d.appelsPartout[0].domaines); n != 0 {
		t.Errorf("%d domaine(s) transmis à AutorisePartout : la vérification "+
			"pourrait les exiger, ce qui ramènerait le défaut d'origine", n)
	}
}

// TestUnDomaineSuffitEstSansEffetSurPorteeGlobale.
//
// Le cœur du défaut, énoncé comme un fait vérifiable. Ce test ne demande pas de
// corriger ce comportement — il est logiquement inévitable — mais de le
// CONSTATER, pour que le contrôle à l'enregistrement ne paraisse pas arbitraire.
func TestUnDomaineSuffitEstSansEffetSurPorteeGlobale(t *testing.T) {
	domaines, err := PorteeGlobale(Params{})
	if err != nil {
		t.Fatalf("PorteeGlobale : %v", err)
	}
	if len(domaines) != 1 || domaines[0] != "*" {
		t.Fatalf("PorteeGlobale rend %v, attendu [*]", domaines)
	}
	// « au moins un de [*] » et « tous les [*] » sont la même question.
	// C'est pourquoi UnDomaineSuffit n'assouplissait rien.
}

// --- le contrôle à l'enregistrement ---------------------------------------

// TestFiltreSurPorteeGlobaleExigePorteeOuverte.
//
// LE test de ce fichier. Il transforme une classe de défaut silencieux en refus
// au démarrage : le serveur ne part pas, et le message nomme l'action et la
// correction.
func TestFiltreSurPorteeGlobaleExigePorteeOuverte(t *testing.T) {
	r := NouveauRegistre()
	err := r.Enregistrer(Definition{
		Nom: "x.list", CleRBAC: "read:get:user", Portee: PorteeGlobale,
		UnDomaineSuffit: true, // l'ancienne déclaration, celle qui ne marchait pas
		Filtre:          filtreFactice,
		Resume:          "t", Executer: rienAFaire,
	})
	if err == nil {
		t.Fatal("PorteeGlobale + Filtre sans PorteeOuverte acceptée : " +
			"le filtre ne servirait jamais et tout délégué serait refusé")
	}
	for _, attendu := range []string{"PorteeOuverte", "*"} {
		if !strings.Contains(err.Error(), attendu) {
			t.Errorf("message %q : ne mentionne pas %q", err.Error(), attendu)
		}
	}
}

// TestPorteeOuverteSansFiltreRefusee.
//
// L'autre bout de la même exigence. Sans filtre, ouvrir une action à qui détient
// le droit sur un seul domaine rend TOUT — la divulgation même que la délégation
// existe pour empêcher, et elle est invisible : la liste ne dit pas ce qu'elle
// aurait dû masquer.
func TestPorteeOuverteSansFiltreRefusee(t *testing.T) {
	r := NouveauRegistre()
	err := r.Enregistrer(Definition{
		Nom: "x.export", CleRBAC: "read:get:user", Portee: PorteeGlobale,
		PorteeOuverte: true,
		Resume:        "t", Executer: rienAFaire,
	})
	if err == nil {
		t.Fatal("PorteeOuverte sans filtre acceptée : l'action rendrait tout " +
			"à qui détient le droit sur un seul domaine")
	}
	if !strings.Contains(err.Error(), "Filtre") {
		t.Errorf("message %q : ne dit pas ce qu'il faut déclarer", err.Error())
	}
}

// TestPorteeOuverteAvecFiltreInutileAcceptee.
//
// La justification écrite tient lieu de filtre, comme pour les listes. Refuser
// sans échappatoire pousserait à écrire un filtre vide pour faire taire le
// contrôle — ce qui serait pire, puisque plus rien ne dirait pourquoi.
func TestPorteeOuverteAvecFiltreInutileAcceptee(t *testing.T) {
	r := NouveauRegistre()
	err := r.Enregistrer(Definition{
		Nom: "x.list", CleRBAC: "read:get:user", Portee: PorteeGlobale,
		PorteeOuverte: true,
		FiltreInutile: "la liste ne porte aucune entité rattachée à un domaine",
		Resume:        "t", Executer: rienAFaire,
	})
	if err != nil {
		t.Fatalf("refusée malgré FiltreInutile : %v", err)
	}
}

// TestPorteeNonGlobaleAvecFiltreResteAcceptee.
//
// Le contrôle ne doit pas déborder. `group.list_users` a pour portée les
// domaines du GROUPE visé, avec un filtre : c'est correct et doit le rester —
// il faut le droit sur le groupe pour lister ses membres, puis le filtre réduit
// aux membres visibles.
func TestPorteeNonGlobaleAvecFiltreResteAcceptee(t *testing.T) {
	r := NouveauRegistre()
	err := r.Enregistrer(Definition{
		Nom: "groupe.list_users", CleRBAC: "read:get:user",
		Portee:          func(Params) ([]string, error) { return []string{"paris"}, nil },
		UnDomaineSuffit: true,
		Filtre:          filtreFactice,
		Resume:          "t", Executer: rienAFaire,
	})
	if err != nil {
		t.Fatalf("portée d'entité avec filtre refusée à tort : %v", err)
	}
}

// --- l'inventaire réel ------------------------------------------------------

// TestListesDEntitesSontOuvertes parcourt le VRAI catalogue.
//
// Les tests précédents éprouvent le mécanisme ; celui-ci éprouve son
// application. Une liste d'entités oubliée resterait inaccessible aux délégués,
// et rien d'autre ne le dirait — le contrôle d'enregistrement ne se déclenche
// que si un filtre est déclaré.
func TestListesDEntitesSontOuvertes(t *testing.T) {
	r := catalogueDeReference()

	attendues := []string{
		"user.list", "group.list", "client.list",
		"permission.list", "client_permission.list", "gpo.list",
		"session.list_users", "session.list_clients", "session.list_clients_by_type",
		"domain.list_tree", "gpo.list_compliance",
	}
	for _, nom := range attendues {
		d, ok := r.Definition(nom)
		if !ok {
			t.Errorf("%s absente du registre", nom)
			continue
		}
		if !d.PorteeOuverte {
			t.Errorf("%s ne déclare pas PorteeOuverte : un délégué d'un domaine "+
				"se verra refuser la liste entière", nom)
		}
		if d.Filtre == nil {
			t.Errorf("%s est ouverte sans filtre : elle rendrait tout", nom)
		}
	}
}

// TestDroitsBooleensRestentGlobaux.
//
// Ceux-là ne se délèguent PAS par domaine, et c'est délibéré : ils portent sur
// des objets qui n'appartiennent à aucun domaine de l'annuaire — une zone DNS,
// une clé d'enrôlement, un certificat, le mode debug. On les accorde avec
// « all », ou pas du tout.
//
// Les ouvrir par mégarde donnerait les certificats du serveur ou le réglage du
// cluster à tout délégué d'un domaine quelconque.
func TestDroitsBooleensRestentGlobaux(t *testing.T) {
	r := catalogueDeReference()

	for _, nom := range []string{
		"dns.list_zones", "dns.list_records",
		"enroll.list_keys",
		"cluster.list_nodes", "cluster.get_purge_delay", "cluster.set_purge_delay",
		"certificate.list", "certificate.get", "certificate.regenerate",
		"server.set_debug", "server.clear_sessions",
	} {
		d, ok := r.Definition(nom)
		if !ok {
			t.Errorf("%s absente du registre", nom)
			continue
		}
		if d.PorteeOuverte {
			t.Errorf("%s déclare PorteeOuverte : ce droit est un booléen, "+
				"l'ouvrir le donnerait à tout délégué d'un domaine quelconque", nom)
		}
	}
}
