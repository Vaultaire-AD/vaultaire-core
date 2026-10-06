package webserveur

import (
	"bytes"
	"html/template"
	"path/filepath"
	"strings"
	"testing"
	"time"

	clusterstorage "vaultaire/cluster/cluster_storage"
)

// La fiche d'un proxy affiche ses relais et permet de les régler (TO-DO 141).
//
// Un gabarit ne se vérifie qu'en l'EXÉCUTANT : un champ mal nommé passe la
// compilation, et ne casse qu'à la première visite — avec une page tronquée
// au milieu d'un tableau.

func rendreLaPageCluster(t *testing.T, data donneesCluster) string {
	t.Helper()
	tmpl, err := template.ParseFiles(
		filepath.Join(cheminGabarits, "admin_sidebar.html"),
		filepath.Join(cheminGabarits, "admin_cluster.html"))
	if err != nil {
		t.Fatalf("analyse du gabarit : %v", err)
	}
	var page bytes.Buffer
	if err := tmpl.ExecuteTemplate(&page, "admin_cluster.html", data); err != nil {
		t.Fatalf("exécution du gabarit : %v", err)
	}
	return page.String()
}

func proxyOuvert() donneesCluster {
	proxy := clusterstorage.Node{Hostname: "proxy1", FQDN: "proxy1", Role: "proxy", Status: "online",
		IPAddress: "10.0.0.2", Port: 6666, ExposeAuxAgents: true, LastHeartbeat: time.Now()}
	return donneesCluster{Username: "alice", Section: "cluster",
		Nodes: []clusterstorage.Node{proxy}, Selection: &proxy}
}

func vueDEssai() *clusterstorage.VueRelais {
	ducky := clusterstorage.RelaisConfig{Nom: "ducky", Type: "ducky", Ecoute: ":6666",
		Cibles: clusterstorage.CiblesRelais{Source: "cores"}}
	nexus := clusterstorage.RelaisConfig{Nom: "nexus", Type: "https", Ecoute: ":443",
		Cibles: clusterstorage.CiblesRelais{Source: "liste", Adresses: []string{"10.0.0.9:8443", "10.0.0.10:8443"}}, MaxConnexions: 200}
	rapport := &clusterstorage.CompteRenduRelais{Revision: 3, Origine: "core", Pilotage: true, PortAnnonce: 6666, Recu: time.Now(),
		Relais: []clusterstorage.RelaisRapporte{
			{RelaisConfig: ducky, Statut: "actif", EcouteEffective: "[::]:6666", CiblesResolues: []string{"10.0.0.1:6666"}},
			{RelaisConfig: nexus, Statut: "refuse", Motif: "écoute sur :443 impossible : permission denied"},
		}}
	v := clusterstorage.ComposerVueRelais([]clusterstorage.RelaisConfig{ducky, nexus}, 3, rapport,
		[]clusterstorage.RelaisMesure{{Nom: "ducky", Actives: 12, Total: 90}}, time.Now())
	v.ModifiePar, v.ModifieLe = "root", time.Now()
	return &v
}

func TestLaFicheDUnProxyMontreSesRelais(t *testing.T) {
	data := proxyOuvert()
	data.RelaisProxy = vueDEssai()
	data.PeutPiloter = true
	html := rendreLaPageCluster(t, data)

	for _, attendu := range []string{
		"Relais — ce que ce proxy expose",
		"révision 3 appliquée par le proxy",
		"les cores du cluster",
		"en ce moment : 10.0.0.1:6666",
		"liste fixe : 10.0.0.9:8443, 10.0.0.10:8443",
		"<strong>refusé</strong>",
		"permission denied",
		`name="action" value="set_relay"`,
		`name="action" value="remove_relay"`,
		`name="action" value="release_relays"`,
		"Ajouter un relais",
	} {
		if !strings.Contains(html, attendu) {
			t.Errorf("page sans %q", attendu)
		}
	}

	// Le relais Ducky ne se retire pas : un seul formulaire de retrait, celui
	// du relais HTTPS.
	if n := strings.Count(html, `name="action" value="remove_relay"`); n != 1 {
		t.Errorf("%d formulaire(s) de retrait, attendu 1 — le relais Ducky ne se retire pas", n)
	}
	// La demande réenregistrée garde son plafond et ses adresses, une par ligne.
	if !strings.Contains(html, `name="max_connections" type="number" min="0" value="200"`) {
		t.Error("le plafond demandé n'est pas repris dans le formulaire : enregistrer le remettrait au défaut")
	}
	if !strings.Contains(html, "10.0.0.9:8443\n10.0.0.10:8443") {
		t.Error("les adresses de la liste ne sont pas reprises une par ligne dans le formulaire")
	}
	// Les compteurs seuls (TO-DO 108) ne doublent pas la nouvelle section.
	if strings.Contains(html, "Compteurs remontés par le nœud, relevés à") {
		t.Error("l'ancien tableau de compteurs est affiché en plus de la section des relais")
	}
}

// Sans write:relay, la page montre tout et ne propose rien.
func TestSansLeDroitLaFicheNeProposeRien(t *testing.T) {
	data := proxyOuvert()
	data.RelaisProxy = vueDEssai()
	html := rendreLaPageCluster(t, data)

	if !strings.Contains(html, "Relais — ce que ce proxy expose") || !strings.Contains(html, "write:relay") {
		t.Error("la lecture doit rester entière, et dire quel droit manque pour modifier")
	}
	for _, interdit := range []string{`value="set_relay"`, `value="remove_relay"`, `value="release_relays"`} {
		if strings.Contains(html, interdit) {
			t.Errorf("formulaire %s proposé sans le droit", interdit)
		}
	}
}

// Un proxy qui garde la main : affiché, et aucun formulaire — même avec le
// droit, il refuserait.
func TestUnProxyQuiGardeLaMainNEstPasModifiable(t *testing.T) {
	data := proxyOuvert()
	v := clusterstorage.ComposerVueRelais(nil, 0, &clusterstorage.CompteRenduRelais{
		Origine: "fichier", Pilotage: false, Recu: time.Now(),
		Relais: []clusterstorage.RelaisRapporte{{RelaisConfig: clusterstorage.RelaisConfig{Nom: "ducky", Type: "ducky", Ecoute: ":6666",
			Cibles: clusterstorage.CiblesRelais{Source: "cores"}}, Statut: "actif"}},
	}, nil, time.Now())
	data.RelaisProxy, data.PeutPiloter = &v, true
	html := rendreLaPageCluster(t, data)

	if !strings.Contains(html, "garde la main") || !strings.Contains(html, "du fichier") {
		t.Error("la page doit dire que ce proxy garde la main, et montrer ses relais du fichier")
	}
	if strings.Contains(html, `value="set_relay"`) {
		t.Error("formulaire proposé sur un proxy qui refuse le pilotage")
	}
}

// Un proxy d'une version antérieure ne rend pas compte : il garde l'ancien
// tableau de compteurs, et la page se rend sans la nouvelle section.
func TestUnProxySansCompteRenduGardeSesCompteurs(t *testing.T) {
	data := proxyOuvert()
	data.Selection.Relais = &clusterstorage.MetriquesRelais{Actives: 2, Total: 9, Mesure: time.Now(),
		Relais: []clusterstorage.RelaisMesure{{Nom: "ducky", Type: "ducky", Ecoute: "[::]:6666", Actives: 2, Total: 9}}}
	inconnu := clusterstorage.ComposerVueRelais(nil, 0, nil, nil, time.Now())

	for nom, vue := range map[string]*clusterstorage.VueRelais{"sans vue": nil, "jamais rendu compte": &inconnu} {
		data.RelaisProxy = vue
		html := rendreLaPageCluster(t, data)
		if !strings.Contains(html, "Compteurs remontés par le nœud, relevés à") {
			t.Errorf("%s : l'ancien tableau de compteurs a disparu", nom)
		}
		if strings.Contains(html, "Relais — ce que ce proxy expose") {
			t.Errorf("%s : section des relais affichée sans rien à montrer", nom)
		}
	}
}

// La fiche d'un core, et la page sans aucun nœud ouvert, se rendent toujours.
func TestLaPageClusterSeRendSansProxy(t *testing.T) {
	data := proxyOuvert()
	data.Selection.Role = "core"
	if html := rendreLaPageCluster(t, data); strings.Contains(html, "ce que ce proxy expose") {
		t.Error("section des relais sur la fiche d'un core")
	}
	data.Selection = nil
	if html := rendreLaPageCluster(t, data); !strings.Contains(html, "Aucun nœud ouvert") {
		t.Error("page sans nœud ouvert mal rendue")
	}
}
