package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"duckynetworkclient/V1/duckynetwork/decouverte"
	"duckynetworkclient/V1/duckynetwork/storage"

	"vaultaire_proxy/relais"
)

// Le pilotage des relais par le core, vu du proxy (TO-DO 141).

func portLibre(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	return port
}

// proxyDEssai pose un répertoire de clés et un fichier de configuration, et
// rend un pilote démarré sur ce fichier, avec les comptes rendus qu'il émet.
type proxyDEssai struct {
	*pilote
	port    int
	config  string
	comptes *[]relais.CompteRendu
}

func fichierDEssai(port int, suite string) string {
	return fmt.Sprintf("servers:\n  - ip: 127.0.0.1\n    port: 1\n%srelais:\n  - nom: ducky\n    type: ducky\n    ecoute: \"127.0.0.1:%d\"\n    cibles: {source: liste, adresses: [\"127.0.0.1:1\"]}\n", suite, port)
}

func demarrerProxyDEssai(t *testing.T, port int, dossierCles, contenuFichier string) proxyDEssai {
	t.Helper()
	ancien := storage.KeyPath
	storage.KeyPath = dossierCles
	t.Cleanup(func() { storage.KeyPath = ancien; relaisVivants.Store(nil) })

	config := filepath.Join(t.TempDir(), "proxy.yaml")
	if err := os.WriteFile(config, []byte(contenuFichier), 0o600); err != nil {
		t.Fatal(err)
	}
	liste, err := relais.Charger(config, port)
	if err != nil {
		t.Fatal(err)
	}

	p := nouveauPilote(config, port)
	var comptes []relais.CompteRendu
	p.rendreCompte = func(document string) bool {
		var c relais.CompteRendu
		if err := json.Unmarshal([]byte(document), &c); err != nil {
			t.Errorf("compte rendu illisible : %v\n%s", err, document)
		}
		comptes = append(comptes, c)
		return true
	}
	if err := p.demarrer(liste); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.parc.Fermer)
	return proxyDEssai{pilote: p, port: port, config: config, comptes: &comptes}
}

func (p proxyDEssai) dernier(t *testing.T) relais.CompteRendu {
	t.Helper()
	if len(*p.comptes) == 0 {
		t.Fatal("aucun compte rendu émis")
	}
	return (*p.comptes)[len(*p.comptes)-1]
}

func (p proxyDEssai) lire(t *testing.T) relais.CompteRendu {
	t.Helper()
	var c relais.CompteRendu
	if err := json.Unmarshal([]byte(p.Document()), &c); err != nil {
		t.Fatal(err)
	}
	return c
}

func demande(t *testing.T, liste ...relais.Relais) string {
	t.Helper()
	b, err := json.Marshal(relais.Demande{Relais: liste})
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func relaisDucky(port int) relais.Relais {
	return relais.Relais{Nom: "ducky", Type: relais.TypeDucky, Ecoute: fmt.Sprintf("127.0.0.1:%d", port),
		Cibles: relais.Cibles{Source: relais.SourceListe, Adresses: []string{"127.0.0.1:1"}}}
}

func relaisNexus(port int) relais.Relais {
	return relais.Relais{Nom: "nexus", Type: relais.TypeHTTPS, Ecoute: fmt.Sprintf("127.0.0.1:%d", port),
		Cibles: relais.Cibles{Source: relais.SourceListe, Adresses: []string{"127.0.0.1:2"}}}
}

func nomsActifs(c relais.CompteRendu) string {
	var noms []string
	for _, r := range c.Relais {
		if r.Statut == relais.StatutActif {
			noms = append(noms, r.Nom)
		}
	}
	return strings.Join(noms, ",")
}

// Sans rien du core, le proxy applique son fichier et le DIT : c'est ce que la
// page Cluster affiche d'un proxy qu'on ne pilote pas.
func TestSansCoreLeProxyRendCompteDeSonFichier(t *testing.T) {
	port := portLibre(t)
	p := demarrerProxyDEssai(t, port, t.TempDir(), fichierDEssai(port, ""))

	c := p.lire(t)
	if c.Origine != relais.OrigineFichier || c.Revision != 0 || !c.Pilotage || c.PortAnnonce != port {
		t.Fatalf("compte rendu d'un proxy sur son fichier : %+v", c)
	}
	if len(c.Relais) != 1 || c.Relais[0].Nom != "ducky" || c.Relais[0].Statut != relais.StatutActif {
		t.Fatalf("relais rapportés : %+v", c.Relais)
	}
	// Les défauts sont RÉSOLUS : le core n'a pas à connaître les constantes.
	r := c.Relais[0]
	if r.MaxConnexions != relais.MaxConnexionsParDefaut || r.InactiviteSecondes != 900 || r.DelaiConnexionSecondes != 3 {
		t.Fatalf("défauts non résolus dans le compte rendu : %+v", r.Relais)
	}
	if len(r.CiblesResolues) != 1 || r.CiblesResolues[0] != "127.0.0.1:1" || r.EcouteEffective == "" {
		t.Fatalf("cibles ou écoute effectives absentes : %+v", r)
	}
}

// Le cas central : le core pousse une liste, le proxy l'applique à chaud, en
// garde une copie, et rend compte de la révision appliquée.
func TestUneListeDuCoreEstAppliqueeEtGardee(t *testing.T) {
	port, portNexus := portLibre(t), portLibre(t)
	cles := t.TempDir()
	p := demarrerProxyDEssai(t, port, cles, fichierDEssai(port, ""))

	p.surConfiguration(decouverte.ConfigurationRelais{Mode: decouverte.ModeCore, Revision: 3,
		Document: demande(t, relaisDucky(port), relaisNexus(portNexus))})

	c := p.dernier(t)
	if c.Origine != relais.OrigineCore || c.Revision != 3 || c.RevisionRefusee != 0 {
		t.Fatalf("après une liste du core : %+v", c)
	}
	if nomsActifs(c) != "ducky,nexus" {
		t.Fatalf("relais actifs : %q, attendu ducky,nexus", nomsActifs(c))
	}
	if conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", portNexus)); err != nil {
		t.Fatalf("le relais poussé par le core n'écoute pas : %v", err)
	} else {
		_ = conn.Close()
	}
	if n := len(*relaisVivants.Load()); n != 2 {
		t.Fatalf("%d relais publiés pour les compteurs, attendu 2", n)
	}

	// La copie locale : c'est elle qui fait redémarrer un proxy isolé sur sa
	// dernière configuration connue, et non sur son fichier.
	if _, err := os.Stat(filepath.Join(cles, NomCopieLocale)); err != nil {
		t.Fatalf("copie locale non écrite : %v", err)
	}
	p.parc.Fermer()

	redemarre := demarrerProxyDEssai(t, port, cles, fichierDEssai(port, ""))
	c = redemarre.lire(t)
	if c.Origine != relais.OrigineCore || c.Revision != 3 || nomsActifs(c) != "ducky,nexus" {
		t.Fatalf("redémarrage sans core : attendu la révision 3 et ses deux relais, reçu %+v", c)
	}
}

// La même révision, renvoyée, n'est pas réappliquée.
func TestLaMemeRevisionNEstPasRejouee(t *testing.T) {
	port, portNexus := portLibre(t), portLibre(t)
	p := demarrerProxyDEssai(t, port, t.TempDir(), fichierDEssai(port, ""))
	cfg := decouverte.ConfigurationRelais{Mode: decouverte.ModeCore, Revision: 1,
		Document: demande(t, relaisDucky(port), relaisNexus(portNexus))}

	p.surConfiguration(cfg)
	avant := (*relaisVivants.Load())[1]
	p.surConfiguration(cfg)
	if apres := (*relaisVivants.Load())[1]; avant != apres {
		t.Fatal("la révision déjà appliquée a rouvert un relais")
	}
}

// Le core rend la main : le fichier est réappliqué, la copie retirée.
func TestLeCoreRendLaMain(t *testing.T) {
	port, portNexus := portLibre(t), portLibre(t)
	cles := t.TempDir()
	p := demarrerProxyDEssai(t, port, cles, fichierDEssai(port, ""))
	p.surConfiguration(decouverte.ConfigurationRelais{Mode: decouverte.ModeCore, Revision: 2,
		Document: demande(t, relaisDucky(port), relaisNexus(portNexus))})

	p.surConfiguration(decouverte.ConfigurationRelais{Mode: decouverte.ModeFichier})

	c := p.dernier(t)
	if c.Origine != relais.OrigineFichier || c.Revision != 0 || nomsActifs(c) != "ducky" {
		t.Fatalf("après le retour au fichier : %+v", c)
	}
	if _, err := os.Stat(filepath.Join(cles, NomCopieLocale)); !os.IsNotExist(err) {
		t.Fatal("la copie locale survit au retour au fichier : le prochain démarrage reprendrait la liste du core")
	}
	if conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", portNexus)); err == nil {
		_ = conn.Close()
		t.Fatal("le relais du core écoute encore après le retour au fichier")
	}
}

// Un proxy qui garde la main refuse la liste, ne change rien, et le dit.
func TestUnProxyQuiGardeLaMainRefuseEtLeDit(t *testing.T) {
	port, portNexus := portLibre(t), portLibre(t)
	cles := t.TempDir()
	p := demarrerProxyDEssai(t, port, cles, fichierDEssai(port, "pilotage_par_le_core: false\n"))

	if p.lire(t).Pilotage {
		t.Fatal("le compte rendu annonce un proxy pilotable")
	}
	p.surConfiguration(decouverte.ConfigurationRelais{Mode: decouverte.ModeCore, Revision: 5,
		Document: demande(t, relaisDucky(port), relaisNexus(portNexus))})

	c := p.dernier(t)
	if c.Origine != relais.OrigineFichier || c.Revision != 0 || c.RevisionRefusee != 5 || !strings.Contains(c.Refus, "pilotage_par_le_core") {
		t.Fatalf("refus de pilotage : %+v", c)
	}
	if nomsActifs(c) != "ducky" {
		t.Fatalf("la liste refusée a été appliquée : %q", nomsActifs(c))
	}
	if _, err := os.Stat(filepath.Join(cles, NomCopieLocale)); !os.IsNotExist(err) {
		t.Fatal("une liste refusée a été gardée en copie locale")
	}
}

// Une liste qui retirerait le relais Ducky, ou qu'on ne comprend pas en
// entier, est refusée EN ENTIER : rien ne bouge, et le core l'apprend.
func TestUneListeInapplicableEstRefuseeEnEntier(t *testing.T) {
	port, portNexus := portLibre(t), portLibre(t)
	p := demarrerProxyDEssai(t, port, t.TempDir(), fichierDEssai(port, ""))

	cas := map[string]string{
		"sans relais Ducky":  demande(t, relaisNexus(portNexus)),
		"champ inconnu":      `{"relais":[{"nom":"ducky","type":"ducky","ecoute":"127.0.0.1:` + fmt.Sprint(port) + `","cibles":{"source":"cores"},"commande":"rm -rf /"}]}`,
		"document illisible": `{"relais":`,
		"liste vide":         `{"relais":[]}`,
	}
	revision := 10
	for nom, document := range cas {
		revision++
		p.surConfiguration(decouverte.ConfigurationRelais{Mode: decouverte.ModeCore, Revision: revision, Document: document})
		c := p.dernier(t)
		if c.Revision != 0 || c.Origine != relais.OrigineFichier || c.RevisionRefusee != revision || c.Refus == "" {
			t.Errorf("%s : attendu un refus entier de la révision %d, reçu %+v", nom, revision, c)
		}
		if nomsActifs(c) != "ducky" {
			t.Errorf("%s : la liste refusée a touché aux relais (%q)", nom, nomsActifs(c))
		}
	}
}

// Un relais que le proxy ne peut pas ouvrir est rapporté REFUSÉ avec son
// motif ; la révision est appliquée pour le reste.
func TestUnRelaisImpossibleEstRapporteRefuse(t *testing.T) {
	port := portLibre(t)
	p := demarrerProxyDEssai(t, port, t.TempDir(), fichierDEssai(port, ""))

	occupant, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer occupant.Close()

	p.surConfiguration(decouverte.ConfigurationRelais{Mode: decouverte.ModeCore, Revision: 4,
		Document: demande(t, relaisDucky(port), relaisNexus(occupant.Addr().(*net.TCPAddr).Port))})

	c := p.dernier(t)
	if c.Revision != 4 || c.Origine != relais.OrigineCore {
		t.Fatalf("la révision devait être appliquée malgré un relais refusé : %+v", c)
	}
	var nexus *relais.RelaisRapporte
	for i := range c.Relais {
		if c.Relais[i].Nom == "nexus" {
			nexus = &c.Relais[i]
		}
	}
	if nexus == nil || nexus.Statut != relais.StatutRefuse || nexus.Motif == "" {
		t.Fatalf("le relais sur un port pris devait être rapporté refusé avec son motif : %+v", c.Relais)
	}
}
