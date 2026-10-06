package clusterstorage

import (
	"strings"
	"testing"
	"time"
)

// Les relais demandés à un proxy et ce qu'il en rapporte (TO-DO 141).

func ducky() RelaisConfig {
	return RelaisConfig{Nom: "ducky", Type: RelaisDucky, Ecoute: ":6666", Cibles: CiblesRelais{Source: SourceCores}}
}

func nexus() RelaisConfig {
	return RelaisConfig{Nom: "nexus", Type: RelaisHTTPS, Ecoute: ":8843",
		Cibles: CiblesRelais{Source: "service:vaultaire_nexus"}}
}

func TestUnRelaisDemandeRecoitSesDefauts(t *testing.T) {
	r := RelaisConfig{Type: " LDAPS "}
	if err := r.Valider(); err != nil {
		t.Fatal(err)
	}
	if r.Nom != "ldaps" || r.Ecoute != ":636" || r.Cibles.Source != SourceCores {
		t.Fatalf("défauts d'un relais ldaps : %+v", r)
	}

	// « 8843 » seul s'entend comme « :8843 ».
	r = RelaisConfig{Nom: "nexus", Type: RelaisHTTPS, Ecoute: "8843", Cibles: CiblesRelais{Source: "service: vaultaire_nexus "}}
	if err := r.Valider(); err != nil {
		t.Fatal(err)
	}
	if r.Ecoute != ":8843" || r.Cibles.Source != "service:vaultaire_nexus" {
		t.Fatalf("normalisation : %+v", r)
	}
}

// Chaque refus nomme ce qui ne va pas : c'est l'administrateur qui le lit, au
// moment où il tape.
func TestLesRelaisRefuses(t *testing.T) {
	cas := []struct {
		nom     string
		relais  RelaisConfig
		attendu string
	}{
		{"ldap en clair", RelaisConfig{Type: RelaisLDAP}, "ldaps"},
		{"type inconnu", RelaisConfig{Type: "http"}, "inconnu"},
		{"type absent", RelaisConfig{Nom: "x"}, "type de relais requis"},
		{"nom dangereux", RelaisConfig{Nom: "a b;rm", Type: RelaisLDAPS}, "nom de relais"},
		{"port hors bornes", RelaisConfig{Type: RelaisLDAPS, Ecoute: ":70000"}, "port d'écoute"},
		{"port zéro", RelaisConfig{Type: RelaisLDAPS, Ecoute: ":0"}, "port d'écoute"},
		{"écoute sur un nom", RelaisConfig{Type: RelaisLDAPS, Ecoute: "proxy.site:636"}, "adresse IP"},
		{"https sans cibles", RelaisConfig{Type: RelaisHTTPS}, "nommer ses cibles"},
		{"https vers les cores", RelaisConfig{Type: RelaisHTTPS, Cibles: CiblesRelais{Source: SourceCores}}, "Ducky des cores"},
		{"service en ldaps", RelaisConfig{Type: RelaisLDAPS, Cibles: CiblesRelais{Source: "service:vaultaire_nexus"}}, "ne sert qu'au relais https"},
		{"service sans type", RelaisConfig{Type: RelaisHTTPS, Cibles: CiblesRelais{Source: "service:"}}, "sans type"},
		{"liste vide", RelaisConfig{Type: RelaisHTTPS, Cibles: CiblesRelais{Source: SourceListe}}, "sans adresse"},
		{"cible sans port", RelaisConfig{Type: RelaisHTTPS, Cibles: CiblesRelais{Source: SourceListe, Adresses: []string{"10.0.0.9"}}}, "hôte:port"},
		{"port cible hors cores", RelaisConfig{Type: RelaisHTTPS, Cibles: CiblesRelais{Source: SourceListe, Adresses: []string{"10.0.0.9:443"}, Port: 443}}, "ne vaut que pour la source"},
		{"source inconnue", RelaisConfig{Type: RelaisLDAPS, Cibles: CiblesRelais{Source: "partout"}}, "inconnue"},
		{"inactivité trop courte", RelaisConfig{Type: RelaisLDAPS, InactiviteSecondes: 2}, "inactivité"},
		{"plafond négatif", RelaisConfig{Type: RelaisLDAPS, MaxConnexions: -1}, "plafond"},
	}
	for _, c := range cas {
		err := c.relais.Valider()
		if err == nil || !strings.Contains(err.Error(), c.attendu) {
			t.Errorf("%s : attendu un refus contenant %q, reçu %v", c.nom, c.attendu, err)
		}
	}
}

// Le relais Ducky ne se retire pas et ne change pas de port : c'est celui que
// le cluster distribue aux agents.
func TestLaListeGardeSonRelaisDucky(t *testing.T) {
	if err := ValiderListeDeRelais([]RelaisConfig{ducky(), nexus()}, 6666); err != nil {
		t.Fatalf("liste saine refusée : %v", err)
	}

	cas := map[string]struct {
		liste   []RelaisConfig
		attendu string
	}{
		"sans relais ducky":  {[]RelaisConfig{nexus()}, "aucun relais Ducky"},
		"ducky déplacé":      {[]RelaisConfig{{Nom: "ducky", Type: RelaisDucky, Ecoute: ":7000"}}, "ne se change pas d'ici"},
		"deux relais ducky":  {[]RelaisConfig{ducky(), {Nom: "ducky2", Type: RelaisDucky, Ecoute: ":6667"}}, "port 6667"},
		"deux fois le nom":   {[]RelaisConfig{ducky(), nexus(), {Nom: "NEXUS", Type: RelaisLDAPS, Ecoute: ":1636"}}, "déclaré deux fois"},
		"deux fois le port":  {[]RelaisConfig{ducky(), nexus(), {Nom: "ldaps", Type: RelaisLDAPS, Ecoute: "10.0.0.5:8843"}}, "écoutent tous deux"},
		"un relais invalide": {[]RelaisConfig{ducky(), {Nom: "x", Type: RelaisLDAP}}, "ldaps"},
	}
	for nom, c := range cas {
		err := ValiderListeDeRelais(c.liste, 6666)
		if err == nil || !strings.Contains(err.Error(), c.attendu) {
			t.Errorf("%s : attendu un refus contenant %q, reçu %v", nom, c.attendu, err)
		}
	}

	// Port annoncé inconnu : la règle du port n'est pas jugée ici, le proxy
	// la jugera. Deux relais Ducky restent refusés.
	if err := ValiderListeDeRelais([]RelaisConfig{{Nom: "ducky", Type: RelaisDucky, Ecoute: ":7000"}}, 0); err != nil {
		t.Errorf("port annoncé inconnu : %v", err)
	}
	deux := []RelaisConfig{{Nom: "a", Type: RelaisDucky, Ecoute: ":7000"}, {Nom: "b", Type: RelaisDucky, Ecoute: ":7001"}}
	if err := ValiderListeDeRelais(deux, 0); err == nil || !strings.Contains(err.Error(), "un seul port") {
		t.Errorf("deux relais Ducky sans port annoncé : %v", err)
	}
}

// Le document du proxy est un format de PROTOCOLE : ce test fige ce que le
// core en lit, tel que le proxy l'écrit.
func TestLeCompteRenduDuProxySeLit(t *testing.T) {
	document := `{"v":1,"revision":3,"origine":"core","pilotage":true,"port_annonce":6666,` +
		`"relais":[{"nom":"ducky","type":"ducky","ecoute":":6666","cibles":{"source":"cores"},` +
		`"delai_connexion_secondes":3,"inactivite_secondes":900,"max_connexions":4000,"max_par_source":20,` +
		`"statut":"actif","ecoute_effective":"[::]:6666","cibles_resolues":["10.0.0.1:6666"]},` +
		`{"nom":"nexus","type":"https","ecoute":":443","cibles":{"source":"service:vaultaire_nexus"},` +
		`"statut":"refuse","motif":"relais nexus : écoute sur :443 impossible : permission denied"}],` +
		`"champ_d_une_version_future":true}`
	c, err := DecoderCompteRendu(document)
	if err != nil {
		t.Fatal(err)
	}
	if c.Revision != 3 || c.Origine != OrigineCore || !c.Pilotage || c.PortAnnonce != 6666 || len(c.Relais) != 2 {
		t.Fatalf("compte rendu mal lu : %+v", c)
	}
	d := c.Relais[0]
	if d.Nom != "ducky" || d.Statut != StatutRelaisActif || d.MaxConnexions != 4000 || d.CiblesResolues[0] != "10.0.0.1:6666" || d.Cibles.Source != SourceCores {
		t.Fatalf("relais actif mal lu : %+v", d)
	}
	if n := c.Relais[1]; n.Statut != StatutRelaisRefuse || !strings.Contains(n.Motif, "permission denied") {
		t.Fatalf("relais refusé mal lu : %+v", n)
	}

	// Une origine inconnue ne se lit pas comme une liste du core.
	if c, _ := DecoderCompteRendu(`{"origine":"autre","relais":[]}`); c.Origine != OrigineFichier {
		t.Errorf("origine inconnue lue %q", c.Origine)
	}
	for nom, mauvais := range map[string]string{
		"illisible":  `{"relais":`,
		"trop grand": `{"refus":"` + strings.Repeat("x", TailleMaxCompteRendu) + `"}`,
	} {
		if _, err := DecoderCompteRendu(mauvais); err == nil {
			t.Errorf("compte rendu %s accepté", nom)
		}
	}
}

// La demande s'encode comme le proxy la lit — il refuse tout champ inconnu.
func TestLaDemandeSEncodePourLeProxy(t *testing.T) {
	r := nexus()
	r.MaxConnexions = 200
	got := DemandeRelais{Relais: []RelaisConfig{ducky(), r}}.Encoder()
	want := `{"relais":[{"nom":"ducky","type":"ducky","ecoute":":6666","cibles":{"source":"cores"}},` +
		`{"nom":"nexus","type":"https","ecoute":":8843","cibles":{"source":"service:vaultaire_nexus"},"max_connexions":200}]}`
	if got != want {
		t.Fatalf("demande encodée :\n got %s\nwant %s", got, want)
	}
	if strings.Contains(got, "\n") {
		t.Fatal("la demande doit tenir sur une ligne : la trame est découpée par lignes")
	}
	if vide := (DemandeRelais{}).Encoder(); vide != `{"relais":[]}` {
		t.Errorf("demande vide : %s", vide)
	}
}

// --- la vue --------------------------------------------------------------------

func rapport(revision int, origine string, relais ...RelaisRapporte) *CompteRenduRelais {
	return &CompteRenduRelais{Version: 1, Revision: revision, Origine: origine, Pilotage: true,
		PortAnnonce: 6666, Relais: relais, Recu: time.Now()}
}

func actif(c RelaisConfig, cibles ...string) RelaisRapporte {
	c.MaxConnexions, c.MaxParSource, c.InactiviteSecondes, c.DelaiConnexionSecondes = 4000, 20, 900, 3
	return RelaisRapporte{RelaisConfig: c, Statut: StatutRelaisActif, EcouteEffective: "[::]" + c.Ecoute, CiblesResolues: cibles}
}

func etats(v VueRelais) string {
	var out []string
	for _, r := range v.Relais {
		out = append(out, r.Nom+"="+r.Etat)
	}
	return strings.Join(out, " ")
}

// Le core ne pilote pas : on montre ce que le proxy tient de son fichier.
func TestLaVueDUnProxyNonPilote(t *testing.T) {
	v := ComposerVueRelais(nil, 0, rapport(0, OrigineFichier, actif(ducky(), "10.0.0.1:6666")), nil, time.Now())
	if v.Pilote || !v.Connu || etats(v) != "ducky=fichier" || len(v.EnService) != 0 {
		t.Fatalf("vue d'un proxy sur son fichier : %+v", v)
	}
	if !strings.Contains(v.Resume(), "fichier du proxy") {
		t.Errorf("résumé : %s", v.Resume())
	}
	if v.Relais[0].CiblesLisibles() != "10.0.0.1:6666" || v.Relais[0].Effectif == nil {
		t.Errorf("cibles ou configuration effective absentes : %+v", v.Relais[0])
	}

	// Un proxy qui n'a jamais rendu compte.
	v = ComposerVueRelais(nil, 0, nil, nil, time.Now())
	if v.Connu || len(v.Relais) != 0 || !strings.Contains(v.Resume(), "n'a pas rendu compte") {
		t.Fatalf("proxy inconnu : %+v — %s", v, v.Resume())
	}
}

// Les trois états : demandé tant que le proxy n'a rien dit, appliqué ou refusé
// ensuite — et c'est le proxy qui tranche.
func TestLesTroisEtats(t *testing.T) {
	demande := []RelaisConfig{ducky(), nexus()}

	// Juste après l'écriture : le proxy applique encore son fichier.
	v := ComposerVueRelais(demande, 4, rapport(0, OrigineFichier, actif(ducky(), "10.0.0.1:6666")), nil, time.Now())
	if etats(v) != "ducky=demande nexus=demande" {
		t.Fatalf("avant application : %s", etats(v))
	}
	if len(v.EnService) != 1 || v.EnService[0].Etat != EtatDuFichier {
		t.Fatalf("ce qui tourne en attendant doit être montré : %+v", v.EnService)
	}
	if v.AJour() || !strings.Contains(v.Resume(), "applique encore son fichier") {
		t.Errorf("résumé avant application : %s", v.Resume())
	}

	// Le proxy a appliqué la révision : un relais ouvert, un refusé.
	refuse := RelaisRapporte{RelaisConfig: nexus(), Statut: StatutRelaisRefuse, Motif: "écoute sur :8843 impossible : address already in use"}
	v = ComposerVueRelais(demande, 4, rapport(4, OrigineCore, actif(ducky(), "10.0.0.1:6666"), refuse), nil, time.Now())
	if etats(v) != "ducky=applique nexus=refuse" {
		t.Fatalf("après application : %s", etats(v))
	}
	if !strings.Contains(v.Relais[1].Motif, "already in use") {
		t.Errorf("le motif du refus doit venir du proxy : %q", v.Relais[1].Motif)
	}
	if len(v.EnService) != 0 || !v.AJour() {
		t.Errorf("révision appliquée : rien d'autre à montrer, reçu %+v", v.EnService)
	}

	// Une révision plus ancienne tourne encore.
	v = ComposerVueRelais(demande, 5, rapport(4, OrigineCore, actif(ducky())), nil, time.Now())
	if etats(v) != "ducky=demande nexus=demande" || !strings.Contains(v.Resume(), "applique encore la révision 4") {
		t.Fatalf("révision en retard : %s — %s", etats(v), v.Resume())
	}
	if len(v.EnService) != 1 || v.EnService[0].Etat != EtatApplique {
		t.Fatalf("la révision 4 qui tourne doit être montrée comme appliquée : %+v", v.EnService)
	}
}

// La liste refusée EN ENTIER : tout est refusé, avec le motif du proxy, et ce
// qui tourne encore est montré.
func TestLaListeRefuseeEnEntier(t *testing.T) {
	r := rapport(0, OrigineFichier, actif(ducky()))
	r.RevisionRefusee, r.Refus = 6, "liste refusée en entier : elle ne porte aucun relais Ducky"
	v := ComposerVueRelais([]RelaisConfig{ducky(), nexus()}, 6, r, nil, time.Now())
	if etats(v) != "ducky=refuse nexus=refuse" || !strings.Contains(v.Resume(), "REFUSÉE") || !strings.Contains(v.Resume(), "aucun relais Ducky") {
		t.Fatalf("refus entier : %s — %s", etats(v), v.Resume())
	}
	if len(v.EnService) != 1 {
		t.Fatalf("ce qui tourne malgré le refus doit être montré : %+v", v.EnService)
	}
	// Un refus d'une AUTRE révision ne concerne pas celle-ci.
	v = ComposerVueRelais([]RelaisConfig{ducky()}, 7, r, nil, time.Now())
	if v.Refus != "" || etats(v) != "ducky=demande" {
		t.Fatalf("un refus de la révision 6 a déteint sur la 7 : %+v", v)
	}
}

// La demande GARDE ses zéros : c'est elle que le formulaire réenregistre, et
// la remplir des valeurs du proxy figerait un défaut en réglage.
func TestLaDemandeAfficheeGardeSesDefauts(t *testing.T) {
	v := ComposerVueRelais([]RelaisConfig{ducky()}, 2, rapport(2, OrigineCore, actif(ducky())), nil, time.Now())
	r := v.Relais[0]
	if r.MaxConnexions != 0 || r.InactiviteSecondes != 0 {
		t.Fatalf("la demande affichée a été remplie avec les valeurs du proxy : %+v", r.RelaisConfig)
	}
	if r.Effectif == nil || r.Effectif.MaxConnexions != 4000 || !strings.Contains(r.Limites(), "connexions au plus : 4000") {
		t.Fatalf("la configuration effective doit porter les défauts résolus : %+v — %s", r.Effectif, r.Limites())
	}
	// Sans compte rendu, zéro se lit « défaut ».
	v = ComposerVueRelais([]RelaisConfig{ducky()}, 2, nil, nil, time.Now())
	if !strings.Contains(v.Relais[0].Limites(), "défaut") {
		t.Errorf("limites sans compte rendu : %s", v.Relais[0].Limites())
	}
}

// Un compte rendu vieux de plus de trois minutes ne décrit plus l'état courant.
func TestUnCompteRenduPerimeLeDit(t *testing.T) {
	r := rapport(0, OrigineFichier, actif(ducky()))
	r.Recu = time.Now().Add(-10 * time.Minute)
	if v := ComposerVueRelais(nil, 0, r, nil, time.Now()); v.Frais {
		t.Fatal("compte rendu de dix minutes tenu pour frais")
	}
	r.Recu = time.Now().Add(-30 * time.Second)
	if v := ComposerVueRelais(nil, 0, r, nil, time.Now()); !v.Frais {
		t.Fatal("compte rendu de trente secondes tenu pour périmé")
	}
}

// Les compteurs (TO-DO 108) se rangent par nom de relais.
func TestLesCompteursSuiventLeRelais(t *testing.T) {
	mesures := []RelaisMesure{{Nom: "nexus", Actives: 3, Total: 40}, {Nom: "ducky", Actives: 12, Total: 90}}
	v := ComposerVueRelais([]RelaisConfig{ducky(), nexus()}, 1,
		rapport(1, OrigineCore, actif(ducky()), actif(nexus())), mesures, time.Now())
	if v.Relais[0].Mesure == nil || v.Relais[0].Mesure.Actives != 12 || v.Relais[1].Mesure.Total != 40 {
		t.Fatalf("compteurs mal rangés : %+v / %+v", v.Relais[0].Mesure, v.Relais[1].Mesure)
	}
}

// Ce que le core prend comme base la première fois : les relais ACTIFS du
// compte rendu, et pas ceux que le proxy n'a pas pu ouvrir.
func TestLaBaseDeLaPremiereRevision(t *testing.T) {
	refuse := RelaisRapporte{RelaisConfig: nexus(), Statut: StatutRelaisRefuse}
	base := DepuisLeCompteRendu(*rapport(0, OrigineFichier, actif(ducky()), refuse))
	if len(base) != 1 || base[0].Nom != "ducky" || base[0].MaxConnexions != 4000 {
		t.Fatalf("base de la première révision : %+v", base)
	}
}
