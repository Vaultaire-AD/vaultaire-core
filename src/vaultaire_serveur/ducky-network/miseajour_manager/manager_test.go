package miseajourmanager

import (
	"encoding/base64"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	dbclients "vaultaire/core/database/db_clients"
	"vaultaire/core/miseajour"
	"vaultaire/core/paquetagent"
	"vaultaire/core/parcversion"
	"vaultaire/core/storage"
	"vaultaire/ducky-network/trame"
)

func trameDe(sous, contenu string) storage.Trames_struct_client {
	return storage.Trames_struct_client{Message_Order: []string{"09", sous}, ClientSoftwareID: "poste-1",
		Destination_Server: "serveur_central", SessionIntegritykey: "CLE", Content: contenu}
}

func situationFixe(t *testing.T, s miseajour.Situation, err error) {
	t.Helper()
	avant := lireSituation
	t.Cleanup(func() { lireSituation = avant })
	lireSituation = func(string) (miseajour.Situation, error) { return s, err }
}

func attendue(v string) parcversion.Attendue {
	x, _ := parcversion.Lire(v)
	return parcversion.Attendue{Definie: true, Version: x, Source: parcversion.SourceGroupe, Groupe: "pilote"}
}

func TestLaDemandeRendLOrdre(t *testing.T) {
	situationFixe(t, miseajour.Situation{Declaree: "2.3.0", Attendue: attendue("2.4.0"), Depot: "site"}, nil)
	rep := Trame_Manager(trameDe("01", ""), nil)
	if rep != "09_02\nserveur_central\nCLE\n2.4.0\nsite\nnon" {
		t.Errorf("%q", rep)
	}
}

func TestLaDemandeRendRienAFaire(t *testing.T) {
	situationFixe(t, miseajour.Situation{Declaree: "2.4.0", Attendue: attendue("2.4.0")}, nil)
	if rep := Trame_Manager(trameDe("01", ""), nil); !strings.HasPrefix(rep, "09_03\nserveur_central\nCLE\nà jour") {
		t.Errorf("%q", rep)
	}
	// Base muette : rien à faire, jamais un ordre deviné.
	situationFixe(t, miseajour.Situation{}, errors.New("base injoignable"))
	if rep := Trame_Manager(trameDe("01", ""), nil); !strings.HasPrefix(rep, "09_03") {
		t.Errorf("%q", rep)
	}
}

func TestLeCompteRendu(t *testing.T) {
	avant := enregistrerCompteRendu
	t.Cleanup(func() { enregistrerCompteRendu = avant })
	var recu miseajour.CompteRendu
	enregistrerCompteRendu = func(id string, c miseajour.CompteRendu) error { recu = c; return nil }

	noterLEnvoi("poste-1", "2.4.0")
	rep := Trame_Manager(trameDe("04", "2.4.0\nnon_pris_en_charge\nbasculement non écrit"), nil)
	if rep != "09_05\nserveur_central\nCLE" || recu.Resultat != miseajour.ResultatNonPrisEnCharge {
		t.Errorf("%q %+v", rep, recu)
	}
	if recemmentEnvoye("poste-1", "2.4.0", time.Now()) {
		t.Error("le compte rendu n'a pas clos l'envoi")
	}
	recu = miseajour.CompteRendu{}
	if rep := Trame_Manager(trameDe("04", "2.4.0\nça marche"), nil); rep != "" || recu.Resultat != "" {
		t.Errorf("compte rendu illisible accepté : %q", rep)
	}
}

func TestLesTramesDuCoreSontRefusees(t *testing.T) {
	for _, s := range []string{"02", "03", "05", "06", "99"} {
		if rep := Trame_Manager(trameDe(s, ""), nil); rep != "" {
			t.Errorf("09_%s : %q", s, rep)
		}
	}
}

func agent(id, declaree string) dbclients.AgentEtCibles {
	return dbclients.AgentEtCibles{ComputeurID: id, Declaree: declaree, Groupes: map[string]string{"pilote": "2.4.0"}}
}

func TestUnTourDePoussee(t *testing.T) {
	envoisMu.Lock()
	envois = map[string]envoi{}
	envoisMu.Unlock()

	var pousses []string
	src := sourceDePoussee{
		connectees: func() []string { return []string{"A", "b", "ancien", "ajour"} },
		parc: func() ([]dbclients.AgentEtCibles, string, string, error) {
			return []dbclients.AgentEtCibles{
				agent("a", "2.3.0"),      // connecté (casse différente), en retard : poussé
				agent("B", "2.3.0"),      // idem
				agent("ancien", "2.2.0"), // ne lit pas la catégorie 09 : pas poussé
				agent("ajour", "2.4.0"),  // à jour
				agent("absent", "2.3.0"), // pas connecté à ce core
			}, "", "", nil
		},
		pousser: func(id string, o miseajour.Ordre) bool { pousses = append(pousses, id+"="+o.Version); return true },
	}
	maintenant := time.Now()
	if n := unTour(src, maintenant); n != 2 || strings.Join(pousses, ",") != "A=2.4.0,b=2.4.0" {
		t.Fatalf("%d : %v", n, pousses)
	}
	// Le tour suivant ne repousse pas…
	if n := unTour(src, maintenant.Add(PasDeLaPoussee)); n != 0 {
		t.Errorf("repoussé au tour suivant : %d", n)
	}
	// … sauf passé RepousseApres.
	if n := unTour(src, maintenant.Add(RepousseApres+time.Second)); n != 2 {
		t.Errorf("après %s : %d", RepousseApres, n)
	}
}

// La capacité annoncée : sans elle, un agent n'émet ni 09_01 ni 04_15 — et un
// agent qui les émettrait vers un core qui ne la connaît pas serait coupé.
func TestLaCapaciteEstAnnoncee(t *testing.T) {
	if !strings.Contains(trame.LigneCapacites(), trame.CapaciteMiseAJour) || trame.CapaciteMiseAJour != "miseajour" {
		t.Errorf("%q", trame.LigneCapacites())
	}
}

// 09_07 (TO-DO 117) : rangé, et accusé par une 09_08 — même si la base refuse.
func TestLaConfiguration(t *testing.T) {
	avant := enregistrerConfiguration
	t.Cleanup(func() { enregistrerConfiguration = avant })
	var recu miseajour.CompteRenduConf
	var pour string
	enregistrerConfiguration = func(id string, c miseajour.CompteRenduConf) error { pour, recu = id, c; return nil }

	rep := Trame_Manager(trameDe("07", "ecart\nrefusé : ssh/sshd_config : sshd -t refuse"), nil)
	if !strings.HasPrefix(rep, "09_08\n") || pour != "poste-1" || recu.Etat != miseajour.ConfEcart ||
		recu.Motif != "refusé : ssh/sshd_config : sshd -t refuse" {
		t.Fatalf("%q — %s %+v", rep, pour, recu)
	}
	enregistrerConfiguration = func(string, miseajour.CompteRenduConf) error { return errors.New("base") }
	if rep := Trame_Manager(trameDe("07", "conforme\n"), nil); !strings.HasPrefix(rep, "09_08\n") {
		t.Errorf("accusé absent quand la base refuse : %q", rep)
	}
	if rep := Trame_Manager(trameDe("07", "n'importe quoi"), nil); rep != "" {
		t.Errorf("état inconnu accusé : %q", rep)
	}
}

// La capacité confsys est annoncée : sans elle, l'agent n'émet pas la 09_07.
func TestLaCapaciteConfSysEstAnnoncee(t *testing.T) {
	if !strings.Contains(trame.LigneCapacites(), ","+trame.CapaciteConfSys) || trame.CapaciteConfSys != "confsys" {
		t.Errorf("%q", trame.LigneCapacites())
	}
}

// 09_09 → 09_10 (TO-DO 207) : le numéro est rangé, le jeu suivant servi.
func TestLeJeuDeCles(t *testing.T) {
	avantJ, avantE := jeuApres, enregistrerJeuAgent
	t.Cleanup(func() { jeuApres, enregistrerJeuAgent = avantJ, avantE })
	var range_ string
	enregistrerJeuAgent = func(id string, n int) error { range_ = id + "=" + strconv.Itoa(n); return nil }
	jeuApres = func(n int) (paquetagent.JeuStocke, bool, error) {
		if n >= 2 {
			return paquetagent.JeuStocke{}, false, nil
		}
		return paquetagent.JeuStocke{Numero: n + 1, Corps: "corps\nsur\nlignes\n", Enveloppe: "env\n"}, true, nil
	}
	rep := Trame_Manager(trameDe("09", "1"), nil)
	l := strings.Split(rep, "\n")
	if range_ != "poste-1=1" || l[0] != "09_10" || len(l) < 3 {
		t.Fatalf("%q %s", rep, range_)
	}
	contenu := l[len(l)-3:]
	corps, _ := base64.StdEncoding.DecodeString(contenu[1])
	if contenu[0] != "2" || string(corps) != "corps\nsur\nlignes\n" {
		t.Errorf("%q", contenu)
	}
	if rep := Trame_Manager(trameDe("09", "2"), nil); !strings.HasSuffix(rep, "\n"+JeuAJour) {
		t.Errorf("à jour : %q", rep)
	}
	if rep := Trame_Manager(trameDe("09", "x"), nil); rep != "" {
		t.Errorf("demande illisible servie : %q", rep)
	}
	if !strings.Contains(trame.LigneCapacites(), ","+trame.CapaciteClesPaquets) {
		t.Error("capacité non annoncée")
	}
}

// Le drapeau de la dérogation passe dans la situation (TO-DO 204).
func TestSituationPorteLaRetrogradation(t *testing.T) {
	s := situationDe(dbclients.AgentEtCibles{Declaree: "2.4.0", Derogation: "2.2.0", DerogationRetrograder: true}, "", "")
	if !s.RetrogradationDemandee {
		t.Fatal("drapeau perdu")
	}
	if d := miseajour.Decider(s); d.Ordre == nil || !d.Ordre.Retrograder {
		t.Errorf("%+v", d)
	}
}
