package confsys

import (
	"os"
	"strings"
	"testing"
	"time"

	"duckynetworkclient/V1/duckynetwork/storage"

	"vaultaire_client/config"
)

func TestGarderNeRapportePasDeuxFoisLeMeme(t *testing.T) {
	d := t.TempDir()
	r := Rapport{Etat: EtatReconciliee, Motif: "écrit : ssh/sshd_config v0→v1"}
	if err := Garder(d, r, time.Now()); err != nil {
		t.Fatal(err)
	}
	e, ok := LireEtat(d)
	if !ok || e.Rapporte || e.Etat != EtatReconciliee {
		t.Fatalf("%+v", e)
	}
	e.Rapporte = true
	_ = ecrireEtat(d, e)
	// Démarrage suivant : conforme — un constat neuf, à rapporter.
	_ = Garder(d, Rapport{Etat: EtatConforme, Motif: "tous les fichiers à la version de l'agent"}, time.Now())
	if e, _ := LireEtat(d); e.Rapporte {
		t.Error("constat neuf marqué rapporté")
	}
	e, _ = LireEtat(d)
	e.Rapporte = true
	_ = ecrireEtat(d, e)
	// Le même constat, encore : pas de nouveau compte rendu.
	_ = Garder(d, Rapport{Etat: EtatConforme, Motif: "tous les fichiers à la version de l'agent"}, time.Now())
	if e, _ := LireEtat(d); !e.Rapporte {
		t.Error("le même constat repart au core à chaque démarrage")
	}
}

func TestCompteRendu0907(t *testing.T) {
	storage.Computeur_ID = "poste-1"
	l := strings.Split(CompteRendu("CLE", EtatEcart, "refusé : sshd -t\nrefuse"), "\n")
	if len(l) != 7 || l[0] != "09_07" || l[2] != "CLE" || l[4] != "poste-1" || l[5] != EtatEcart ||
		l[6] != "refusé : sshd -t refuse" {
		t.Errorf("%q", l)
	}
}

func avecLancement(t *testing.T) {
	t.Helper()
	d, maj, pas, root := dossierEtat, majEnCours, pasDAttente, estRoot
	t.Cleanup(func() { dossierEtat, majEnCours, pasDAttente, estRoot = d, maj, pas, root })
	dossierEtat = t.TempDir()
	pasDAttente = time.Millisecond
	estRoot = func() bool { return true }
}

// Le passage attend la fin d'une mise à jour — c'est l'ordre « porte de
// santé, PUIS configuration ».
func TestLePassageAttendLaMiseAJour(t *testing.T) {
	avecLancement(t)
	p := nouveauPoste(t, "rocky", false)
	p.installer()
	avant := envReel
	t.Cleanup(func() { envReel = avant })
	envReel = func() (Env, error) { return p.env(&fauxSysteme{}), nil }
	tours := 0
	majEnCours = func() bool { tours++; return tours < 4 }
	r := Passage()
	if tours != 4 || r.Etat != EtatConforme {
		t.Errorf("%d tours, %s", tours, r.Etat)
	}
	if e, ok := LireEtat(dossierEtat); !ok || e.Etat != EtatConforme {
		t.Errorf("état non gardé : %+v", e)
	}
}

func TestLePassageNonRoot(t *testing.T) {
	avecLancement(t)
	estRoot = func() bool { return false }
	if r := Passage(); r.Etat != EtatNonPrisEnCharge {
		t.Errorf("%+v", r)
	}
}

func TestAfficher(t *testing.T) {
	r := Rapport{Constats: []Constat{{Nom: "ssh/sshd_config", Avant: 0, Attendue: 1, Action: ActionAEcrire},
		{Nom: "pam.d/sshd", Avant: 1, Attendue: 1, Action: ActionAJour}}}
	s := Afficher(r, "rocky")
	if !strings.Contains(s, "ssh/sshd_config") || !strings.Contains(s, "v0 / attendu v1   à écrire") || !resteAFaire(r) {
		t.Errorf("%s", s)
	}
	if resteAFaire(Rapport{Constats: r.Constats[1:]}) {
		t.Error("rien à faire")
	}
}

func TestLePassageDesactive(t *testing.T) {
	avecLancement(t)
	p := t.TempDir() + "/client_conf.json"
	_ = os.WriteFile(p, []byte(`{"servers":[{"ip":"10.0.0.1","port":6666}],"reconcile_system_config":false}`), 0o600)
	if err := config.LoadConfig(p); err != nil {
		t.Fatal(err)
	}
	defaut := t.TempDir() + "/client_conf.json"
	_ = os.WriteFile(defaut, []byte(`{"servers":[{"ip":"10.0.0.1","port":6666}]}`), 0o600)
	t.Cleanup(func() { _ = config.LoadConfig(defaut) })
	if r := Passage(); r.Etat != EtatDesactivee {
		t.Errorf("%+v", r)
	}
}

// Jumeaux de vaultaire_serveur/core/miseajour (TestEtatsDeConfigurationJumeaux).
func TestEtatsJumeaux(t *testing.T) {
	for c, attendu := range map[string]string{
		EtatConforme: "conforme", EtatReconciliee: "reconciliee", EtatEcart: "ecart",
		EtatDesactivee: "desactivee", EtatNonPrisEnCharge: "non_pris_en_charge",
	} {
		if c != attendu {
			t.Errorf("%q", c)
		}
	}
}
