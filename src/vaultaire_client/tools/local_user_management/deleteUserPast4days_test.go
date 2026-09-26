package localusermanagement

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"
)

// Le défaut que ces tests gardent : le ménage ne trouvait AUCUN compte, tous
// les jours, depuis toujours — il cherchait dans le GECOS une chaîne que rien
// n'écrivait.

// avecFixtures pose un /etc/passwd et un uid.map de test.
func avecFixtures(t *testing.T, passwd string, carte string) {
	t.Helper()
	dir := t.TempDir()

	cheminPasswd := filepath.Join(dir, "passwd")
	if err := os.WriteFile(cheminPasswd, []byte(passwd), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "uid.map"), []byte(carte), 0o644); err != nil {
		t.Fatal(err)
	}

	t.Setenv("VAULTAIRE_PASSWD_FILE", cheminPasswd)
	t.Setenv("VAULTAIRE_UID_MAP_DIR", dir)
}

// avecDerniereConnexion remplace l'appel à `lastlog`.
func avecDerniereConnexion(t *testing.T, f func(string) (time.Time, bool, error)) {
	t.Helper()
	ancien := derniereConnexion
	derniereConnexion = f
	t.Cleanup(func() { derniereConnexion = ancien })
}

// avecSuppression remplace l'appel à `userdel` et retient les noms.
func avecSuppression(t *testing.T) *[]string {
	t.Helper()
	var vus []string
	ancien := supprimerCompte
	supprimerCompte = func(nom string) error {
		vus = append(vus, nom)
		return nil
	}
	t.Cleanup(func() { supprimerCompte = ancien })
	return &vus
}

const passwdOrdinaire = `root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
alice@test.fr:x:5000:5000:alice@test.fr@vaultaire:/home/alice@test.fr:/bin/bash
bob@test.fr:x:5001:5001:bob@test.fr@vaultaire:/home/bob@test.fr:/bin/bash
carole:x:1500:1500:compte local:/home/carole:/bin/bash
`

// LE test du point : les comptes que l'agent a créés portent
// « <compte>@vaultaire » dans le GECOS, jamais « vaultaire_user_account ». La
// recherche d'origine ne pouvait donc rien trouver.
func TestLesComptesSontReconnusParLaCarteEtNonParLeGecos(t *testing.T) {
	avecFixtures(t, passwdOrdinaire, "alice@test.fr:5000:5000\nbob@test.fr:5001:5001\n")

	noms, err := comptesDuDomaine()
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(noms)

	if len(noms) != 2 || noms[0] != "alice@test.fr" || noms[1] != "bob@test.fr" {
		t.Fatalf("comptes retenus = %v, attendu [alice@test.fr bob@test.fr]", noms)
	}
	for _, n := range noms {
		if n == "root" || n == "carole" {
			t.Fatalf("compte hors du domaine retenu : %s", n)
		}
	}
}

// Un compte de la carte dont l'UID diffère de celui de /etc/passwd n'est PAS
// à nous, ou plus : la carte adopte l'UID d'un compte local préexistant, et
// l'égalité est ce qui distingue « ce compte est le nôtre » de « ce compte
// porte un nom que nous connaissons ».
func TestUnUIDQuiNeCorrespondPasEpargneLeCompte(t *testing.T) {
	avecFixtures(t, passwdOrdinaire, "alice@test.fr:5000:5000\ncarole:5002:5002\n")

	noms, err := comptesDuDomaine()
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range noms {
		if n == "carole" {
			t.Error("compte local carole retenu : son UID de passwd (1500) ne suit pas la carte (5002)")
		}
	}
}

// Une entrée de carte sans compte local n'est pas une anomalie : le compte a
// déjà été retiré, ou ne s'est jamais connecté sur cette machine. L'entrée
// reste — c'est elle qui tient l'UID stable.
func TestUneEntreeSansCompteLocalNEstPasUnCandidat(t *testing.T) {
	avecFixtures(t, passwdOrdinaire, "alice@test.fr:5000:5000\nparti@test.fr:5009:5009\n")

	noms, err := comptesDuDomaine()
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range noms {
		if n == "parti@test.fr" {
			t.Error("un compte absent de /etc/passwd est présenté comme candidat à la suppression")
		}
	}
}

// Un /etc/passwd illisible arrêtait l'agent ENTIER par log.Fatalf — donc
// l'authentification de toute la machine — pour un fichier qu'il n'avait qu'à
// relire au tour suivant.
func TestUnPasswdIllisibleNArretePasLAgent(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("VAULTAIRE_PASSWD_FILE", filepath.Join(dir, "absent"))
	t.Setenv("VAULTAIRE_UID_MAP_DIR", dir)
	if err := os.WriteFile(filepath.Join(dir, "uid.map"), []byte("alice@test.fr:5000:5000\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	if _, err := comptesDuDomaine(); err == nil {
		t.Fatal("aucune erreur rendue sur un passwd absent")
	}

	// Et le point qui compte : la fonction de haut niveau rend la main.
	DeleteUser_Vaultaire_Past_4Days_withoutconnection()
}

// La décision, cas par cas.
func TestLaDecisionDeRetrait(t *testing.T) {
	cas := []struct {
		nom      string
		derniere time.Time
		jamais   bool
		retirer  bool
		pourquoi string
	}{
		{
			nom:      "jamais connecté",
			jamais:   true,
			retirer:  true,
			pourquoi: "un compte provisionné puis jamais utilisé est exactement ce que le ménage vise",
		},
		{
			nom:      "connecté hier",
			derniere: time.Now().Add(-24 * time.Hour),
			retirer:  false,
		},
		{
			nom:      "juste avant le délai",
			derniere: time.Now().Add(-InactiviteAvantRetrait + time.Hour),
			retirer:  false,
			pourquoi: "la borne doit être franchie, pas approchée",
		},
		{
			nom:      "juste après le délai",
			derniere: time.Now().Add(-InactiviteAvantRetrait - time.Hour),
			retirer:  true,
		},
	}

	for _, c := range cas {
		t.Run(c.nom, func(t *testing.T) {
			avecDerniereConnexion(t, func(string) (time.Time, bool, error) {
				return c.derniere, c.jamais, nil
			})
			inactif, _, err := compteInactif("alice@test.fr")
			if err != nil {
				t.Fatal(err)
			}
			if inactif != c.retirer {
				t.Errorf("retrait = %v, attendu %v (%s)", inactif, c.retirer, c.pourquoi)
			}
		})
	}
}

// Une dernière connexion inconnue CONSERVE le compte.
//
// Confondre « je ne sais pas » avec « jamais connecté » ferait supprimer un
// compte actif dès que `lastlog` change d'un mot ou disparaît de la
// distribution.
func TestUneDerniereConnexionInconnueConserveLeCompte(t *testing.T) {
	avecFixtures(t, passwdOrdinaire, "alice@test.fr:5000:5000\n")
	avecDerniereConnexion(t, func(string) (time.Time, bool, error) {
		return time.Time{}, false, fmt.Errorf("lastlog : executable file not found")
	})
	supprimes := avecSuppression(t)

	DeleteUser_Vaultaire_Past_4Days_withoutconnection()

	if len(*supprimes) != 0 {
		t.Errorf("comptes supprimés sans savoir : %v", *supprimes)
	}
}

// La sortie de `lastlog` est analysée en anglais. Sur une machine en locale
// française, la date ne s'analysait pas, le compte passait pour actif, et le
// ménage se taisait — d'où LC_ALL=C.
func TestLaLigneLastlogEstLuePourChaqueForme(t *testing.T) {
	cas := []struct {
		nom     string
		ligne   string
		jamais  bool
		erreur  bool
		attendu string
	}{
		{
			nom:    "jamais connecté",
			ligne:  "alice@test.fr                            **Never logged in**",
			jamais: true,
		},
		{
			nom:     "connexion par ssh, avec adresse",
			ligne:   "alice@test.fr    pts/0    10.0.0.5         Mon Sep 22 09:14:03 2026",
			attendu: "2026-09-22T09:14:03Z",
		},
		{
			nom:     "connexion en console, sans adresse",
			ligne:   "bob@test.fr      tty1                      Tue Sep  2 23:59:59 2026",
			attendu: "2026-09-02T23:59:59Z",
		},
		{
			nom:    "ligne tronquée",
			ligne:  "alice@test.fr",
			erreur: true,
		},
		{
			nom:    "date en français",
			ligne:  "alice@test.fr    pts/0    10.0.0.5         lun. sept. 22 09:14:03 2026",
			erreur: true,
		},
	}

	for _, c := range cas {
		t.Run(c.nom, func(t *testing.T) {
			date, jamais, err := LireLigneLastlog(c.ligne)
			if c.erreur {
				if err == nil {
					t.Fatalf("aucune erreur sur %q : le compte serait jugé actif pour toujours", c.ligne)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if jamais != c.jamais {
				t.Errorf("jamais connecté = %v, attendu %v", jamais, c.jamais)
			}
			if c.attendu != "" && date.UTC().Format(time.RFC3339) != c.attendu {
				t.Errorf("date = %s, attendu %s", date.UTC().Format(time.RFC3339), c.attendu)
			}
		})
	}
}

// L'entrée de carte part AVEC le compte. La garder laisserait un UID réservé à
// un compte qui n'existe plus.
func TestLEntreeDeCartePartAvecLeCompte(t *testing.T) {
	avecFixtures(t, passwdOrdinaire, "alice@test.fr:5000:5000\nbob@test.fr:5001:5001\n")
	avecDerniereConnexion(t, func(nom string) (time.Time, bool, error) {
		if nom == "alice@test.fr" {
			return time.Time{}, true, nil // jamais connectée
		}
		return time.Now(), false, nil
	})
	supprimes := avecSuppression(t)

	DeleteUser_Vaultaire_Past_4Days_withoutconnection()

	if len(*supprimes) != 1 || (*supprimes)[0] != "alice@test.fr" {
		t.Fatalf("comptes supprimés = %v, attendu [alice@test.fr]", *supprimes)
	}

	carte, err := LoadUIDMap()
	if err != nil {
		t.Fatal(err)
	}
	if _, reste := carte["alice@test.fr"]; reste {
		t.Error("l'entrée d'uid.map survit au compte : son UID reste réservé à personne")
	}
	if _, present := carte["bob@test.fr"]; !present {
		t.Error("l'entrée d'un compte conservé a été retirée")
	}
}

// Un userdel en échec — session ouverte, par exemple — ne doit PAS retirer
// l'entrée de la carte : le compte est toujours là, et son UID doit rester tenu.
func TestUnEchecDeSuppressionGardeLEntree(t *testing.T) {
	avecFixtures(t, passwdOrdinaire, "alice@test.fr:5000:5000\n")
	avecDerniereConnexion(t, func(string) (time.Time, bool, error) {
		return time.Time{}, true, nil
	})

	ancien := supprimerCompte
	supprimerCompte = func(string) error {
		return fmt.Errorf("userdel: user alice@test.fr is currently used by process 4242")
	}
	t.Cleanup(func() { supprimerCompte = ancien })

	DeleteUser_Vaultaire_Past_4Days_withoutconnection()

	carte, err := LoadUIDMap()
	if err != nil {
		t.Fatal(err)
	}
	if _, present := carte["alice@test.fr"]; !present {
		t.Error("entrée retirée alors que le compte est toujours sur la machine")
	}
}

// Une machine sans aucun compte du domaine ne doit rien tenter — et surtout
// pas échouer.
func TestUneMachineSansCompteDuDomaineNeFaitRien(t *testing.T) {
	avecFixtures(t, passwdOrdinaire, "")
	supprimes := avecSuppression(t)

	DeleteUser_Vaultaire_Past_4Days_withoutconnection()

	if len(*supprimes) != 0 {
		t.Errorf("suppressions sur une machine sans compte du domaine : %v", *supprimes)
	}
}
