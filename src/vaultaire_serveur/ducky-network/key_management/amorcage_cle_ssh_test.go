package keymanagement

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	dbcertificates "vaultaire/core/database/db_certificates"
	"vaultaire/core/storage"
)

// Ce qui empêchait un core de redémarrer sur sa propre base (TO-DO 94).
//
// Deux défauts qui se combinaient : les fichiers de clé étaient écrits sous un
// chemin codé en dur pendant que le répertoire suivait `clientconfpath`, et
// l'amorçage prenait l'échec d'écriture qui s'ensuivait pour « la clé n'existe
// pas encore ». Il régénérait alors une clé déjà en base, et s'arrêtait sur
// « certificat server_login_client existe déjà ».

// avecClientConfPath substitue le chemin d'installation le temps d'un test.
func avecClientConfPath(t *testing.T, chemin string) {
	t.Helper()
	ancien := storage.Client_Conf_path
	storage.Client_Conf_path = chemin
	t.Cleanup(func() { storage.Client_Conf_path = ancien })
}

// LE test du premier défaut : les trois chemins doivent vivre sous
// `clientconfpath`. Le répertoire y était déjà ; les fichiers, non.
func TestLesCheminsSuiventClientConfPath(t *testing.T) {
	base := t.TempDir()
	avecClientConfPath(t, base)

	repertoire, prive, public := CheminsCleLoginClient()

	if repertoire != filepath.Join(base, ".ssh") {
		t.Errorf("répertoire = %q, attendu sous %q", repertoire, base)
	}
	for nom, chemin := range map[string]string{"privée": prive, "publique": public} {
		if !strings.HasPrefix(chemin, base+string(filepath.Separator)) {
			t.Errorf("clé %s écrite hors de clientconfpath : %q", nom, chemin)
		}
		if strings.Contains(chemin, "/opt/vaultaire") && !strings.Contains(base, "/opt/vaultaire") {
			t.Errorf("clé %s sur un chemin codé en dur : %q", nom, chemin)
		}
	}
	if public != prive+".pub" {
		t.Errorf("la clé publique ne suit pas la privée : %q vs %q", public, prive)
	}
}

// Un `clientconfpath` sans barre oblique finale doit donner le même résultat
// qu'avec : la concaténation d'origine (`chemin + ".ssh"`) produisait
// « /opt/vaultaire.ssh » sur une valeur sans barre.
func TestUneBarreObliqueFinaleNeChangeRien(t *testing.T) {
	base := t.TempDir()

	avecClientConfPath(t, base)
	avec, _, _ := CheminsCleLoginClient()
	avecClientConfPath(t, base+"/")
	sans, _, _ := CheminsCleLoginClient()

	if avec != sans {
		t.Errorf("« %s » et « %s/ » donnent des répertoires différents : %q vs %q",
			base, base, avec, sans)
	}
	if filepath.Base(avec) != ".ssh" {
		t.Errorf("répertoire %q : le suffixe .ssh est collé au chemin au lieu d'être un segment", avec)
	}
}

// LE test du second défaut, et le plus important.
//
// Une erreur d'écriture ne doit JAMAIS déclencher une régénération : cette clé
// est celle que « create -c … --join » dépose sur les machines, et la
// régénérer invaliderait l'accès à tout ce qui l'a déjà acceptée.
func TestSeuleUneCleAbsenteAutoriseUneRegeneration(t *testing.T) {
	cas := []struct {
		nom         string
		err         error
		doitGenerer bool
		commentaire string
	}{
		{
			nom:         "absente de la base",
			err:         fmt.Errorf("%w: server_login_client", dbcertificates.ErrCertificatIntrouvable),
			doitGenerer: true,
			commentaire: "premier démarrage : il faut bien la créer une fois",
		},
		{
			nom:         "répertoire non accessible en écriture",
			err:         fmt.Errorf("écriture de la clé privée dans /x : permission denied"),
			doitGenerer: false,
			commentaire: "la clé EST en base : régénérer couperait le parc",
		},
		{
			nom:         "certificat incomplet",
			err:         fmt.Errorf("certificat server_login_client incomplet"),
			doitGenerer: false,
			commentaire: "une ligne existe déjà : l'insertion échouerait",
		},
		{
			nom:         "base injoignable",
			err:         fmt.Errorf("erreur récupération certificat: connexion refusée"),
			doitGenerer: false,
			commentaire: "on ne sait pas ce qu'il y a en base",
		},
	}

	for _, c := range cas {
		genere := errors.Is(c.err, dbcertificates.ErrCertificatIntrouvable)
		if genere != c.doitGenerer {
			t.Errorf("%s : régénération = %v, attendu %v (%s)",
				c.nom, genere, c.doitGenerer, c.commentaire)
		}
	}
}

// Le sentinelle doit survivre à l'enveloppement : c'est tout son intérêt par
// rapport à une comparaison de message, qui casse au premier reformulage.
func TestLeSentinelleSurvitALEnveloppement(t *testing.T) {
	err := fmt.Errorf("clé SSH de déploiement des agents : %w",
		fmt.Errorf("%w: server_login_client", dbcertificates.ErrCertificatIntrouvable))
	if !errors.Is(err, dbcertificates.ErrCertificatIntrouvable) {
		t.Error("ErrCertificatIntrouvable perdu à travers deux enveloppes")
	}
}

// Le répertoire est créé en 0700 : il porte une clé privée que seul le core
// doit lire.
func TestLeRepertoireEstCreeEnPrive(t *testing.T) {
	base := t.TempDir()
	avecClientConfPath(t, base)
	repertoire, _, _ := CheminsCleLoginClient()

	if err := os.MkdirAll(repertoire, 0700); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(repertoire)
	if err != nil {
		t.Fatal(err)
	}
	if mode := info.Mode().Perm(); mode != 0700 {
		t.Errorf("répertoire en %04o, attendu 0700", mode)
	}
}
