package controle

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
)

// Le contrôle de démarrage — TO-DO 112.
//
// Chaque test part d'une installation SAINE, dans un dossier à lui, et n'y
// abîme qu'une chose : c'est ce qui dit quel fichier porte quel verdict.

var (
	cleUneFois sync.Once
	cleDeTest  *rsa.PrivateKey
)

// cle rend une paire RSA, générée une fois pour tout le paquet : 2048 bits
// suffisent à éprouver le décodage, et la générer par test coûterait des
// secondes pour rien.
func cle(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	cleUneFois.Do(func() {
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		cleDeTest = k
	})
	return cleDeTest
}

func ecrire(t *testing.T, chemin, contenu string, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(chemin, []byte(contenu), mode); err != nil {
		t.Fatal(err)
	}
}

// installationSaine pose ce que `rocky.sh` laisse sur une machine.
func installationSaine(t *testing.T) Chemins {
	t.Helper()
	d := t.TempDir()
	k := cle(t)
	c := Chemins{
		Configuration: filepath.Join(d, "client_conf.json"),
		Identite:      filepath.Join(d, "client_software.yaml"),
		ClePrivee:     filepath.Join(d, "private_key.pem"),
		CleDuCore:     filepath.Join(d, "serveurpublickey.pem"),
		Empreinte:     filepath.Join(d, "core_key_fingerprint"),
		Journaux:      filepath.Join(d, "logs"),
	}
	ecrire(t, c.Configuration, `{"servers":[{"ip":"10.0.0.10","port":6666}]}`, 0o600)
	ecrire(t, c.Identite, "client_software:\n  computeur_id: PC-01\n  logiciel_type: vaultaire_client\n  isServeur: false\n", 0o600)
	ecrire(t, c.ClePrivee, string(pem.EncodeToMemory(&pem.Block{
		Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)})), 0o400)
	pub, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	ecrire(t, c.CleDuCore, string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pub})), 0o644)
	ecrire(t, c.Empreinte, "SHA256:abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ\n", 0o644)
	if err := os.Mkdir(c.Journaux, 0o700); err != nil {
		t.Fatal(err)
	}
	return c
}

func constatDe(t *testing.T, constats []Constat, sujet string) Constat {
	t.Helper()
	for _, c := range constats {
		if c.Sujet == sujet {
			return c
		}
	}
	t.Fatalf("aucun constat « %s » dans %+v", sujet, constats)
	return Constat{}
}

func TestUneInstallationSaineDemarre(t *testing.T) {
	constats := Verifier(installationSaine(t))
	for _, c := range constats {
		if c.Gravite != Bon {
			t.Errorf("« %s » : %s — %s. Une installation telle que rocky.sh la laisse doit passer sans réserve",
				c.Sujet, c.Gravite, c.Detail)
		}
	}
	var sortie bytes.Buffer
	if n := Rapport(&sortie, "contrôle", constats); n != 0 {
		t.Fatalf("%d bloquant(s) sur une installation saine", n)
	}
	if !strings.Contains(sortie.String(), "peut démarrer") {
		t.Fatalf("le rapport ne conclut pas :\n%s", sortie.String())
	}
}

// Ce qui empêche de servir une authentification est BLOQUANT, et le dit.
func TestCeQuiEmpecheDeDemarrerEstBloquant(t *testing.T) {
	k := cle(t)
	pkcs8, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	cas := []struct {
		nom, sujet string
		abimer     func(c Chemins)
		dit        string
	}{
		{"configuration absente", "configuration", func(c Chemins) { os.Remove(c.Configuration) }, "absent"},
		{"configuration tronquée", "configuration", func(c Chemins) { ecrire(t, c.Configuration, `{"servers":[{"ip":"10.0`, 0o600) }, "illisible"},
		{"configuration sans core", "configuration", func(c Chemins) { ecrire(t, c.Configuration, `{"servers":[]}`, 0o600) }, "aucun core"},
		{"core sans port", "configuration", func(c Chemins) { ecrire(t, c.Configuration, `{"servers":[{"ip":"10.0.0.10"}]}`, 0o600) }, "aucun core"},
		{"identité absente", "identité", func(c Chemins) { os.Remove(c.Identite) }, "absent"},
		{"identité sans identifiant", "identité", func(c Chemins) { ecrire(t, c.Identite, "client_software:\n  logiciel_type: vaultaire_client\n", 0o600) }, "identifiant"},
		{"identité illisible", "identité", func(c Chemins) { ecrire(t, c.Identite, "client_software: [\n", 0o600) }, "illisible"},
		{"clé privée absente", "clé privée", func(c Chemins) { os.Remove(c.ClePrivee) }, "absent"},
		{"clé privée vide", "clé privée", func(c Chemins) { os.Chmod(c.ClePrivee, 0o600); ecrire(t, c.ClePrivee, "", 0o600) }, "PEM"},
		{"clé privée tronquée", "clé privée", func(c Chemins) {
			os.Chmod(c.ClePrivee, 0o600)
			ecrire(t, c.ClePrivee, "-----BEGIN RSA PRIVATE KEY-----\nAAAA\n-----END RSA PRIVATE KEY-----\n", 0o600)
		}, "PKCS#1"},
		// Le socle ne lit que du PKCS#1 : une clé PKCS#8, valide ailleurs, ne
		// déchiffrerait pas la première réponse du core.
		{"clé privée en PKCS#8", "clé privée", func(c Chemins) {
			os.Chmod(c.ClePrivee, 0o600)
			ecrire(t, c.ClePrivee, string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})), 0o600)
		}, "PKCS#1"},
	}
	for _, cs := range cas {
		t.Run(cs.nom, func(t *testing.T) {
			c := installationSaine(t)
			cs.abimer(c)
			constats := Verifier(c)
			constat := constatDe(t, constats, cs.sujet)
			if constat.Gravite != Bloquant {
				t.Fatalf("« %s » : %s (%s) — attendu BLOQUANT : l'agent serait lancé pour mourir, ou pour ne servir personne",
					cs.sujet, constat.Gravite, constat.Detail)
			}
			if !strings.Contains(constat.Detail, cs.dit) {
				t.Errorf("le constat ne nomme pas la cause (« %s » attendu) : %s", cs.dit, constat.Detail)
			}
			if Bloquants(constats) != 1 {
				t.Errorf("%d bloquant(s) pour UNE chose abîmée : %+v", Bloquants(constats), constats)
			}
			var sortie bytes.Buffer
			if Rapport(&sortie, "contrôle", constats) == 0 || !strings.Contains(sortie.String(), "ne peut PAS démarrer") {
				t.Errorf("le rapport ne conclut pas à l'échec :\n%s", sortie.String())
			}
		})
	}
}

// Ce que l'agent tolère aujourd'hui ne doit JAMAIS bloquer : ce contrôle garde
// la porte du service, et un refus de trop couperait une machine qui marche.
func TestCeQueLAgentTolereNeBloquePas(t *testing.T) {
	cas := []struct {
		nom    string
		abimer func(c Chemins)
		sujet  string
		veut   Gravite
	}{
		{"clé du core absente, empreinte présente", func(c Chemins) { os.Remove(c.CleDuCore) }, "clé du core", Bon},
		{"clé du core et empreinte absentes", func(c Chemins) { os.Remove(c.CleDuCore); os.Remove(c.Empreinte) }, "clé du core", Attention},
		{"clé du core illisible", func(c Chemins) { ecrire(t, c.CleDuCore, "pas une clé", 0o644) }, "clé du core", Attention},
		{"clé du core illisible, sans empreinte", func(c Chemins) { ecrire(t, c.CleDuCore, "pas une clé", 0o644); os.Remove(c.Empreinte) }, "clé du core", Attention},
		{"empreinte absente", func(c Chemins) { os.Remove(c.Empreinte) }, "clé du core", Attention},
		{"journaux absents", func(c Chemins) { os.Remove(c.Journaux) }, "journaux", Attention},
		{"clé privée trop ouverte", func(c Chemins) { os.Chmod(c.ClePrivee, 0o644) }, "clé privée", Attention},
		// Le Bloc-notes et PowerShell posent une marque d'ordre des octets :
		// l'agent la retire, le contrôle doit lire pareil.
		{"configuration avec BOM", func(c Chemins) {
			ecrire(t, c.Configuration, "\xEF\xBB\xBF"+`{"servers":[{"ip":"10.0.0.10","port":6666}]}`, 0o600)
		}, "configuration", Bon},
		// Seule la liste apprise est utilisable : l'agent s'en sert.
		{"core appris seulement", func(c Chemins) {
			ecrire(t, c.Configuration, `{"servers":[],"learned":[{"ip":"10.0.0.11","port":6666}]}`, 0o600)
		}, "configuration", Bon},
	}
	for _, cs := range cas {
		t.Run(cs.nom, func(t *testing.T) {
			c := installationSaine(t)
			cs.abimer(c)
			constats := Verifier(c)
			if n := Bloquants(constats); n != 0 {
				t.Fatalf("%d bloquant(s) : %+v — l'agent démarre et travaille dans cet état, "+
					"le contrôle l'en empêcherait", n, constats)
			}
			if g := constatDe(t, constats, cs.sujet).Gravite; g != cs.veut {
				t.Errorf("« %s » : %s, attendu %s", cs.sujet, g, cs.veut)
			}
		})
	}
}

// Le contrôle LIT. Il tourne à côté d'un agent en service : rien ne doit
// apparaître, disparaître ni changer.
func TestLeControleNEcritRien(t *testing.T) {
	c := installationSaine(t)
	os.Remove(c.Journaux) // même le répertoire de journaux n'est pas créé
	releve := func() string {
		var lignes []string
		racine := filepath.Dir(c.Configuration)
		filepath.Walk(racine, func(p string, info os.FileInfo, err error) error {
			if err != nil {
				return nil
			}
			contenu := ""
			if !info.IsDir() {
				b, _ := os.ReadFile(p)
				contenu = string(b)
			}
			lignes = append(lignes, p+"|"+info.Mode().String()+"|"+info.ModTime().String()+"|"+contenu)
			return nil
		})
		sort.Strings(lignes)
		return strings.Join(lignes, "\n")
	}
	avant := releve()
	Verifier(c)
	if apres := releve(); apres != avant {
		t.Fatalf("le contrôle a modifié l'installation :\nAVANT\n%s\nAPRÈS\n%s", avant, apres)
	}
}

// Les chemins réels sont ceux que l'agent résout — variables d'environnement
// comprises. Un contrôle qui regarderait ailleurs que lui ne contrôlerait rien.
func TestLesCheminsReelsSuiventLEnvironnement(t *testing.T) {
	t.Setenv("VAULTAIRE_KEY_PATH", "/srv/cles")
	t.Setenv("VAULTAIRE_CLIENT_SOFTWARE", "")
	c := CheminsReels()
	for nom, chemin := range map[string]string{
		"identité": c.Identite, "clé privée": c.ClePrivee, "clé du core": c.CleDuCore, "empreinte": c.Empreinte,
	} {
		if !strings.HasPrefix(chemin, "/srv/cles/") {
			t.Errorf("%s cherchée dans %s alors que l'agent lira /srv/cles", nom, chemin)
		}
	}
	t.Setenv("VAULTAIRE_CLIENT_SOFTWARE", "/srv/identite.yaml")
	if got := CheminsReels().Identite; got != "/srv/identite.yaml" {
		t.Errorf("identité cherchée dans %s, l'agent lira /srv/identite.yaml", got)
	}
}
