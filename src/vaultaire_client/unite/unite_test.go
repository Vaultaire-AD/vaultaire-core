package unite

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"vaultaire_client/controle"
)

// L'unité systemd de l'agent — TO-DO 112.

// sections découpe l'unité : nom de section → lignes « Clé=valeur ».
func sections(t *testing.T, unite string) map[string]map[string][]string {
	t.Helper()
	out := map[string]map[string][]string{}
	courante := ""
	for _, ligne := range strings.Split(unite, "\n") {
		ligne = strings.TrimSpace(ligne)
		switch {
		case ligne == "" || strings.HasPrefix(ligne, "#"):
			continue
		case strings.HasPrefix(ligne, "[") && strings.HasSuffix(ligne, "]"):
			courante = strings.Trim(ligne, "[]")
			out[courante] = map[string][]string{}
		default:
			cle, valeur, ok := strings.Cut(ligne, "=")
			if !ok || courante == "" {
				t.Fatalf("ligne d'unité illisible : %q", ligne)
			}
			out[courante][cle] = append(out[courante][cle], valeur)
		}
	}
	return out
}

func unique(t *testing.T, s map[string]map[string][]string, section, cle string) string {
	t.Helper()
	v := s[section][cle]
	if len(v) != 1 {
		t.Fatalf("[%s] %s : %d valeur(s) (%v), attendu une", section, cle, len(v), v)
	}
	return v[0]
}

func TestLaRelanceEstBornee(t *testing.T) {
	s := sections(t, Gabarit)

	if v := unique(t, s, "Service", "Restart"); v != "on-failure" {
		t.Errorf("Restart=%s", v)
	}
	if v := unique(t, s, "Service", "RestartSec"); v != "5s" {
		t.Errorf("RestartSec=%s, attendu 5s", v)
	}
	// Dans [Unit], PAS dans [Service] : c'est l'emplacement documenté. Le
	// second n'est plus qu'une tolérance de compatibilité.
	if v := unique(t, s, "Unit", "StartLimitBurst"); v != "3" {
		t.Errorf("StartLimitBurst=%s, attendu 3", v)
	}
	if v := unique(t, s, "Unit", "StartLimitIntervalSec"); v != "60" {
		t.Errorf("StartLimitIntervalSec=%s, attendu 60", v)
	}
	for _, cle := range []string{"StartLimitBurst", "StartLimitIntervalSec", "StartLimitInterval"} {
		if len(s["Service"][cle]) > 0 {
			t.Errorf("%s est dans [Service] : emplacement historique, que systemd ne garde que par compatibilité", cle)
		}
	}
}

func TestLeControlePrecedeLeDemarrage(t *testing.T) {
	s := sections(t, Gabarit)
	start := unique(t, s, "Service", "ExecStart")
	pre := unique(t, s, "Service", "ExecStartPre")
	if start != Binaire {
		t.Errorf("ExecStart=%s, attendu %s", start, Binaire)
	}
	// Le MÊME binaire, et sans le « - » qui ferait ignorer son échec : un
	// contrôle dont on ignore le verdict ne garde rien.
	if pre != Binaire+" --check" {
		t.Errorf("ExecStartPre=%q, attendu %q", pre, Binaire+" --check")
	}
	if unique(t, s, "Service", "User") != "root" {
		t.Error("l'agent ne tourne plus en root : il crée des comptes et applique des politiques système")
	}
}

// systemd lit-il cette unité sans rien y trouver à redire ? Sauté sans
// systemd-analyze. Le binaire est remplacé par un programme qui existe : la
// vérification refuse une unité dont l'exécutable est absent, ce qui est le cas
// sur toute machine de fabrication.
func TestSystemdAccepteLUnite(t *testing.T) {
	analyse, err := exec.LookPath("systemd-analyze")
	if err != nil {
		t.Skip("systemd-analyze absent")
	}
	vrai, err := exec.LookPath("true")
	if err != nil {
		t.Skip("pas de programme « true »")
	}
	d := t.TempDir()
	chemin := filepath.Join(d, "vaultaire_client.service")
	contenu := strings.ReplaceAll(Gabarit, Binaire, vrai)
	contenu = strings.ReplaceAll(contenu, "WorkingDirectory=/etc/vaultaire_client", "WorkingDirectory="+d)
	if err := os.WriteFile(chemin, []byte(contenu), 0o644); err != nil {
		t.Fatal(err)
	}
	sortie, err := exec.Command(analyse, "verify", chemin).CombinedOutput()
	texte := string(sortie)
	// Les remarques sur d'AUTRES unités de la machine ne nous concernent pas.
	var remarques []string
	for _, ligne := range strings.Split(texte, "\n") {
		if strings.Contains(ligne, "vaultaire_client.service") {
			remarques = append(remarques, ligne)
		}
	}
	if len(remarques) > 0 {
		t.Fatalf("systemd-analyze verify (%v) :\n%s", err, strings.Join(remarques, "\n"))
	}
}

// env assemble une installation d'essai : un dossier pour l'unité, et tout ce
// qui autorise l'écriture.
type essai struct {
	env       Environnement
	recharges int
}

func nouvelEssai(t *testing.T) *essai {
	t.Helper()
	e := &essai{}
	e.env = Environnement{
		CheminUnite:  filepath.Join(t.TempDir(), "vaultaire_client.service"),
		Executable:   func() (string, error) { return Binaire, nil },
		EstRoot:      func() bool { return true },
		Controler:    func() []controle.Constat { return []controle.Constat{{Sujet: "configuration", Gravite: controle.Bon}} },
		SystemdActif: func() bool { return true },
		Recharger:    func() error { e.recharges++; return nil },
	}
	return e
}

const ancienneUnite = `[Unit]
Description=Vaultaire Client Service
After=network.target

[Service]
User=root
Group=root
ExecStart=/usr/bin/vaultaire_client
WorkingDirectory=/etc/vaultaire_client
Environment=USER=root
LimitNOFILE=4096
Restart=on-failure

[Install]
WantedBy=multi-user.target
`

func TestLUniteDejaPoseeEstRattrapee(t *testing.T) {
	e := nouvelEssai(t)
	if err := os.WriteFile(e.env.CheminUnite, []byte(ancienneUnite), 0o644); err != nil {
		t.Fatal(err)
	}
	var sortie bytes.Buffer
	if err := Installer(e.env, &sortie); err != nil {
		t.Fatalf("%v\n%s", err, sortie.String())
	}
	ecrite, _ := os.ReadFile(e.env.CheminUnite)
	if string(ecrite) != Gabarit {
		t.Fatalf("l'unité en place n'est pas le gabarit :\n%s", ecrite)
	}
	gardee, err := os.ReadFile(e.env.CheminUnite + ".precedente")
	if err != nil || string(gardee) != ancienneUnite {
		t.Fatalf("l'unité précédente n'est pas gardée (%v) : sans elle, pas de retour en arrière en une commande", err)
	}
	if e.recharges != 1 {
		t.Fatalf("%d rechargement(s) : systemd garderait l'ancienne unité en mémoire", e.recharges)
	}
	if info, _ := os.Stat(e.env.CheminUnite); info.Mode().Perm() != 0o644 {
		t.Errorf("mode %04o : systemd avertit sur une unité non lisible par tous", info.Mode().Perm())
	}

	// Rejouée : rien ne bouge, rien n'est rechargé, et la sauvegarde n'est pas
	// écrasée par la nouvelle unité — elle doit rester l'ANCIENNE.
	sortie.Reset()
	if err := Installer(e.env, &sortie); err != nil {
		t.Fatal(err)
	}
	if e.recharges != 1 || !strings.Contains(sortie.String(), "déjà à jour") {
		t.Fatalf("seconde passe : %d rechargement(s)\n%s", e.recharges, sortie.String())
	}
	if gardee, _ := os.ReadFile(e.env.CheminUnite + ".precedente"); string(gardee) != ancienneUnite {
		t.Fatal("la sauvegarde a été remplacée par l'unité courante")
	}
}

func TestSurUneMachineNeuveLUniteEstEcrite(t *testing.T) {
	e := nouvelEssai(t)
	e.env.SystemdActif = func() bool { return false }
	var sortie bytes.Buffer
	if err := Installer(e.env, &sortie); err != nil {
		t.Fatalf("%v\n%s", err, sortie.String())
	}
	if ecrite, _ := os.ReadFile(e.env.CheminUnite); string(ecrite) != Gabarit {
		t.Fatal("unité non écrite")
	}
	if _, err := os.Stat(e.env.CheminUnite + ".precedente"); err == nil {
		t.Error("une sauvegarde a été créée alors qu'il n'y avait rien à sauvegarder")
	}
	if e.recharges != 0 {
		t.Error("rechargement demandé sans systemd : la commande échouerait dans un conteneur")
	}
}

// Les trois refus. Aucun ne doit laisser une trace sur le disque.
func TestLesRefusNEcriventRien(t *testing.T) {
	cas := []struct {
		nom    string
		regler func(e *essai)
		dit    string
	}{
		{"pas root", func(e *essai) { e.env.EstRoot = func() bool { return false } }, "root"},
		// Une copie de travail, ou une version plus récente posée ailleurs :
		// rien ne dit que le binaire de /usr/bin connaît --check.
		{"un autre binaire", func(e *essai) {
			e.env.Executable = func() (string, error) { return "/root/vaultaire_client", nil }
		}, "/usr/bin/vaultaire_client"},
		{"binaire introuvable", func(e *essai) {
			e.env.Executable = func() (string, error) { return "", errors.New("introuvable") }
		}, "/usr/bin/vaultaire_client"},
		// L'unité rejoue ce contrôle avant chaque démarrage : la poser quand il
		// échoue, c'est décider que l'agent ne redémarrera pas.
		{"contrôle bloquant", func(e *essai) {
			e.env.Controler = func() []controle.Constat {
				return []controle.Constat{{Sujet: "clé privée", Gravite: controle.Bloquant, Detail: "absente"}}
			}
		}, "Rien n'a été écrit"},
	}
	for _, cs := range cas {
		t.Run(cs.nom, func(t *testing.T) {
			e := nouvelEssai(t)
			if err := os.WriteFile(e.env.CheminUnite, []byte(ancienneUnite), 0o644); err != nil {
				t.Fatal(err)
			}
			cs.regler(e)
			var sortie bytes.Buffer
			err := Installer(e.env, &sortie)
			if !errors.Is(err, ErrRefus) {
				t.Fatalf("erreur %v, attendu un refus\n%s", err, sortie.String())
			}
			if !strings.Contains(sortie.String(), cs.dit) {
				t.Errorf("le refus ne dit pas pourquoi (« %s ») :\n%s", cs.dit, sortie.String())
			}
			if en, _ := os.ReadFile(e.env.CheminUnite); string(en) != ancienneUnite {
				t.Fatal("l'unité a été réécrite malgré le refus")
			}
			restes, _ := os.ReadDir(filepath.Dir(e.env.CheminUnite))
			if len(restes) != 1 {
				t.Fatalf("le refus a laissé des fichiers : %v", restes)
			}
			if e.recharges != 0 {
				t.Error("systemd rechargé malgré le refus")
			}
		})
	}
}

// Une attention n'empêche rien : seul le bloquant refuse.
func TestUneAttentionNEmpechePasDInstaller(t *testing.T) {
	e := nouvelEssai(t)
	e.env.Controler = func() []controle.Constat {
		return []controle.Constat{{Sujet: "clé du core", Gravite: controle.Attention, Detail: "sans empreinte"}}
	}
	var sortie bytes.Buffer
	if err := Installer(e.env, &sortie); err != nil {
		t.Fatalf("%v\n%s", err, sortie.String())
	}
}

func TestUnRechargementEnEchecSeDit(t *testing.T) {
	e := nouvelEssai(t)
	e.env.Recharger = func() error { return errors.New("bus indisponible") }
	var sortie bytes.Buffer
	err := Installer(e.env, &sortie)
	if err == nil || errors.Is(err, ErrRefus) {
		t.Fatalf("erreur %v : un rechargement manqué passe pour un succès — systemd garderait l'ancienne unité", err)
	}
}
