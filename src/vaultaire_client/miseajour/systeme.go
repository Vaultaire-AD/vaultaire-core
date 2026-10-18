package miseajour

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// Le basculement (TO-DO 116) : les chemins, la famille, l'état, le verrou.
//
// Tout ce qui touche au système passe par Chemins et Systeme : les tests jouent
// le basculement entier dans un répertoire temporaire, avec de faux systemctl,
// ldd et systemd-run, sans jamais toucher /usr.

// Chemins : où sont les fichiers d'une installation.
type Chemins struct {
	Binaire   string   // l'agent, que l'unité lance
	Updater   string   // la copie qui fait la bascule
	Etat      string   // /var/lib/vaultaire/updates
	Unite     string   // l'unité systemd de l'agent
	OSRelease string   // pour la famille
	ReposPAM  []string // candidats, dans l'ordre des scripts d'installation
}

// CheminsReels : ceux de rocky.sh et debian.sh.
func CheminsReels() Chemins {
	return Chemins{
		Binaire:   "/usr/bin/vaultaire_client",
		Updater:   "/usr/libexec/vaultaire/vaultaire_update",
		Etat:      "/var/lib/vaultaire/updates",
		Unite:     "/etc/systemd/system/vaultaire_client.service",
		OSRelease: "/etc/os-release",
		ReposPAM: []string{
			"/usr/lib64/security", "/lib64/security",
			"/lib/x86_64-linux-gnu/security", "/usr/lib/x86_64-linux-gnu/security",
		},
	}
}

// Systeme lance une commande et rend sa sortie. Remplaçable par les tests.
type Systeme func(nom string, args ...string) ([]byte, error)

// SystemeReel lance pour de vrai, borné à deux minutes.
func SystemeReel(nom string, args ...string) ([]byte, error) {
	cmd := exec.Command(nom, args...)
	done := make(chan struct{})
	var sortie []byte
	var err error
	go func() { sortie, err = cmd.CombinedOutput(); close(done) }()
	select {
	case <-done:
		return sortie, err
	case <-time.After(2 * time.Minute):
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		<-done
		return sortie, fmt.Errorf("%s : délai dépassé", nom)
	}
}

// FamilleDe lit la famille dans /etc/os-release — la MÊME règle que le core
// pour choisir le script d'installation (ScriptDInstallation) : la ligne ID=
// seule, ID_LIKE ignoré. Une machine reçoit les modules de la famille dont
// elle a reçu le script, ou rien.
func FamilleDe(osRelease string) (string, error) {
	for _, ligne := range strings.Split(osRelease, "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(ligne), "ID="); ok {
			switch strings.ToLower(strings.Trim(strings.TrimSpace(v), `"'`)) {
			case "rocky":
				return "rocky", nil
			case "debian", "ubuntu":
				return "debian", nil
			case "":
			default:
				return "", fmt.Errorf("distribution %q : aucune famille de modules", strings.Trim(v, `"'`))
			}
		}
	}
	return "", fmt.Errorf("aucune ligne ID= dans os-release")
}

// RepertoirePAM rend le répertoire où les modules Vaultaire SONT installés —
// on remplace là où ils sont, pas là où ils devraient être.
func RepertoirePAM(c Chemins) (string, error) {
	for _, d := range c.ReposPAM {
		if _, err := os.Stat(filepath.Join(d, "pam_login_custom_module.so")); err == nil {
			return d, nil
		}
	}
	return "", fmt.Errorf("modules PAM de Vaultaire introuvables (%s)", strings.Join(c.ReposPAM, ", "))
}

// --- l'état, que le compte rendu reprend au redémarrage -------------------

// EtatFichier : le dernier résultat d'une mise à jour, écrit par celui qui le
// connaît — l'agent quand il refuse, l'updater quand il bascule. L'agent qui
// démarre ensuite le rapporte en 09_04, puis le marque rapporté.
type EtatFichier struct {
	Version  string    `json:"version"`
	Resultat string    `json:"resultat"`
	Motif    string    `json:"motif"`
	Le       time.Time `json:"le"`
	Rapporte bool      `json:"rapporte"`
}

func cheminEtat(c Chemins) string { return filepath.Join(c.Etat, "etat.json") }

// EcrireEtat écrit l'état de façon atomique.
func EcrireEtat(c Chemins, e EtatFichier) error {
	if err := os.MkdirAll(c.Etat, 0o700); err != nil {
		return err
	}
	if e.Le.IsZero() {
		e.Le = time.Now()
	}
	b, err := json.MarshalIndent(e, "", "  ")
	if err != nil {
		return err
	}
	return ecrireAtomique(cheminEtat(c), b, 0o600)
}

// LireEtat rend l'état, et false s'il n'y en a pas.
func LireEtat(c Chemins) (EtatFichier, bool) {
	b, err := os.ReadFile(cheminEtat(c))
	if err != nil {
		return EtatFichier{}, false
	}
	var e EtatFichier
	if json.Unmarshal(b, &e) != nil || e.Version == "" || e.Resultat == "" {
		return EtatFichier{}, false
	}
	return e, true
}

// --- le verrou : une mise à jour à la fois ----------------------------------

// VieDuVerrou : au-delà, un verrou est tenu pour abandonné (updater tué).
const VieDuVerrou = 30 * time.Minute

func cheminVerrou(c Chemins) string { return filepath.Join(c.Etat, "verrou") }

// PrendreVerrou rend false si une mise à jour est en cours.
func PrendreVerrou(c Chemins, version string) bool {
	if err := os.MkdirAll(c.Etat, 0o700); err != nil {
		return false
	}
	if info, err := os.Stat(cheminVerrou(c)); err == nil {
		if time.Since(info.ModTime()) < VieDuVerrou {
			return false
		}
		_ = os.Remove(cheminVerrou(c))
	}
	f, err := os.OpenFile(cheminVerrou(c), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return false
	}
	_, _ = f.WriteString(version + "\n")
	return f.Close() == nil
}

// VerrouTenu dit si une mise à jour est en cours — un verrou présent et pas
// encore abandonné. La réconciliation de la configuration (TO-DO 117) attend
// qu'il soit rendu : après une bascule, l'updater ne le rend qu'une fois la
// porte de santé passée.
func VerrouTenu(c Chemins) bool {
	info, err := os.Stat(cheminVerrou(c))
	return err == nil && time.Since(info.ModTime()) < VieDuVerrou
}

// LibererVerrou rend la main.
func LibererVerrou(c Chemins) { _ = os.Remove(cheminVerrou(c)) }

// ecrireAtomique : fichier temporaire dans le MÊME répertoire, puis rename —
// atomique au sein d'un système de fichiers, et seulement là.
func ecrireAtomique(chemin string, contenu []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(chemin), "."+filepath.Base(chemin)+".vaultaire-*")
	if err != nil {
		return err
	}
	nom := tmp.Name()
	_, errW := tmp.Write(contenu)
	errS := tmp.Sync()
	errC := tmp.Close()
	if errW != nil || errS != nil || errC != nil {
		_ = os.Remove(nom)
		return fmt.Errorf("écriture de %s : %v %v %v", chemin, errW, errS, errC)
	}
	if err := os.Chmod(nom, mode); err != nil {
		_ = os.Remove(nom)
		return err
	}
	if err := os.Rename(nom, chemin); err != nil {
		_ = os.Remove(nom)
		return err
	}
	return nil
}
