package gpo

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"sort"
	"sync"
)

// Inventaire des fichiers déposés par les GPO.
//
// # Le défaut que cela ferme
//
// applyModule renvoyait « unchanged » dès que l'empreinte d'un module
// correspondait à celle enregistrée, SANS jamais regarder le système. Un
// administrateur qui éditait à la main /etc/ssh/sshd_config.d/99-vaultaire-gpo.conf
// laissait l'empreinte intacte : le module n'était plus jamais réappliqué, et
// l'interface continuait d'afficher la politique comme appliquée avec succès.
//
// Une GPO qui n'est plus appliquée mais affichée comme conforme est pire que pas
// de GPO : elle donne une garantie qui n'existe plus.
//
// # Pourquoi l'inventaire est global et non par module
//
// Les 29 écritures de fichiers du paquet passent TOUTES par writeSystemFile, et
// il n'existe aucun autre chemin d'écriture — vérifié. Y noter le chemin et le
// hachage couvre donc l'ensemble sans toucher aux 34 appliqueurs, et sans qu'un
// appliqueur écrit demain puisse l'oublier.
//
// L'attribution à un module se fait par différence : applyModule relève
// l'inventaire avant et après l'appel, et ce qui est apparu entre les deux
// appartient au module qu'il vient d'appliquer.

// FileState est l'état attendu d'un fichier déposé.
type FileState struct {
	// SHA256 du contenu écrit.
	SHA256 string `json:"sha256"`
	// Mode au moment de l'écriture.
	Mode uint32 `json:"mode"`
	// StateKey du module qui l'a déposé, pour savoir quoi réappliquer.
	StateKey string `json:"state_key,omitempty"`
}

var (
	manifestMu sync.Mutex
	// manifest accumule les écritures de l'application EN COURS.
	//
	// Vidé au début de chaque cycle par ResetManifest : il ne sert qu'à
	// attribuer les fichiers à leur module, pas à conserver l'état, qui vit dans
	// applied_policies.json.
	manifest = map[string]FileState{}
)

// ResetManifest vide l'inventaire de travail.
//
// Appelé au début d'une application. Sans cela, deux cycles successifs
// mélangeraient leurs écritures et un fichier serait attribué au module d'un
// cycle antérieur.
func ResetManifest() {
	manifestMu.Lock()
	defer manifestMu.Unlock()
	manifest = map[string]FileState{}
}

// recordWrite note qu'un fichier vient d'être déposé.
//
// Appelé par writeSystemFile, jamais directement : c'est ce qui garantit que
// l'inventaire suit les écritures réelles et non une liste tenue à la main.
func recordWrite(path, content string, mode os.FileMode) {
	sum := sha256.Sum256([]byte(content))
	manifestMu.Lock()
	defer manifestMu.Unlock()
	manifest[path] = FileState{
		SHA256: hex.EncodeToString(sum[:]),
		Mode:   uint32(mode.Perm()),
	}
}

// manifestPaths rend les chemins écrits jusqu'ici, triés.
//
// Triés pour que la différence faite par applyModule soit déterministe : un
// parcours de map en ordre aléatoire rendrait les journaux et les rapports
// différents à chaque exécution, pour un même état.
func manifestPaths() []string {
	manifestMu.Lock()
	defer manifestMu.Unlock()
	paths := make([]string, 0, len(manifest))
	for p := range manifest {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	return paths
}

// manifestSince rend les fichiers apparus depuis un relevé.
//
// C'est le mécanisme d'attribution : applyModule relève l'inventaire avant
// d'appeler l'appliqueur, puis demande ce qui s'y est ajouté.
func manifestSince(avant map[string]struct{}, stateKey string) map[string]FileState {
	manifestMu.Lock()
	defer manifestMu.Unlock()

	nouveaux := map[string]FileState{}
	for path, state := range manifest {
		if _, existait := avant[path]; existait {
			continue
		}
		state.StateKey = stateKey
		nouveaux[path] = state
	}
	return nouveaux
}

// manifestSnapshot relève les chemins présents, pour comparaison ultérieure.
func manifestSnapshot() map[string]struct{} {
	manifestMu.Lock()
	defer manifestMu.Unlock()
	vue := make(map[string]struct{}, len(manifest))
	for p := range manifest {
		vue[p] = struct{}{}
	}
	return vue
}

// HashFile rend le hachage du contenu actuel d'un fichier.
//
// Retourne false si le fichier est absent ou illisible — les deux cas comptent
// comme une dérive, et l'appelant les distingue par un os.Stat.
func HashFile(path string) (string, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", false
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), true
}
