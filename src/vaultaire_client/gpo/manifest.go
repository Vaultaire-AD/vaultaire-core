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

// FileState est l'état attendu d'un fichier déposé — ou retiré.
type FileState struct {
	// SHA256 du contenu écrit. Vide pour une entrée d'absence.
	SHA256 string `json:"sha256"`
	// Mode au moment de l'écriture. Nul pour une entrée d'absence.
	Mode uint32 `json:"mode"`
	// StateKey du module qui l'a déposé, pour savoir quoi réappliquer.
	StateKey string `json:"state_key,omitempty"`

	// Absent inverse le sens de l'entrée : le module ne demande pas que ce
	// fichier ait un certain contenu, il demande qu'il N'EXISTE PAS.
	//
	// # Pourquoi cela ne pouvait pas être déduit
	//
	// Une entrée sans hachage aurait pu servir de marqueur, mais elle se
	// confondrait avec un fichier écrit vide — cas réel : un `authorized_keys`
	// dont toutes les clés ont été révoquées. Le drapeau nomme l'intention au
	// lieu de la faire deviner.
	//
	// # Ce que le scan en fait
	//
	// L'inverse exactement de ce qu'il fait des autres : la dérive n'est pas la
	// disparition, c'est la RÉAPPARITION.
	//
	// CHAMP AJOUTÉ, avec omitempty : un état écrit par une version antérieure
	// n'en a pas, se relit sans erreur, et vaut « faux » — donc l'ancien
	// comportement.
	Absent bool `json:"absent,omitempty"`
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
	manifest = map[string]FileState{}
	manifestMu.Unlock()

	// Les attentes d'état système suivent le MÊME cycle de vie. Les vider
	// ailleurs laisserait l'un des deux inventaires survivre à l'autre, et une
	// attente serait attribuée au module d'un cycle antérieur.
	ResetCheckManifest()
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

// recordAbsent note qu'un fichier ne doit PAS exister.
//
// Appelé par removeSystemFile, jamais directement — même discipline que
// recordWrite : l'inventaire suit les suppressions réelles, pas une liste tenue
// à la main.
//
// # Le trou que cela ferme
//
// Un module dont l'effet est « ce fichier ne doit pas exister » ne laissait
// AUCUNE trace dans l'inventaire. Le recréer ne produisait donc aucun écart : le
// scan ne compare que ce qu'il connaît, et il ne connaissait que des écritures.
//
// Concrètement : une GPO retire /etc/modprobe.d/vaultaire-usb-storage.conf pour
// lever une interdiction, ou l'inverse — pose un fichier interdisant un module
// noyau. Quelqu'un le recrée, ou le rétablit, et la machine reste déclarée
// conforme indéfiniment.
//
// # Écraser une entrée d'écriture, et l'inverse
//
// Les deux sens sont possibles dans un même cycle : un module peut retirer un
// fichier qu'un module antérieur avait déposé. La dernière opération gagne,
// puisque c'est elle qui décrit l'état où le système a été laissé.
func recordAbsent(path string) {
	manifestMu.Lock()
	defer manifestMu.Unlock()
	manifest[path] = FileState{Absent: true}
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

// manifestSince rend les entrées apparues OU MODIFIÉES depuis un relevé.
//
// C'est le mécanisme d'attribution : applyModule relève l'inventaire avant
// d'appeler l'appliqueur, puis demande ce qui a bougé.
//
// # Pourquoi « ou modifiées » et non « apparues »
//
// La comparaison portait sur la seule PRÉSENCE du chemin. Deux modules qui
// touchent au même fichier dans un cycle — le second le réécrit, ou le retire —
// laissaient donc l'entrée attribuée au PREMIER, avec son hachage d'origine. Le
// scan signalait ensuite une dérive permanente sur un fichier parfaitement
// conforme à ce que le second module en a fait, et faisait réappliquer le
// mauvais module.
//
// Le cas devient courant avec les entrées d'absence : « ce fichier ne doit pas
// exister » vient souvent APRÈS un module qui l'avait déposé.
func manifestSince(avant map[string]FileState, stateKey string) map[string]FileState {
	manifestMu.Lock()
	defer manifestMu.Unlock()

	nouveaux := map[string]FileState{}
	for path, state := range manifest {
		if ancien, existait := avant[path]; existait &&
			ancien.SHA256 == state.SHA256 &&
			ancien.Mode == state.Mode &&
			ancien.Absent == state.Absent {
			continue
		}
		state.StateKey = stateKey
		nouveaux[path] = state
	}
	return nouveaux
}

// manifestSnapshot relève l'inventaire, pour comparaison ultérieure.
//
// Copie les états et pas seulement les clés : c'est ce qui permet à
// manifestSince de voir qu'un fichier déjà connu a changé.
func manifestSnapshot() map[string]FileState {
	manifestMu.Lock()
	defer manifestMu.Unlock()
	vue := make(map[string]FileState, len(manifest))
	for p, s := range manifest {
		vue[p] = s
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
