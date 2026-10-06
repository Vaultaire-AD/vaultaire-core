package gpo

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
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
// # Pourquoi l'inscription se fait à l'écriture et non par module
//
// Les écritures du scope machine passent TOUTES par writeSystemFile. Y noter le
// chemin et le hachage couvre donc l'ensemble sans toucher aux appliqueurs, et
// sans qu'un appliqueur écrit demain puisse l'oublier.
//
// Ce paragraphe disait « il n'existe aucun autre chemin d'écriture — vérifié ».
// C'était faux, et c'est le point 135 : le scope UTILISATEUR écrivait par
// `writeUserFile`, qui n'inscrivait rien. Ses fichiers n'entraient jamais dans
// l'inventaire, le scan n'avait rien à comparer, et un `HOME` défait restait
// affiché conforme. Les deux chemins inscrivent désormais, chacun dans
// l'inventaire de son cycle, et un test-sentinelle interdit d'en ouvrir un
// troisième (sentinelle_inventaire_test.go).
//
// L'attribution à un module se fait par les marques : applyModule relève le
// rang de l'inventaire avant l'appel, et ce qui a été inscrit après appartient
// au module qu'il vient d'appliquer.

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

	// Owners liste TOUS les modules qui répondent de ce fichier, quand il y en
	// a plusieurs — TO-DO 135.
	//
	// # Le cas qui l'exige
	//
	// Toutes les variables d'environnement d'un compte vivent dans un seul
	// `.vaultaire_env`, et chacune est un module. Avec un propriétaire unique,
	// le fichier appartenait au dernier module à l'avoir écrit : retirer CE
	// module de la politique faisait sortir le fichier de l'inventaire alors
	// que les autres variables y vivaient encore — plus personne ne le
	// surveillait, et rien ne le disait.
	//
	// # Ce que le scan en fait
	//
	// Un écart sur un fichier partagé fait rejouer TOUS ses propriétaires, dans
	// l'ordre de la politique : c'est la seule façon de retrouver le contenu
	// qu'ils produisent ensemble.
	//
	// CHAMP AJOUTÉ, avec omitempty, et écrit SEULEMENT s'il y a plusieurs
	// propriétaires. `StateKey` reste renseigné — le dernier à avoir écrit — et
	// un agent antérieur qui relirait cet état y trouve ce qu'il sait lire.
	Owners []string `json:"owners,omitempty"`
}

// Les fonctions de ce fichier inscrivent dans l'inventaire du cycle MACHINE.
//
// Elles n'ont pas changé de nom ni de signature : les appliqueurs du scope
// machine les appellent par `writeSystemFile` et `removeSystemFile`, sans rien
// savoir du cycle qui les porte. Ce qu'elles ont perdu, c'est la carte globale
// qu'elles partageaient avec tous les cycles — voir inventaire.go, qui dit
// pourquoi (TO-DO 135).
//
// Un appliqueur qui connaît le scope UTILISATEUR n'a pas le droit de s'en
// servir : il passe par les formes qui prennent le contexte (`writeUserFile`,
// `removeUserFile`, `ctx.writeSystemFile`, `ctx.recordCheck`), qui inscrivent
// dans l'inventaire de SON cycle.

// ResetManifest vide l'inventaire de travail du cycle machine, fichiers ET
// attentes : les deux ont le même cycle de vie, et en vider un seul laisserait
// l'autre attribuer ses entrées au module d'un cycle antérieur.
//
// Appelé par ApplyPolicy au début de chaque application machine.
func ResetManifest() { inventaireMachine.vider() }

// manifestSnapshot rend ce que le cycle machine a inscrit jusqu'ici.
//
// Pour un test ou un diagnostic : le moteur n'attribue plus par comparaison de
// relevés mais par les marques de l'inventaire.
func manifestSnapshot() map[string]FileState { return inventaireMachine.releveFichiers() }

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
