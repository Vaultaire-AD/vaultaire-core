package gpo

import (
	"fmt"
	"os"
	"sort"

	"duckynetworkclient/V1/duckynetwork/logs"
)

// Détection de dérive.
//
// # Ce que cela répond
//
// « Un module marqué appliqué avec succès correspond-il encore à l'état réel du
// système ? » Jusqu'ici, personne ne posait la question : applyModule renvoyait
// « unchanged » sur simple correspondance d'empreinte, et un fichier édité à la
// main n'était plus jamais réappliqué.
//
// # Mode enforce ou audit
//
// En ENFORCE, le scan oublie l'empreinte du module dérivé : le cycle suivant le
// réapplique, et la politique redevient la source de vérité. C'est le
// comportement d'un annuaire ou d'un gestionnaire de configuration.
//
// En AUDIT, il se contente de signaler. À réserver aux parcs où des
// interventions manuelles légitimes existent — mais une GPO qui n'est plus
// appliquée et reste affichée comme conforme est pire que pas de GPO du tout.
//
// La correction n'est jamais IMMÉDIATE : réappliquer un module peut relancer un
// service, et le faire à l'instant de la détection reviendrait à redémarrer sshd
// pendant qu'un administrateur débogue. Le cycle suivant s'en charge, à un
// moment prévisible.

// DriftMode décide de ce que le scan fait d'un écart.
type DriftMode string

const (
	// DriftEnforce signale ET fait réappliquer au cycle suivant.
	DriftEnforce DriftMode = "enforce"
	// DriftAudit signale seulement.
	DriftAudit DriftMode = "audit"
)

// CurrentDriftMode est le mode actif.
//
// Variable et non constante : destinée à être relue depuis la configuration de
// l'agent. Enforce par défaut — c'est ce qu'on attend d'une politique.
var CurrentDriftMode = DriftEnforce

// DriftKind qualifie l'écart constaté.
type DriftKind string

const (
	// DriftModified : le contenu a changé.
	DriftModified DriftKind = "modified"
	// DriftMissing : le fichier a disparu.
	DriftMissing DriftKind = "missing"
	// DriftUnreadable : le fichier existe mais n'est pas lisible.
	//
	// Distinct de « disparu » : ses droits ont pu être changés, ce qui est une
	// dérive en soi, et le contenu reste inconnu.
	DriftUnreadable DriftKind = "unreadable"
	// DriftPermissions : le contenu est bon, le mode ne l'est plus.
	DriftPermissions DriftKind = "permissions"
	// DriftReappeared : un fichier que la politique RETIRE a été recréé.
	//
	// L'exact opposé de DriftMissing, et il fallait les distinguer : ils
	// n'appellent pas la même lecture. « Disparu » se lit comme un fichier
	// effacé par erreur ; « réapparu » se lit comme une interdiction contournée
	// — un module noyau réautorisé, un dépôt de paquets remis, un durcissement
	// PAM annulé.
	DriftReappeared DriftKind = "reappeared"
	// DriftSystemState : un effet NON-fichier ne tient plus.
	//
	// Un service réactivé, une règle nftables disparue, un compte remis dans
	// sudo. Le fichier qui décrit l'état voulu peut être parfaitement intact :
	// c'est l'état lui-même qui a bougé.
	DriftSystemState DriftKind = "system_state"
	// DriftUnverifiable : l'état n'a pas pu être constaté.
	//
	// Le pendant de DriftUnreadable pour les effets non-fichier — commande
	// absente, délai dépassé, sortie inattendue. Distinct de DriftSystemState
	// pour la même raison : ici on ne sait pas, on ne constate pas. Confondre
	// les deux ferait réapplique un module sur une simple incertitude.
	DriftUnverifiable DriftKind = "unverifiable"
)

// DriftItem est un écart constaté sur un fichier.
type DriftItem struct {
	Path     string
	StateKey string
	Kind     DriftKind
	Detail   string
}

// DriftReport est le résultat d'un scan pour un scope.
type DriftReport struct {
	Scope    string
	Username string
	// Checked est le nombre de fichiers examinés — utile pour distinguer
	// « conforme » de « rien à vérifier ».
	Checked int
	Items   []DriftItem
}

// Conforming dit si rien n'a dérivé.
func (r DriftReport) Conforming() bool { return len(r.Items) == 0 }

// ModulesConcerned rend les modules à réappliquer, sans doublon.
func (r DriftReport) ModulesConcerned() []string {
	vus := map[string]struct{}{}
	var keys []string
	for _, item := range r.Items {
		if item.StateKey == "" {
			continue
		}
		if _, déjà := vus[item.StateKey]; déjà {
			continue
		}
		vus[item.StateKey] = struct{}{}
		keys = append(keys, item.StateKey)
	}
	sort.Strings(keys)
	return keys
}

// ScanScope compare l'état réel d'un scope à l'inventaire.
//
// Deux inventaires, deux comparaisons : les FICHIERS déposés ou retirés, et les
// ATTENTES d'état système déclarées par les modules — un service actif, une
// règle de pare-feu, une appartenance de groupe.
//
// Ne modifie rien : c'est une lecture. La correction est décidée par
// EnforceDrift, séparément, pour qu'un scan puisse être lancé sans effet de bord.
func ScanScope(scope, username string) DriftReport {
	state := LoadState()
	return scanFromState(state.Scope(scope, username), scope, username)
}

// scanFromState est le cœur du scan, séparé de la lecture de l'état.
//
// Séparé pour être testable : l'état vit dans /var/lib/vaultaire, que seul
// root peut écrire. Un test qui exigerait ce droit ne serait jamais lancé, et
// c'est précisément la partie qu'il faut vérifier.
func scanFromState(scopeState *ScopeState, scope, username string) DriftReport {
	report := DriftReport{Scope: scope, Username: username}

	// Les attentes d'état système sont constatées AVANT les fichiers, et
	// séparément : elles ne dépendent pas de l'inventaire des fichiers, et un
	// module peut très bien n'avoir déclaré qu'une attente — un service à
	// laisser actif, sans aucun fichier déposé.
	//
	// Compté dans Checked, au même titre qu'un fichier : « conforme » et « rien
	// à vérifier » doivent rester distinguables, et un module qui ne dépose
	// aucun fichier aurait sinon un rapport à zéro contrôle.
	if scopeState != nil {
		verifs := scanChecks(scopeState)
		report.Checked += len(scopeState.Checks)
		report.Items = append(report.Items, verifs...)
	}

	if scopeState == nil || len(scopeState.Files) == 0 {
		// Aucun inventaire : soit rien n'a été appliqué, soit l'état vient d'une
		// version antérieure qui ne l'enregistrait pas. Dans les deux cas il n'y
		// a rien à comparer, et signaler une dérive serait faux.
		return report
	}

	chemins := make([]string, 0, len(scopeState.Files))
	for path := range scopeState.Files {
		chemins = append(chemins, path)
	}
	// Trié pour que deux scans successifs sur un même état produisent le même
	// rapport, dans le même ordre : un rapport dont l'ordre change à chaque
	// exécution est illisible en comparaison.
	sort.Strings(chemins)

	for _, path := range chemins {
		attendu := scopeState.Files[path]
		report.Checked++

		// Les entrées d'ABSENCE se lisent à l'envers : la dérive n'est pas la
		// disparition, c'est la réapparition. Traitées avant tout le reste, car
		// aucun des contrôles qui suivent — hachage, mode — n'a de sens sur un
		// fichier qui ne doit pas exister.
		if attendu.Absent {
			if _, err := os.Stat(path); err == nil {
				report.Items = append(report.Items, DriftItem{
					Path: path, StateKey: attendu.StateKey, Kind: DriftReappeared,
					Detail: "fichier recree alors que la politique le retire",
				})
			}
			// Une erreur autre que « n'existe pas » — un répertoire parent
			// devenu illisible, par exemple — n'est PAS signalée. On ne peut
			// alors rien affirmer, et déclarer une dérive sur une incertitude
			// ferait réappliquer un module sans motif.
			continue
		}

		info, err := os.Stat(path)
		if os.IsNotExist(err) {
			report.Items = append(report.Items, DriftItem{
				Path: path, StateKey: attendu.StateKey, Kind: DriftMissing,
				Detail: "fichier supprime",
			})
			continue
		}
		if err != nil {
			report.Items = append(report.Items, DriftItem{
				Path: path, StateKey: attendu.StateKey, Kind: DriftUnreadable,
				Detail: sanitizeDetail(err.Error()),
			})
			continue
		}

		actuel, lisible := HashFile(path)
		if !lisible {
			report.Items = append(report.Items, DriftItem{
				Path: path, StateKey: attendu.StateKey, Kind: DriftUnreadable,
				Detail: "contenu illisible",
			})
			continue
		}

		if actuel != attendu.SHA256 {
			report.Items = append(report.Items, DriftItem{
				Path: path, StateKey: attendu.StateKey, Kind: DriftModified,
				Detail: "contenu modifie",
			})
			continue
		}

		// Le contenu est bon mais le mode a changé : c'est une dérive à part
		// entière. Un fichier de configuration passé en lecture pour tous peut
		// exposer ce qu'il contient sans qu'une seule ligne n'ait bougé.
		if attendu.Mode != 0 && uint32(info.Mode().Perm()) != attendu.Mode {
			report.Items = append(report.Items, DriftItem{
				Path: path, StateKey: attendu.StateKey, Kind: DriftPermissions,
				Detail: fmt.Sprintf("mode %04o attendu %04o", info.Mode().Perm(), attendu.Mode),
			})
		}
	}

	return report
}

// EnforceDrift applique la politique de correction.
//
// En enforce, retire l'empreinte des modules concernés : ils seront réappliqués
// au cycle suivant. Retourne le nombre de modules marqués.
func EnforceDrift(scope, username string, report DriftReport) int {
	if report.Conforming() {
		return 0
	}

	for _, item := range report.Items {
		logs.Write_log("WARNING", fmt.Sprintf(
			"GPO: derive detectee sur %s (%s) — %s", item.Path, item.Kind, item.Detail))
	}

	if CurrentDriftMode != DriftEnforce {
		logs.Write_log("INFO", fmt.Sprintf(
			"GPO: mode audit, %d ecart(s) signale(s) sans correction", len(report.Items)))
		return 0
	}

	modules := report.ModulesConcerned()
	if len(modules) == 0 {
		// Des écarts sans module identifié : l'inventaire vient d'une version
		// qui ne notait pas l'origine. Rien à réappliquer de ciblé, on le dit
		// plutôt que de laisser croire à une correction.
		logs.Write_log("WARNING",
			"GPO: derive detectee mais aucun module identifie, reapplication impossible")
		return 0
	}

	state := LoadState()
	scopeState := state.Scope(scope, username)
	if scopeState == nil {
		return 0
	}
	for _, key := range modules {
		scopeState.ForgetModule(key)
	}

	// L'empreinte de POLITIQUE est effacée elle aussi.
	//
	// Sans cela, le cycle suivant verrait l'empreinte inchangée, conclurait que
	// la machine est à jour, et n'irait jamais jusqu'à la comparaison par
	// module — la correction n'aurait donc jamais lieu.
	scopeState.Fingerprint = ""

	if err := SaveScopeState(scope, username, scopeState); err != nil {
		logs.Write_log("ERROR", "GPO: etat non enregistre apres detection de derive : "+err.Error())
		return 0
	}

	logs.Write_log("INFO", fmt.Sprintf(
		"GPO: %d module(s) marque(s) pour reapplication au prochain cycle : %v",
		len(modules), modules))
	return len(modules)
}
