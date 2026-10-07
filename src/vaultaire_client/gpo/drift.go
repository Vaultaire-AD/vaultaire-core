package gpo

import (
	"errors"
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
//
// # D'où vient le mode
//
// Du CORE, module par module. Il était auparavant une variable de ce paquet, que
// personne ne renseignait : le mode audit était donc inatteignable en
// production. Le lire dans la configuration de l'agent aurait remis la décision
// sur la machine — celle qui dérive, et donc la dernière à qui la confier.
//
// Il est désormais un attribut de la GPO, hérité par ses modules, transmis dans
// la politique et mémorisé dans l'état local (ScopeState.Modes). Une machine qui
// reçoit une GPO en audit et une autre en enforce applique la règle de chacune
// sur SES modules : c'est ce qui permet un groupe « laboratoire » en audit sans
// désarmer le reste du parc.

// DriftMode décide de ce que le scan fait d'un écart.
type DriftMode string

const (
	// DriftEnforce signale ET fait réappliquer au cycle suivant.
	DriftEnforce DriftMode = "enforce"
	// DriftAudit signale seulement.
	DriftAudit DriftMode = "audit"
)

// DefaultDriftMode s'applique à un module dont le mode n'est pas connu.
//
// Le cas est courant et normal : le core n'écrit le mode que lorsqu'il s'écarte
// du défaut, et un état écrit par une version antérieure n'en contient aucun.
//
// Enforce, et jamais audit. Le défaut d'un mécanisme de conformité doit être de
// faire respecter la configuration : un défaut permissif transformerait chaque
// trou d'information — core plus ancien, état tronqué, mode inconnu — en machine
// silencieusement plus corrigée.
const DefaultDriftMode = DriftEnforce

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

	// Coproprietaires : les AUTRES modules qui écrivent le même fichier.
	//
	// Local à l'agent, jamais transmis : le rapport 05_15 garde un module par
	// ligne, celui qui a écrit en dernier. Ce champ ne sert qu'à décider quoi
	// rejouer — voir ModulesConcerned et FileState.Owners.
	Coproprietaires []string

	// NonCorrige : tous les modules qui répondent de cet écart sont en AUDIT —
	// il est signalé, et personne ne le corrigera (TO-DO 86).
	//
	// Posé par ScanScope, qui lit le mode dans l'état local ; transmis au core
	// en tête du détail (voir SendDriftReport). Sans cela, un écart en audit et
	// un écart en enforce se lisaient pareil dans « gpo status » : rien ne
	// disait lequel des deux allait rester.
	NonCorrige bool
}

// MentionAudit précède le détail d'un écart que l'agent ne corrigera pas.
//
// En TÊTE et non à la fin : le détail est tronqué à l'envoi, et c'est le début
// qui survit.
const MentionAudit = "[audit : signale, non corrige] "

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
//
// # Tous les propriétaires d'un fichier partagé
//
// Un fichier que plusieurs modules écrivent — `.vaultaire_env`, où vit chaque
// variable d'un compte — ne se rétablit qu'en les rejouant TOUS : n'en rejouer
// qu'un rendrait un fichier où il manque ce que les autres y mettaient, et dont
// le nouveau hachage serait aussitôt enregistré comme la référence.
//
// # Une incertitude ne fait rien rejouer
//
// `DriftUnverifiable` veut dire « je n'ai pas pu constater » : commande
// absente, délai dépassé. Le commentaire du type le dit depuis l'origine — sur
// une incertitude on ne réapplique rien — mais cette fonction rendait le module
// quand même, et EnforceDrift lui faisait perdre son empreinte. Un `getfacl`
// désinstallé faisait donc rejouer `setfacl` à chaque cycle, indéfiniment.
// L'écart reste dans le rapport, où il se lit ; il n'entre plus ici.
func (r DriftReport) ModulesConcerned() []string {
	vus := map[string]struct{}{}
	var keys []string
	noter := func(key string) {
		if key == "" {
			return
		}
		if _, déjà := vus[key]; déjà {
			return
		}
		vus[key] = struct{}{}
		keys = append(keys, key)
	}
	for _, item := range r.Items {
		if item.Kind == DriftUnverifiable {
			continue
		}
		noter(item.StateKey)
		for _, key := range item.Coproprietaires {
			noter(key)
		}
	}
	sort.Strings(keys)
	return keys
}

// seulementDesIncertitudes dit si aucun écart du rapport n'est un constat.
func (r DriftReport) seulementDesIncertitudes() bool {
	if len(r.Items) == 0 {
		return false
	}
	for _, item := range r.Items {
		if item.Kind != DriftUnverifiable {
			return false
		}
	}
	return true
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
	scopeState := state.Scope(scope, username)
	report := scanFromState(scopeState, scope, username)
	marquerLesNonCorriges(scopeState, &report)
	return report
}

// marquerLesNonCorriges repère les écarts dont AUCUN module n'est en enforce.
//
// Un fichier écrit par deux modules, l'un en audit et l'autre en enforce, sera
// réécrit par le second : l'écart sera corrigé, il n'est pas marqué. Une
// incertitude (« unverifiable ») ne l'est jamais non plus — elle ne fait rien
// rejouer, quel que soit le mode, et la dire « non corrigée pour cause
// d'audit » inventerait une cause.
func marquerLesNonCorriges(scopeState *ScopeState, report *DriftReport) {
	if scopeState == nil {
		return
	}
	for i := range report.Items {
		item := &report.Items[i]
		if item.Kind == DriftUnverifiable || item.Kind == DriftUnreadable {
			continue
		}
		modules := append([]string{item.StateKey}, item.Coproprietaires...)
		tousEnAudit, unModule := true, false
		for _, key := range modules {
			if key == "" {
				continue
			}
			unModule = true
			if scopeState.ModuleMode(key) != DriftAudit {
				tousEnAudit = false
			}
		}
		item.NonCorrige = unModule && tousEnAudit
	}
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
		compte := ""
		if scope == ScopeUser {
			compte = username
		}
		verifs := scanChecks(scopeState, compte)
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

	// SOUS UN DOSSIER PERSONNEL, LE SCAN NE SUIT PLUS AUCUN LIEN — TO-DO 163.
	//
	// Voir scanSousHome : chaque fichier est constaté par descripteur, à partir
	// du `HOME` du compte. Les deux boucles ne se mélangent pas — la portée
	// machine garde ses chemins, où des liens sont légitimes.
	if scope == ScopeUser {
		report.Checked += len(chemins)
		report.Items = append(report.Items, scanSousHome(scopeState, chemins, username)...)
		return report
	}

	for _, path := range chemins {
		attendu := scopeState.Files[path]
		report.Checked++

		// Les entrées d'ABSENCE se lisent à l'envers : la dérive n'est pas la
		// disparition, c'est la réapparition. Traitées avant tout le reste, car
		// aucun des contrôles qui suivent — hachage, mode — n'a de sens sur un
		// fichier qui ne doit pas exister.
		if attendu.Absent {
			// Lstat et non Stat : un lien symbolique EXISTE, même s'il pointe
			// vers rien. Avec Stat, un lien cassé posé à l'emplacement d'un
			// fichier que la politique retire passait pour « toujours absent ».
			if _, err := os.Lstat(path); err == nil {
				report.Items = append(report.Items, DriftItem{
					Path: path, StateKey: attendu.StateKey, Coproprietaires: attendu.Owners, Kind: DriftReappeared,
					Detail: "fichier recree alors que la politique le retire",
				})
			}
			// Une erreur autre que « n'existe pas » — un répertoire parent
			// devenu illisible, par exemple — n'est PAS signalée. On ne peut
			// alors rien affirmer, et déclarer une dérive sur une incertitude
			// ferait réappliquer un module sans motif.
			continue
		}

		// Portée MACHINE : des fichiers gérés par une politique sont légitimement
		// des liens — /etc/resolv.conf vers systemd-resolved — et `os.Stat` les
		// suit à dessein. La portée utilisateur ne passe plus par ici.
		info, err := os.Stat(path)
		if os.IsNotExist(err) {
			report.Items = append(report.Items, DriftItem{
				Path: path, StateKey: attendu.StateKey, Coproprietaires: attendu.Owners, Kind: DriftMissing,
				Detail: "fichier supprime",
			})
			continue
		}
		if err != nil {
			report.Items = append(report.Items, DriftItem{
				Path: path, StateKey: attendu.StateKey, Coproprietaires: attendu.Owners, Kind: DriftUnreadable,
				Detail: sanitizeDetail(err.Error()),
			})
			continue
		}

		actuel, lisible := HashFile(path)
		if !lisible {
			report.Items = append(report.Items, DriftItem{
				Path: path, StateKey: attendu.StateKey, Coproprietaires: attendu.Owners, Kind: DriftUnreadable,
				Detail: "contenu illisible",
			})
			continue
		}

		if actuel != attendu.SHA256 {
			report.Items = append(report.Items, DriftItem{
				Path: path, StateKey: attendu.StateKey, Coproprietaires: attendu.Owners, Kind: DriftModified,
				Detail: "contenu modifie",
			})
			continue
		}

		// Le contenu est bon mais le mode a changé : c'est une dérive à part
		// entière. Un fichier de configuration passé en lecture pour tous peut
		// exposer ce qu'il contient sans qu'une seule ligne n'ait bougé.
		if attendu.Mode != 0 && uint32(info.Mode().Perm()) != attendu.Mode {
			report.Items = append(report.Items, DriftItem{
				Path: path, StateKey: attendu.StateKey, Coproprietaires: attendu.Owners, Kind: DriftPermissions,
				Detail: fmt.Sprintf("mode %04o attendu %04o", info.Mode().Perm(), attendu.Mode),
			})
		}
	}

	return report
}

// partitionByMode répartit les modules dérivés selon leur mode.
//
// Séparé d'EnforceDrift pour être testable : EnforceDrift lit et écrit
// /var/lib/vaultaire, que seul root peut toucher. Un test qui exigerait ce droit
// ne serait jamais lancé, et c'est précisément la décision qu'il faut vérifier.
func partitionByMode(scopeState *ScopeState, modules []string) (corriges, audites []string) {
	for _, key := range modules {
		if scopeState.ModuleMode(key) == DriftAudit {
			audites = append(audites, key)
			continue
		}
		corriges = append(corriges, key)
	}
	return corriges, audites
}

// EnforceDrift applique la politique de correction, module par module.
//
// Le mode est lu dans l'état local, pour chaque module concerné : ceux en
// enforce perdent leur empreinte et seront réappliqués au cycle suivant, ceux en
// audit sont signalés et laissés en place. Retourne le nombre de modules marqués
// pour réapplication.
//
// # Pourquoi le tri se fait ici et pas dans le scan
//
// Le scan ne modifie rien : c'est une lecture, et il doit rester utilisable pour
// répondre à « qu'est-ce qui a bougé sur cette machine ? » sans effet de bord.
// Le rapport 05_15 part donc COMPLET vers le core, écarts en audit compris — un
// écart non corrigé reste un écart à afficher, et le masquer ferait de l'audit
// un mode qui ne sert à rien.
func EnforceDrift(scope, username string, report DriftReport) int {
	if report.Conforming() {
		return 0
	}

	for _, item := range report.Items {
		logs.Write_log("WARNING", fmt.Sprintf(
			"GPO: derive detectee sur %s (%s) — %s", item.Path, item.Kind, item.Detail))
	}

	modules := report.ModulesConcerned()
	if len(modules) == 0 {
		if report.seulementDesIncertitudes() {
			// Rien n'a été CONSTATÉ : une commande manque, un délai est passé.
			// On ne rejoue pas un module sur une incertitude, et on ne parle
			// pas de « réapplication impossible » — il n'y a rien à réappliquer.
			logs.Write_log("INFO",
				"GPO: etat non verifiable sur cette machine, aucun module rejoue")
			return 0
		}
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

	corriges, audites := partitionByMode(scopeState, modules)

	if len(audites) > 0 {
		logs.Write_log("INFO", fmt.Sprintf(
			"GPO: mode audit, %d module(s) en ecart signale(s) sans correction : %v",
			len(audites), audites))
	}

	// Aucun module à corriger : rien n'est écrit.
	//
	// Effacer l'empreinte de politique ici ferait retélécharger et recomparer la
	// politique entière à chaque cycle sur une machine en audit durablement
	// dérivée — un cycle de travail par heure et par machine, pour aboutir à
	// « rien à faire » à tous les coups.
	if len(corriges) == 0 {
		return 0
	}

	for _, key := range corriges {
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
		len(corriges), corriges))
	return len(corriges)
}

// scanSousHome constate les fichiers d'une portée UTILISATEUR — TO-DO 163.
//
// # Ce que la boucle commune faisait
//
// `os.Lstat` sur le chemin, pour refuser le lien posé À LA PLACE du fichier
// (TO-DO 97), puis `os.Stat` et une lecture pour le hacher. Les trois résolvent
// les RÉPERTOIRES qui mènent au fichier : avec `ln -s /etc ~/.config`, root
// hachait `/etc/app.conf` et le comparait à ce que la politique avait déposé
// dans `~/.config/app.conf`. L'empreinte ne sortait pas de la machine ; le
// verdict, lui, était faux, et c'est root qui lisait.
//
// # Ce qu'elle fait
//
// Chaque fichier est constaté par constaterSousHome : descente depuis le
// `HOME`, un composant après l'autre, sans suivre un seul lien, et hachage par
// le descripteur du fichier. Un chemin qui n'est plus celui que la politique a
// emprunté EST un écart, et le dit.
//
// # Ce qui change pour qui lit le rapport
//
// Un fichier déposé par une politique est un fichier ORDINAIRE du compte. Un
// fichier devenu la propriété d'un autre, ou remplacé par autre chose qu'un
// fichier, n'était pas signalé tant que son contenu se lisait pareil. Il l'est.
func scanSousHome(scopeState *ScopeState, chemins []string, username string) []DriftItem {
	var items []DriftItem
	signaler := func(path string, attendu FileState, genre DriftKind, detail string) {
		items = append(items, DriftItem{
			Path: path, StateKey: attendu.StateKey, Coproprietaires: attendu.Owners,
			Kind: genre, Detail: detail,
		})
	}

	home, errHome := resolveHomeDir(username)
	uid, _, errUID := resolveUserIDs(username)
	if username == "" || errHome != nil || errUID != nil {
		// Le compte n'existe plus sur cette machine, ou son dossier ne se
		// résout pas : on ne sait pas où regarder. « Invérifiable », et non
		// « illisible » : le second est un constat sur le fichier — ses droits
		// ont pu changer — et fait rejouer le module. Ici on n'a rien constaté.
		for _, path := range chemins {
			signaler(path, scopeState.Files[path], DriftUnverifiable,
				"compte ou dossier personnel introuvable, fichier non verifie")
		}
		return items
	}

	for _, path := range chemins {
		attendu := scopeState.Files[path]
		constat, err := constaterSousHome(home, path, uid)

		// Les entrées d'ABSENCE se lisent à l'envers : la dérive, c'est la
		// réapparition. Un lien compte — il EXISTE, même s'il ne mène nulle part.
		if attendu.Absent {
			// Un chemin suspect ne permet de rien affirmer : on ne signale pas
			// une réapparition sur une incertitude.
			if err == nil && constat.Existe {
				signaler(path, attendu, DriftReappeared, "fichier recree alors que la politique le retire")
			}
			continue
		}

		switch {
		case errors.Is(err, ErrCheminSuspect):
			// Un répertoire du chemin est un lien, ou n'appartient plus au
			// compte. Ce n'est pas « illisible » : c'est un constat, et le
			// module rejoué le dira à son tour en refusant d'écrire.
			signaler(path, attendu, DriftModified,
				"un repertoire du chemin est un lien symbolique ou n'appartient plus au compte")
		case err != nil:
			signaler(path, attendu, DriftUnreadable, sanitizeDetail(err.Error()))
		case !constat.Existe:
			signaler(path, attendu, DriftMissing, "fichier supprime")
		case constat.Lien:
			signaler(path, attendu, DriftModified, "remplace par un lien symbolique")
		case !constat.Ordinaire:
			signaler(path, attendu, DriftModified, "remplace par autre chose qu'un fichier")
		case constat.Uid != uid:
			signaler(path, attendu, DriftModified,
				fmt.Sprintf("appartient a l'uid %d et non plus au compte", constat.Uid))
		case constat.TropGros || constat.SHA256 != attendu.SHA256:
			signaler(path, attendu, DriftModified, "contenu modifie")
		case attendu.Mode != 0 && constat.Mode != attendu.Mode:
			// Le contenu est bon mais le mode a changé : une dérive à part
			// entière. Un fichier passé en lecture pour tous peut exposer ce
			// qu'il contient sans qu'une seule ligne n'ait bougé.
			signaler(path, attendu, DriftPermissions,
				fmt.Sprintf("mode %04o attendu %04o", constat.Mode, attendu.Mode))
		}
	}
	return items
}
