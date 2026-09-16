package gpo

import (
	"fmt"
	"sort"
	"strings"
	"sync"
)

// Vérification des effets NON-fichier.
//
// # Le trou que cela ferme
//
// Le scan de conformité ne comparait que des FICHIERS. Or les appliqueurs font
// 55 appels de commandes : systemctl, nft, chage, usermod, gpasswd, setsebool,
// sysctl. Un service réactivé, une table nftables vidée, un compte remis dans
// sudo — tout cela était invisible, et la machine restait déclarée conforme.
//
// Le déséquilibre était complet : le fichier qui décrit l'état voulu était
// surveillé, l'état lui-même ne l'était pas. Un `sshd_config.d/99-vaultaire.conf`
// intact au hachage près ne dit rien si sshd a été arrêté.
//
// # Pourquoi une DÉCLARATION et pas une inspection générale
//
// On ne devine pas l'état d'un service depuis un fichier. Chaque module sait ce
// qu'il a fait, et lui seul : c'est donc lui qui déclare ce qu'il faudra
// revérifier, au moment où il l'applique.
//
// Le mécanisme est le jumeau exact de celui des fichiers — recordWrite note une
// écriture, recordCheck note une attente — et il s'attribue de la même façon,
// par différence avant/après l'appel de l'appliqueur. Aucun appliqueur n'a à
// tenir de liste, et un module écrit demain sans recordCheck n'est simplement
// pas vérifié : silence, pas fausse conformité.
//
// # Ce que la vérification N'EST PAS
//
// Un test d'intention. Elle constate un état observable, rien de plus. Une
// vérification approximative est PIRE qu'aucune : elle déclare conforme ce qui
// ne l'est pas, et personne ne va plus regarder. C'est pourquoi les vérificateurs
// sont écrits un par un, en commençant par les modules qui portent un privilège,
// plutôt que tous d'un coup.

// SystemCheck est une attente d'état système, déclarée par un appliqueur.
//
// Les trois champs sont des chaînes, et c'est délibéré : la structure est
// sérialisée dans applied_policies.json, relue par une version qui n'est pas
// forcément celle qui l'a écrite, et un type riche s'y prêterait mal.
type SystemCheck struct {
	// Kind désigne le vérificateur à employer.
	Kind string `json:"kind"`
	// Target est ce qui est vérifié : une unité systemd, un couple
	// utilisateur/groupe, une étiquette de règle nftables.
	Target string `json:"target"`
	// Expect est l'état attendu, interprété par le vérificateur.
	Expect string `json:"expect"`
	// StateKey du module qui l'a déclarée, pour savoir quoi réappliquer.
	StateKey string `json:"state_key,omitempty"`
}

// CheckID identifie une attente de façon stable.
//
// Kind ET Target : un même module peut surveiller plusieurs unités, et deux
// modules différents peuvent surveiller la même sous des angles différents —
// « activé au démarrage » et « en cours d'exécution » ne sont pas la même
// question.
func (c SystemCheck) CheckID() string { return c.Kind + "|" + c.Target }

// Checker constate un état système.
//
// Rend « conforme » et un détail COURT, destiné à un administrateur : il part
// tel quel dans le rapport 05_15, comme celui des écarts de fichiers.
//
// Une erreur signifie « je n'ai pas pu savoir » — commande absente, délai
// dépassé — et NON « l'état est mauvais ». La distinction est celle de
// DriftUnreadable pour les fichiers : sur une incertitude, on ne réapplique
// rien, on le dit.
type Checker func(c SystemCheck) (conforme bool, detail string, err error)

// checkers associe un type de vérification à son vérificateur.
//
// POINT D'EXTENSION, jumeau de `appliers` — un module devient vérifiable en
// deux gestes : appeler recordCheck dans son appliqueur, et enregistrer ici le
// vérificateur correspondant.
var checkers = map[string]Checker{}

// registerChecker enregistre un vérificateur.
//
// Panique sur un doublon. C'est une faute de programmation, découverte au
// démarrage : l'alternative — la dernière déclaration l'emporte — ferait
// silencieusement vérifier autre chose que ce que l'auteur croit.
func registerChecker(kind string, c Checker) {
	if _, déjà := checkers[kind]; déjà {
		panic("gpo: vérificateur " + kind + " déclaré deux fois")
	}
	checkers[kind] = c
}

// CheckerFor rend le vérificateur d'un type d'attente.
func CheckerFor(kind string) (Checker, bool) {
	c, ok := checkers[kind]
	return c, ok
}

// VerifiableKinds rend les types d'attente que cet agent sait vérifier.
func VerifiableKinds() []string {
	out := make([]string, 0, len(checkers))
	for k := range checkers {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// --- inventaire des attentes, jumeau de celui des fichiers -------------------

var (
	checkMu sync.Mutex
	// checkManifest accumule les attentes déclarées par l'application EN COURS.
	checkManifest = map[string]SystemCheck{}
)

// ResetCheckManifest vide l'inventaire des attentes.
//
// Appelé par ResetManifest : les deux inventaires ont exactement le même cycle
// de vie, et les séparer laisserait l'un survivre à l'autre — donc des attentes
// attribuées au module d'un cycle antérieur.
func ResetCheckManifest() {
	checkMu.Lock()
	defer checkMu.Unlock()
	checkManifest = map[string]SystemCheck{}
}

// recordCheck déclare un état à revérifier.
//
// Appelé DEPUIS l'appliqueur, une fois l'action réussie. L'appeler avant
// noterait une attente que l'action n'a pas obtenue, et le scan signalerait une
// dérive permanente sur un état jamais atteint.
func recordCheck(kind, target, expect string) {
	c := SystemCheck{Kind: kind, Target: target, Expect: expect}
	checkMu.Lock()
	defer checkMu.Unlock()
	checkManifest[c.CheckID()] = c
}

// checkSnapshot relève les attentes présentes, pour comparaison ultérieure.
//
// Copie les attentes et pas seulement les clés, comme manifestSnapshot : deux
// modules peuvent surveiller la même cible avec des attentes différentes, et
// comparer les seules clés attribuerait la seconde au premier module.
func checkSnapshot() map[string]SystemCheck {
	checkMu.Lock()
	defer checkMu.Unlock()
	vue := make(map[string]SystemCheck, len(checkManifest))
	for id, c := range checkManifest {
		vue[id] = c
	}
	return vue
}

// checksSince rend les attentes apparues OU MODIFIÉES depuis un relevé.
func checksSince(avant map[string]SystemCheck, stateKey string) map[string]SystemCheck {
	checkMu.Lock()
	defer checkMu.Unlock()

	nouvelles := map[string]SystemCheck{}
	for id, c := range checkManifest {
		if ancienne, existait := avant[id]; existait && ancienne.Expect == c.Expect {
			continue
		}
		c.StateKey = stateKey
		nouvelles[id] = c
	}
	return nouvelles
}

// --- le scan ----------------------------------------------------------------

// scanChecks constate les attentes d'un état et rend les écarts.
//
// Séparé de scanFromState pour la même raison que celui-ci est séparé de
// LoadState : les vérificateurs lancent des commandes, et un test doit pouvoir
// éprouver la logique de parcours sans en lancer aucune.
func scanChecks(scopeState *ScopeState) []DriftItem {
	if scopeState == nil || len(scopeState.Checks) == 0 {
		return nil
	}

	ids := make([]string, 0, len(scopeState.Checks))
	for id := range scopeState.Checks {
		ids = append(ids, id)
	}
	// Trié, comme les chemins : un rapport dont l'ordre change à chaque
	// exécution est illisible en comparaison.
	sort.Strings(ids)

	var items []DriftItem
	for _, id := range ids {
		attendu := scopeState.Checks[id]

		checker, ok := CheckerFor(attendu.Kind)
		if !ok {
			// Attente écrite par une version PLUS RÉCENTE de l'agent, ou
			// vérificateur retiré. Silence plutôt qu'écart : on ne sait pas
			// constater, donc on ne constate rien. Signaler une dérive
			// ferait réappliquer un module sans le moindre motif.
			continue
		}

		conforme, detail, err := checker(attendu)
		switch {
		case err != nil:
			items = append(items, DriftItem{
				Path: attendu.Target, StateKey: attendu.StateKey,
				Kind:   DriftUnverifiable,
				Detail: sanitizeDetail(err.Error()),
			})
		case !conforme:
			items = append(items, DriftItem{
				Path: attendu.Target, StateKey: attendu.StateKey,
				Kind:   DriftSystemState,
				Detail: sanitizeDetail(detail),
			})
		}
	}
	return items
}

// --- utilitaires partagés par les vérificateurs -----------------------------

// attenduEt constate rend un détail lisible pour un écart d'état.
//
// Une seule formulation pour tous les vérificateurs : un rapport où chacun
// rédige à sa façon devient impossible à parcourir dès qu'il dépasse l'écran.
func ecartConstate(quoi, attendu, constate string) string {
	return fmt.Sprintf("%s : %s attendu, %s constate", quoi, attendu, constate)
}

// champsAttendus découpe un Expect de la forme « a=1,b=2 ».
//
// Rend une carte vide plutôt qu'une erreur sur une entrée malformée : un Expect
// illisible vient d'un état écrit par une autre version, et le vérificateur qui
// le reçoit doit le traiter comme « rien à vérifier », pas comme un écart.
func champsAttendus(expect string) map[string]string {
	out := map[string]string{}
	for _, part := range strings.Split(expect, ",") {
		cle, valeur, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok {
			continue
		}
		out[strings.TrimSpace(cle)] = strings.TrimSpace(valeur)
	}
	return out
}
