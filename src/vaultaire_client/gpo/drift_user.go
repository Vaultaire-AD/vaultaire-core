package gpo

import (
	"fmt"
	"sync"
	"time"

	"duckynetworkclient/V1/duckynetwork/logs"
)

// Conformité du scope UTILISATEUR — le pendant de scanMachineDrift.
//
// # Le défaut que cela corrige
//
// Le scan de conformité n'existait que pour le scope machine. Les GPO
// utilisateur étaient appliquées à l'ouverture de session, et plus jamais
// vérifiées : un fichier posé dans le `HOME` puis modifié, supprimé ou rendu
// illisible restait dans cet état aussi longtemps que l'empreinte de politique
// ne bougeait pas — c'est-à-dire indéfiniment sur un parc stable.
//
// C'est le scope où la dérive est la PLUS probable. Le `HOME` est le seul
// endroit où l'utilisateur écrit librement sans être root : il n'a pas besoin
// d'un privilège pour défaire ce que la politique a posé, et il n'a pas non
// plus besoin de le vouloir — un `.bashrc` réécrit par un outil tiers suffit.
// La surveillance manquait donc exactement là où elle servait le plus.
//
// # Ce qui n'a PAS eu à être écrit
//
// Rien côté core : `05_15` porte déjà le scope et le nom d'utilisateur, la
// table `gpo_drift` a déjà sa colonne `target_user`, et la contrainte
// d'unicité de `gpo_compliance` porte les trois colonnes. Le rapport
// utilisateur remonte donc par le chemin existant, et s'affiche là où
// s'affiche celui de la machine.
//
// Rien non plus sur le mode enforce/audit : il est un attribut de la GPO,
// hérité par ses modules et mémorisé dans l'état local (point 34). `EnforceDrift`
// le lit module par module, sans savoir de quel scope il s'agit. Une GPO
// utilisateur qu'on préfère ne pas voir corriger dans les `HOME` se met en
// audit comme n'importe quelle autre — l'administrateur a déjà le levier, il
// n'en fallait pas un second, propre au scope, qui aurait dit la même chose
// avec d'autres mots.

// intervalleScanUtilisateur borne la fréquence des scans utilisateur.
//
// # Pourquoi une borne ici et pas côté machine
//
// La boucle machine décide elle-même quand elle tourne : un scan par cadence,
// par construction. Le scope utilisateur n'a pas de boucle — il est déclenché
// par PAM, à chaque AUTHENTIFICATION du compte sur le poste : un `ssh`, une
// ouverture de session sur la console, et — c'est le cas le plus fréquent sur
// un poste de travail — chaque DÉVERROUILLAGE de l'écran sous GDM, qui repasse
// par la même pile. Scanner à chaque passage ferait hacher l'inventaire et
// émettre une trame `05_15` à chaque fois que quelqu'un revient de la machine
// à café.
//
// (Ce commentaire disait « chaque `sudo` ». C'est inexact pour les piles
// qu'installe `rocky.sh` : le module y est posé dans `login`, `sshd` et
// `gdm-password`, pas dans `sudo`. Il n'y a donc pas, sur un poste installé
// normalement, de commande privilégiée à distinguer d'une ouverture de session
// — TO-DO 142.)
//
// # La valeur : un réglage à lui, cinq minutes par défaut — TO-DO 142
//
// La borne était la cadence MACHINE (`gpo_refresh_minutes`, une heure par
// défaut). Elle rendait bien au scope utilisateur « une vérification par
// cadence », mais ce n'est pas ce qu'on attend d'un dossier personnel : qui
// défait sa politique, se déconnecte et revient dix minutes plus tard doit la
// retrouver en place, pas attendre le prochain tour d'horloge du parc.
//
// C'est donc `gpo_user_check_minutes`, annoncé par le core comme l'autre
// (cadence.go). Passé ce délai depuis la dernière vérification, la connexion
// suivante scanne, et le cycle qui suit repose ce qui manque ; en deçà, elle ne
// scanne pas — c'est le « pas avant cinq minutes » demandé à la recette.
func intervalleScanUtilisateur() time.Duration { return CadenceUtilisateur() }

var (
	scansMu sync.Mutex
	// dernierScanUtilisateur retient la dernière vérification par compte.
	//
	// En mémoire, et non dans l'état local : un agent qui redémarre refait un
	// scan de trop, ce qui est le sens sûr de l'erreur. L'écrire sur le disque
	// aurait ajouté un champ à migrer pour économiser une vérification par
	// redémarrage.
	dernierScanUtilisateur = map[string]time.Time{}

	// verrousUtilisateur sérialise les cycles d'un MÊME compte.
	//
	// Deux connexions simultanées du même utilisateur — deux terminaux, ou un
	// `ssh` pendant qu'un écran se déverrouille — lançaient deux cycles en
	// parallèle sur le même `HOME`
	// et le même état local. Tant que le cycle ne faisait qu'appliquer, les
	// modules étant idempotents, cela passait. Le scan introduit une lecture
	// suivie d'une écriture (oublier l'empreinte des modules dérivés) : deux
	// exécutions entrelacées y perdraient l'une des deux corrections.
	//
	// Attendre, et non abandonner comme le fait le cycle machine : la seconde
	// connexion a besoin que son environnement soit en place avant que la main
	// ne soit rendue à PAM. L'abandonner rendrait la main sans garantie que le
	// premier cycle ait fini.
	verrousMu          sync.Mutex
	verrousUtilisateur = map[string]*sync.Mutex{}
)

// verrouDe rend le verrou d'un compte, en le créant au besoin.
func verrouDe(username string) *sync.Mutex {
	verrousMu.Lock()
	defer verrousMu.Unlock()
	verrou, ok := verrousUtilisateur[username]
	if !ok {
		verrou = &sync.Mutex{}
		verrousUtilisateur[username] = verrou
	}
	return verrou
}

// scanDuADeja dit si un scan est dû pour ce compte, et note l'instant.
//
// Le marquage se fait à l'ENTRÉE et non à la sortie : deux connexions
// rapprochées ne doivent pas scanner toutes les deux parce que la première n'a
// pas encore terminé.
func scanDuADeja(username string, maintenant time.Time) bool {
	scansMu.Lock()
	defer scansMu.Unlock()

	dernier, vu := dernierScanUtilisateur[username]
	if vu && maintenant.Sub(dernier) < intervalleScanUtilisateur() {
		return false
	}
	dernierScanUtilisateur[username] = maintenant
	return true
}

// oublierScansUtilisateur efface la mémoire des scans d'un compte.
//
// Appelée quand l'état local d'un utilisateur est retiré : garder son instant
// ferait sauter le premier scan d'un compte recréé sous le même nom, c'est-à-
// dire celui d'un `HOME` neuf dont on ne sait rien.
func oublierScansUtilisateur(username string) {
	scansMu.Lock()
	delete(dernierScanUtilisateur, username)
	scansMu.Unlock()
}

// scanUserDrift vérifie la conformité d'un compte et remonte les écarts.
//
// Rend le nombre de modules marqués pour réapplication : l'appelant s'en sert
// pour savoir s'il doit constater de nouveau APRÈS le cycle.
//
// # Pourquoi AVANT le cycle, et non après
//
// Le scan efface l'empreinte des modules dérivés ; le cycle qui suit les voit
// absents de l'état et les réapplique dans la foulée. L'utilisateur trouve donc
// son environnement remis en état à l'ouverture de session, avant que son shell
// ne démarre.
//
// Scanner APRÈS aurait reporté la correction au cycle suivant — et le cycle
// suivant d'un scope utilisateur n'est pas dans une heure, c'est à la prochaine
// connexion. Quelqu'un qui se connecte une fois par semaine aurait gardé son
// `HOME` dérivé une semaine, en étant signalé comme non conforme tout du long.
//
// # Ce qu'il reste à savoir
//
// Une seconde connexion pendant qu'une première travaille peut faire réécrire
// un fichier que l'utilisateur vient d'éditer. C'est assumé : la politique est
// la source de vérité, et l'agent n'a aucun moyen fiable de savoir qu'une autre
// session est ouverte — compter les ouvertures et les fermetures PAM laisserait
// un compteur faussé par la première session tuée, et désarmerait la correction
// en silence. Un parc où ces interventions sont légitimes met les GPO
// concernées en audit.
func scanUserDrift(sessionKey, username string) int {
	if username == "" {
		return 0
	}
	if !scanDuADeja(username, time.Now()) {
		logs.Write_log("DEBUG", fmt.Sprintf(
			"GPO: conformite de %s verifiee il y a moins de %s, scan ignore",
			username, intervalleScanUtilisateur()))
		return 0
	}

	report := ScanScope(ScopeUser, username)
	if report.Checked == 0 {
		// Aucun inventaire : rien n'a encore été appliqué à ce compte, ou rien
		// de ce qui lui est appliqué ne sait encore être vérifié. Se taire
		// plutôt qu'envoyer un rapport vide, qui ferait croire à une
		// vérification réelle — et qui, pour un utilisateur de passage sans
		// GPO, partirait à chaque connexion. Le core affiche alors « non
		// vérifié », ce qui est la vérité.
		//
		// Ce silence était, avant le point 135, le sort de TOUS les comptes
		// dont la politique ne posait que des fichiers : leur inventaire était
		// vide par construction. Il ne l'est plus.
		return 0
	}

	if report.Conforming() {
		logs.Write_log("DEBUG", fmt.Sprintf(
			"GPO: conformite de %s verifiee, %d element(s) intact(s)", username, report.Checked))
	}

	if err := SendDriftReport(sessionKey, report); err != nil {
		// Un rapport perdu n'empêche pas la correction : elle est locale.
		logs.Write_log("WARNING", "GPO: rapport de conformite utilisateur non transmis : "+err.Error())
	}

	return EnforceDrift(ScopeUser, username, report)
}

// constaterApresApplication scanne un compte dont des modules viennent d'être
// posés, et dit au core ce qu'il en est MAINTENANT.
//
// # Pourquoi le scope utilisateur en a besoin et pas la machine
//
// Côté machine, le tour suivant de la boucle scanne : un écart corrigé reste
// affiché une cadence au plus, et une politique neuve est vérifiée dans
// l'heure. Un compte, lui, n'a pas de tour suivant — son prochain scan est à sa
// prochaine connexion, demain ou jamais. Sans ce constat :
//
//   - un `HOME` réparé à 9 h restait affiché « 1 écart » jusqu'au retour de la
//     personne : le rapport d'écart part avant la correction, c'est voulu
//     (scanMachineDrift), et rien ne venait le remplacer ;
//   - un compte qui venait de recevoir sa politique restait « non vérifié »,
//     puisque le scan précède le cycle et n'avait encore rien à comparer.
//
// Dans les deux cas la vue de conformité montrait autre chose que l'état du
// poste, et une vue qui a tort par construction est une vue qu'on cesse de lire.
//
// Ce constat ne corrige rien et ne compte pas comme une vérification due : il
// ne touche pas à la mémoire des scans, et n'efface aucune empreinte. Un écart
// qui subsiste — module en échec, politique en audit — reste affiché, à juste
// titre, et sera repris à la prochaine vérification.
func constaterApresApplication(sessionKey, username string) {
	report := ScanScope(ScopeUser, username)
	if report.Checked == 0 {
		return
	}
	if !report.Conforming() {
		logs.Write_log("WARNING", fmt.Sprintf(
			"GPO: %d ecart(s) subsiste(nt) pour %s apres application", len(report.Items), username))
	}
	if err := SendDriftReport(sessionKey, report); err != nil {
		logs.Write_log("WARNING", "GPO: constat apres application non transmis : "+err.Error())
	}
}

// rattraperInventaireUtilisateur fait rejouer UNE fois les modules d'un compte
// dont l'état a été écrit avant que le scope utilisateur n'inventorie — TO-DO 135.
//
// Voir ScopeState.Inventaire pour le pourquoi : sans cela, un compte à la
// politique stable n'aurait jamais d'inventaire, et la correction du point 135
// ne se serait appliquée qu'aux politiques modifiées après la mise à jour.
//
// # Ce qui n'est PAS rejoué
//
// Les modules en AUDIT. Rejouer, c'est réécrire, et l'audit est précisément le
// mode où l'on a décidé de ne pas réécrire ce qu'un poste a modifié. Ces
// modules-là entreront dans l'inventaire à leur prochaine modification ; d'ici
// là ils restent « non vérifiés », ce qui est exact.
//
// # Ce que cela coûte
//
// Une réapplication complète du scope utilisateur, à la première connexion de
// chaque compte après la mise à jour de l'agent. Les modules sont idempotents ;
// c'est le coût d'une première connexion.
func rattraperInventaireUtilisateur(username string) {
	state := LoadState()
	scopeState := state.Scope(ScopeUser, username)
	if scopeState == nil || scopeState.Inventaire >= versionInventaire {
		return
	}

	rejoues := scopeState.oublierPourInventaire()
	if rejoues == 0 {
		return
	}

	if err := SaveScopeState(ScopeUser, username, scopeState); err != nil {
		logs.Write_log("ERROR", "GPO: etat non enregistre avant le rattrapage de l'inventaire : "+err.Error())
		return
	}
	logs.Write_log("INFO", fmt.Sprintf(
		"GPO: l'etat de %s date d'avant l'inventaire du scope utilisateur, "+
			"%d module(s) rejoue(s) une fois pour l'y faire entrer", username, rejoues))
}
