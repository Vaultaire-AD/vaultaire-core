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
// par PAM, et PAM est sollicité bien plus souvent qu'on ne l'imagine : chaque
// `ssh`, mais aussi chaque `sudo`. Scanner à chaque passage aurait fait, sur un
// poste d'administration, un hachage de tout l'inventaire et une trame `05_15`
// par commande privilégiée.
//
// La borne rend au scope utilisateur la garantie de la machine — une
// vérification par cadence — sans la payer à chaque authentification.
//
// La cadence en vigueur est celle que le core annonce (`gpo_refresh_minutes`) :
// un administrateur qui resserre le rafraîchissement du parc pendant un
// déploiement resserre aussi les vérifications, ce qui est ce qu'il demande.
func intervalleScanUtilisateur() time.Duration { return CadenceActuelle() }

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
	// Deux connexions simultanées du même utilisateur — un `ssh` et un `sudo`,
	// ou deux terminaux — lançaient deux cycles en parallèle sur le même `HOME`
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
func scanUserDrift(sessionKey, username string) {
	if username == "" {
		return
	}
	if !scanDuADeja(username, time.Now()) {
		logs.Write_log("DEBUG", "GPO: conformite de "+username+" verifiee recemment, scan ignore")
		return
	}

	report := ScanScope(ScopeUser, username)
	if report.Checked == 0 {
		// Aucun inventaire : rien n'a encore été appliqué à ce compte, ou son
		// état vient d'une version antérieure. Se taire plutôt qu'envoyer un
		// rapport vide, qui ferait croire à une vérification réelle — et qui,
		// pour un utilisateur de passage sans GPO, partirait à chaque connexion.
		return
	}

	if report.Conforming() {
		logs.Write_log("DEBUG", fmt.Sprintf(
			"GPO: conformite de %s verifiee, %d element(s) intact(s)", username, report.Checked))
	}

	if err := SendDriftReport(sessionKey, report); err != nil {
		// Un rapport perdu n'empêche pas la correction : elle est locale.
		logs.Write_log("WARNING", "GPO: rapport de conformite utilisateur non transmis : "+err.Error())
	}

	EnforceDrift(ScopeUser, username, report)
}
