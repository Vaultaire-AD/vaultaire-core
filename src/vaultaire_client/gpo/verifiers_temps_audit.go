package gpo

import (
	"fmt"
	"sort"
	"strings"
)

// Vérificateurs du temps et de l'audit.
//
// Troisième lot du point 4, après les cinq modules dont la dérive donne un
// DROIT et les quatre dont elle coûte de la COHÉRENCE.
//
// Ces deux-là sont d'une troisième nature : leur dérive coûte la CAPACITÉ À
// SAVOIR. Une horloge qui suit d'autres serveurs que ceux de la politique rend
// tous les horodatages du parc incomparables entre eux ; une règle d'audit qui
// n'est plus chargée ne produit plus la trace qu'on ira chercher après coup.
//
// Rien n'est plus permissif pour autant. C'est ce qui les distingue du premier
// lot, et pourquoi ils viennent après.
//
// # Deux candidats de la TO-DO ne sont PAS ici, et ne le seront pas ainsi
//
// `system_env` et `resource_limits` étaient sur la liste. Voir plus bas :
// aucune attente n'est déclarée pour eux, et la cause est écrite.

const (
	// CheckNTPServers : Target est vide, Expect la liste attendue.
	CheckNTPServers = "ntp_servers"
	// CheckAuditRule : Target est l'étiquette de la règle, Expect « present »
	// ou « absent ».
	CheckAuditRule = "audit_rule"
)

func init() {
	registerChecker(CheckNTPServers, verifierServeursNTP)
	registerChecker(CheckAuditRule, verifierRegleAudit)
}

// --- serveurs de temps ------------------------------------------------------

// verifierServeursNTP constate les serveurs que timesyncd a RÉELLEMENT chargés.
//
// # Ce que cela ajoute au scan des fichiers
//
// Le fichier `/etc/systemd/timesyncd.conf.d/99-vaultaire-gpo.conf` est déjà
// surveillé. Il décrit ce que timesyncd devrait lire — pas ce qu'il a lu.
//
// Trois écarts lui échappent : un second fichier de configuration, chargé après
// celui de la GPO et qui l'emporte ; un `timedatectl set-ntp` local ; et le cas
// le plus courant, un service qui n'a jamais été redémarré depuis l'écriture du
// fichier. Dans les trois cas la machine suit d'autres serveurs que ceux de la
// politique, et le fichier est intact au caractère près.
//
// # Ce que ce vérificateur NE constate PAS
//
// Que l'horloge est effectivement synchronisée. `NTPSynchronized` répond à une
// autre question — le réseau, la joignabilité des serveurs — et une horloge
// désynchronisée n'est pas une dérive de CONFIGURATION : réappliquer le module
// n'y changerait rien, et l'écart se rappellerait à chaque scan sans que
// personne puisse le lever.
//
// # Une machine sans timesyncd n'est pas en dérive
//
// L'appliqueur le dit déjà : « systemd-timesyncd non redemarre », la machine
// utilise peut-être chrony ou ntpd. On ne sait alors rien constater, et c'est
// « inverifiable » — pas un écart.
func verifierServeursNTP(c SystemCheck) (bool, string, error) {
	if !commandExists("timedatectl") {
		return false, "", fmt.Errorf("timedatectl absent de cette machine")
	}

	sortie, err := runCommand("timedatectl", "show-timesync", "-p", "SystemNTPServers", "--value")
	if err != nil {
		// timesyncd absent, masqué, ou trop ancien pour « show-timesync ». Dans
		// les trois cas on ne sait pas ce qui est chargé.
		return false, "", fmt.Errorf("serveurs de temps illisibles : %v", err)
	}

	constates := serveursNTP(sortie)
	attendus := serveursNTP(c.Expect)

	if len(attendus) == 0 {
		// Attente vide : rien à comparer. Vient d'un état écrit par une autre
		// version ; la traiter comme « aucun serveur attendu » ferait signaler
		// une dérive sur toute machine correctement configurée.
		return true, "", nil
	}
	if len(constates) == 0 {
		return false, "aucun serveur de temps charge — la politique en demande " +
			strings.Join(attendus, ", "), nil
	}
	if egalesIgnorantLOrdre(attendus, constates) {
		return true, "", nil
	}
	return false, ecartConstate("serveurs de temps",
		strings.Join(attendus, ","), strings.Join(constates, ",")), nil
}

// serveursNTP découpe une liste de serveurs.
//
// Les deux bouts n'écrivent pas pareil : la politique sépare par des virgules,
// `normalizeList` en fait des espaces avant écriture, et timedatectl rend des
// espaces. Accepter les deux séparateurs évite un vérificateur qui ne marcherait
// que sur l'un des deux formats — et qui signalerait une dérive permanente sur
// l'autre.
func serveursNTP(brut string) []string {
	champs := strings.FieldsFunc(brut, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t' || r == '\n'
	})
	var out []string
	for _, s := range champs {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// egalesIgnorantLOrdre compare deux listes sans tenir compte de leur ordre.
//
// # Pourquoi l'ordre ne compte pas
//
// timesyncd interroge les serveurs dans l'ordre, mais bascule d'un serveur à
// l'autre selon leur disponibilité et peut réordonner ce qu'il rend. Exiger
// l'ordre exact ferait signaler une dérive sur une machine dont la
// configuration n'a pas bougé d'un caractère — et une dérive qu'aucune
// réapplication ne corrige.
//
// Le NOMBRE compte : un serveur en trop est une dérive, même si tous ceux de la
// politique sont présents. C'est un serveur de temps que personne n'a demandé.
func egalesIgnorantLOrdre(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	triA := append([]string(nil), a...)
	triB := append([]string(nil), b...)
	sort.Strings(triA)
	sort.Strings(triB)
	for i := range triA {
		if triA[i] != triB[i] {
			return false
		}
	}
	return true
}

// --- règles d'audit ---------------------------------------------------------

// verifierRegleAudit constate qu'une règle est CHARGÉE dans le noyau.
//
// # Ce que cela ajoute au scan des fichiers
//
// `/etc/audit/rules.d/99-vaultaire-<clé>.rules` est déjà surveillé. Il décrit
// une règle qui sera chargée au prochain démarrage d'auditd — pas une règle en
// vigueur.
//
// Un `auditctl -D` vide toutes les règles du noyau sans toucher à un seul
// fichier. C'est une commande d'une ligne, elle ne laisse aucune trace, et à
// partir de là la machine n'enregistre plus rien alors que le scan la déclare
// conforme. C'est précisément le point aveugle que ce vérificateur ferme.
//
// # La règle est retrouvée par son ÉTIQUETTE
//
// Comme la règle nftables l'est par son commentaire, et pour la même raison :
// `auditctl -l` NORMALISE ce qu'il rend. Une règle écrite « -w /etc/passwd -p wa
// -k vaultaire » peut ressortir avec ses champs dans un autre ordre, un chemin
// résolu, ou des permissions réécrites. Comparer la ligne entière ferait
// signaler une dérive sur une règle parfaitement chargée.
//
// L'étiquette, elle, est ce que l'appliqueur a choisi et ce qu'auditd conserve
// tel quel — c'est le seul lien stable entre un module de GPO et sa règle.
func verifierRegleAudit(c SystemCheck) (bool, string, error) {
	if !commandExists("auditctl") {
		// auditd n'est pas installé, ou l'on est dans un conteneur sans la
		// capacité AUDIT_CONTROL. La règle est écrite et prendra effet le jour
		// où auditd sera là — l'appliqueur le dit déjà.
		return false, "", fmt.Errorf("auditctl absent de cette machine")
	}

	sortie, err := runCommand("auditctl", "-l")
	if err != nil {
		return false, "", fmt.Errorf("regles d'audit illisibles : %v", err)
	}

	presente := regleAuditPresente(sortie, c.Target)
	veutPresente := strings.TrimSpace(c.Expect) != "absent"

	if presente == veutPresente {
		return true, "", nil
	}
	if veutPresente {
		return false, "regle d'audit " + c.Target + " absente du noyau — " +
			"le fichier est en place mais la regle n'est pas chargee", nil
	}
	return false, "regle d'audit " + c.Target + " toujours chargee alors que la " +
		"politique la retire (effective jusqu'au prochain rechargement)", nil
}

// regleAuditPresente cherche une étiquette dans la sortie d'auditctl.
//
// « No rules » est la réponse d'un noyau sans aucune règle. Le traiter comme une
// sortie ordinaire fonctionnerait — aucune ligne ne porterait l'étiquette — mais
// le nommer rend le cas lisible : c'est celui d'un `auditctl -D`, et c'est le
// plus grave.
func regleAuditPresente(sortie, etiquette string) bool {
	etiquette = strings.TrimSpace(etiquette)
	if etiquette == "" {
		return false
	}
	for _, ligne := range strings.Split(sortie, "\n") {
		ligne = strings.TrimSpace(ligne)
		if ligne == "" || strings.EqualFold(ligne, "No rules") {
			continue
		}
		if etiquetteDeRegle(ligne) == etiquette {
			return true
		}
	}
	return false
}

// etiquetteDeRegle extrait la valeur de « -k » d'une ligne d'auditctl.
//
// Par POSITION relative à « -k » et non par recherche de sous-chaîne : une
// étiquette « vaultaire » se retrouverait dans un chemin surveillé
// « /opt/vaultaire/… », et le vérificateur conclurait à une règle chargée en
// lisant la règle d'un autre.
func etiquetteDeRegle(ligne string) string {
	champs := strings.Fields(ligne)
	for i, champ := range champs {
		if champ == "-k" && i+1 < len(champs) {
			return champs[i+1]
		}
		// auditctl rend aussi la forme collée « -k=cle », et « -F key=cle »
		// pour les règles de syscall.
		if valeur, ok := strings.CutPrefix(champ, "-k="); ok {
			return valeur
		}
		if valeur, ok := strings.CutPrefix(champ, "key="); ok {
			return valeur
		}
	}
	return ""
}

// --- ce que ce lot refuse de vérifier ---------------------------------------

// # `system_env` : une variable ne s'observe pas depuis l'agent
//
// Le candidat était sur la liste, et il paraissait facile : lire la variable et
// la comparer. Il ne l'est pas.
//
// Ce que la politique fixe, c'est ce qu'un SHELL DE CONNEXION recevra. L'agent
// est un service ; son propre environnement est celui de systemd au démarrage
// de la machine, pas celui d'une session. Lire `os.Getenv` constaterait quelque
// chose de vrai et de sans rapport.
//
// Lancer un shell de connexion pour observer ne marche pas non plus : il
// faudrait le lancer POUR CHAQUE UTILISATEUR, puisque `~/.profile` et les
// fichiers de `/etc/profile.d/` peuvent redéfinir la variable différemment selon
// le compte. Et le lancer coûterait à chaque scan ce qu'une ouverture de session
// coûte.
//
// Le fichier `/etc/environment` reste surveillé par le scan des fichiers. Ce qui
// n'est pas couvert — une variable masquée ailleurs — reste non couvert, et
// c'est écrit plutôt que comblé par une observation qui ne répondrait pas à la
// question posée.
//
// # `resource_limits` : la valeur dépend de la session
//
// L'appliqueur le dit lui-même dans son propre message : « nouvelles sessions ».
// PAM lit `/etc/security/limits.d/` à l'OUVERTURE d'une session ; une session
// déjà ouverte garde les siennes.
//
// Constater les limites du processus de l'agent reviendrait à constater celles
// de la session sous laquelle il a été lancé — au démarrage de la machine, avant
// que la politique ne soit appliquée pour certaines. Ce n'est pas une
// approximation, c'est une autre mesure.
//
// Ces deux-là rejoignent `boot_params` et `kernel_module_policy` dans les refus
// assumés. Un test lit la source et vérifie qu'aucune attente n'y est déclarée :
// c'est une décision, pas un oubli, et elle doit résister à quelqu'un qui la
// croirait manquante.
