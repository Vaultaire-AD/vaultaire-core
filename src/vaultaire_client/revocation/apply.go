package revocation

import (
	"fmt"
	"os/exec"
	"os/user"
	"sort"
	"strings"

	"duckynetworkclient/V1/duckynetwork/logs"
	localusermanagement "vaultaire_client/tools/local_user_management"
)

// Modes acceptés. Doivent rester alignés sur core/revocation côté serveur —
// les deux modules Go sont séparés, il n'y a pas de type partagé possible.
const (
	ModeSoft   = "soft"
	ModeUnlock = "unlock"
	ModeHard   = "hard"
)

// Résultats renvoyés au serveur dans une trame 06_02.
const (
	ResultApplied       = "applied"
	ResultAlreadyAbsent = "already_absent"
	ResultNotApplicable = "not_applicable"
)

// Apply exécute un ordre sur le ou les comptes locaux qu'il désigne, et rend le
// résultat.
//
// # Qui l'ordre désigne — TO-DO 133
//
// Le compte local d'une personne s'appelle `nom@domaine` : c'est le module PAM
// qui le crée, sous le nom qu'elle a tapé pour se connecter. L'annuaire, lui,
// ne connaît que `nom`, et c'est ce nom-là qu'un exploitant tape dans l'urgence
// — `vlt kill -u bob.durand`, la forme de toute la documentation.
//
// L'ordre arrivait donc avec `bob.durand`, l'agent cherchait un compte local de
// ce nom exact, n'en trouvait pas, journalisait « ordre sans objet » et
// ACQUITTAIT. Rien n'était verrouillé, sur aucune machine, et le core rangeait
// l'ordre comme traité. Seule la forme complète, tapée à la main, atteignait le
// compte — et encore, sur les seules machines jointes à l'instant : le rejeu
// d'un ordre en attente (06_05) relit le nom en base, où il est court.
//
// Un nom SANS domaine désigne donc désormais tous les comptes locaux de cette
// personne — `nom@<n'importe quel domaine>` — parmi ceux que CET agent a
// provisionnés. Un nom AVEC domaine désigne ce compte-là, comme avant.
//
// Jamais un compte que l'agent n'a pas créé : un compte Unix local qui porterait
// le même nom qu'une personne de l'annuaire n'est pas le sien.
func Apply(mode, username string) (string, error) {
	username = strings.TrimSpace(username)
	if username == "" {
		return "", fmt.Errorf("utilisateur cible manquant")
	}
	if mode != ModeSoft && mode != ModeUnlock && mode != ModeHard {
		return "", fmt.Errorf("mode inconnu %q", mode)
	}

	comptes := comptesVises(username)

	// Aucun compte : rien à faire, et c'est un SUCCÈS. Un ordre part vers
	// toutes les machines partageant un groupe avec l'utilisateur, or il ne
	// s'est pas forcément connecté à chacune. Signaler un échec provoquerait un
	// rejeu sans fin sur des machines qui n'ont rien à nettoyer.
	if len(comptes) == 0 {
		logs.Write_log("INFO", fmt.Sprintf(
			"revocation: aucun compte local de %s sur cette machine, ordre sans objet", username))
		return ResultAlreadyAbsent, nil
	}

	// Chaque compte est traité, même si l'un d'eux échoue : s'arrêter au
	// premier échec laisserait les suivants ouverts pour une raison qui ne les
	// concerne pas. L'ordre n'est acquitté que si TOUS ont abouti — sinon le
	// serveur doit le voir, et rejouer.
	var echecs []string
	for _, compte := range comptes {
		if err := appliquerAuCompte(mode, compte); err != nil {
			echecs = append(echecs, compte+" : "+err.Error())
		}
	}
	if len(echecs) > 0 {
		return "", fmt.Errorf("%s", strings.Join(echecs, " ; "))
	}
	return ResultApplied, nil
}

// comptesVises rend les comptes locaux qu'un nom d'ordre désigne.
func comptesVises(username string) []string {
	if strings.Contains(username, "@") {
		if _, err := user.Lookup(username); err != nil {
			return nil
		}
		return []string{username}
	}

	provisionnes, err := comptesDuDomaine()
	if err != nil {
		// On ne sait pas quels comptes sont les nôtres. Ne rien toucher, et le
		// dire fort : l'ordre sera acquitté « sans objet » alors qu'il en avait
		// peut-être un.
		logs.Write_log("ERROR", fmt.Sprintf(
			"revocation: comptes du domaine illisibles (%v) — les comptes locaux de %s "+
				"ne peuvent pas être retrouvés sur cette machine", err, username))
		return nil
	}
	return comptesDeLaPersonne(username, provisionnes)
}

// comptesDeLaPersonne retient, parmi les comptes provisionnés, ceux d'une
// personne désignée par son nom d'annuaire.
//
// `bob.durand` désigne `bob.durand@acme.lan` et `bob.durand@filiale.lan`. Il ne
// désigne PAS `bob.durandal@acme.lan` : la comparaison s'arrête à l'arobase, pas
// au préfixe — c'est ce qui sépare couper la bonne personne de couper son
// homonyme partiel.
func comptesDeLaPersonne(username string, provisionnes []string) []string {
	var comptes []string
	for _, nom := range provisionnes {
		if nom == username || strings.HasPrefix(nom, username+"@") {
			comptes = append(comptes, nom)
		}
	}
	sort.Strings(comptes)
	return comptes
}

// comptesDuDomaine est remplaçable par les tests, qui ne peuvent pas écrire
// /etc/vaultaire/uid.map.
var comptesDuDomaine = localusermanagement.ComptesDuDomaine

// appliquerAuCompte exécute un mode sur UN compte local, qui existe.
func appliquerAuCompte(mode, username string) error {
	compte, err := user.Lookup(username)
	if err != nil {
		// Disparu entre le recensement et maintenant : il n'y a plus rien à faire.
		return nil
	}

	// JAMAIS root — TO-DO 133.
	//
	// Le core refuse de viser un compte protégé, et le module PAM ne crée pas
	// de compte de ce nom. Mais l'ordre vient du réseau, et ce qui suit est
	// `usermod -L`, `pkill -KILL` ou `userdel -r` : sur l'uid 0, aucun des trois
	// ne se rattrape, et le poste ne redevient administrable que par sa console.
	// Un contrôle qui ne sert jamais coûte une ligne ; son absence, une machine.
	//
	// Le déverrouillage reste permis : il ne retire rien.
	if strings.TrimSpace(compte.Uid) == "0" && mode != ModeUnlock {
		logs.Write_log("CRITICAL", fmt.Sprintf(
			"revocation: ordre %s REFUSÉ sur %s — c'est le compte root de cette machine", mode, username))
		return fmt.Errorf("refus d'appliquer %s au compte root local", mode)
	}

	switch mode {
	case ModeSoft:
		_, err = lockAccount(username)
	case ModeUnlock:
		_, err = unlockAccount(username)
	case ModeHard:
		_, err = deleteAccount(username)
	}
	return err
}

// lockAccount verrouille un compte local sans rien détruire, PUIS coupe ce
// qu'il a d'ouvert.
//
// DEUX verrous, et il en faut deux :
//
//   - `usermod -L` préfixe le hash d'un « ! » dans /etc/shadow : plus aucune
//     authentification par mot de passe. Mais cela ne bloque PAS une connexion
//     par clé SSH, ni les sessions déjà ouvertes.
//   - `chage -E 1` fixe la date d'expiration du compte au 2 janvier 1970 :
//     le compte est expiré, ce que la pile PAM (pam_unix, account) refuse
//     quelle que soit la méthode d'authentification, clé SSH comprise.
//
// Le premier seul laisserait entrer par clé. Le second seul suffirait presque,
// mais un administrateur qui lit /etc/shadow doit voir que le compte est
// verrouillé, pas seulement expiré.
//
// # Et les sessions DÉJÀ ouvertes — TO-DO 133
//
// Les deux verrous sont deux écritures dans /etc/shadow. Elles empêchent
// d'ENTRER ; elles ne font sortir personne. Une fois `sshd` fourché et le shell
// lancé, plus rien ne relit /etc/shadow : la session vivait jusqu'au `exit`, ou
// indéfiniment sous `tmux`. Le kill switch d'un compte compromis laissait donc
// la personne exactement où elle était, pendant que l'aide de la commande
// affirmait le contraire.
//
// L'ordre compte : on verrouille D'ABORD. Couper avant laisserait une fenêtre
// où la personne, éjectée, se reconnecte avant que le compte ne soit fermé.
func lockAccount(username string) (string, error) {
	if err := executer("usermod", "-L", username); err != nil {
		return "", fmt.Errorf("verrouillage du mot de passe : %w", err)
	}
	if err := executer("chage", "-E", "1", username); err != nil {
		// Le premier verrou tient déjà : on remonte l'échec pour que le serveur
		// le voie et rejoue, mais l'accès par mot de passe est déjà coupé.
		return "", fmt.Errorf("expiration du compte : %w", err)
	}

	logs.Write_log("WARNING", "revocation: compte local "+username+" verrouillé (mot de passe invalidé, compte expiré)")

	if err := terminerLeCompte(username); err != nil {
		// Le compte EST verrouillé : plus personne n'entre. Mais l'ordre n'a pas
		// tenu sa promesse, et le serveur doit le savoir — il rejouera, et
		// l'exploitant voit une machine en échec plutôt qu'un succès qui ment.
		return "", fmt.Errorf("compte verrouillé, sessions non coupées : %w", err)
	}
	return ResultApplied, nil
}

// unlockAccount lève le verrouillage posé par lockAccount.
//
// `chage -E -1` retire la date d'expiration, `usermod -U` retire le « ! ».
// L'ordre inverse de la pose, sans importance technique ici, mais qui rend la
// symétrie lisible.
func unlockAccount(username string) (string, error) {
	if err := executer("chage", "-E", "-1", username); err != nil {
		return "", fmt.Errorf("levée de l'expiration : %w", err)
	}
	if err := executer("usermod", "-U", username); err != nil {
		return "", fmt.Errorf("déverrouillage du mot de passe : %w", err)
	}

	logs.Write_log("INFO", "revocation: compte local "+username+" déverrouillé")
	return ResultApplied, nil
}

// deleteAccount supprime le compte et son répertoire personnel.
//
// `userdel -r` détruit le home. C'est le choix retenu pour le mode hard, et il
// est irréversible : sur un compte compromis, cela détruit aussi les traces de
// la compromission.
//
// Les processus de l'utilisateur sont tués d'abord : userdel refuse de
// supprimer un compte dont une session est encore ouverte, et sur une
// révocation d'urgence la personne est précisément en train de travailler.
// C'est le même geste que celui du mode soft (terminerLeCompte) — il n'y a
// qu'une façon de couper un compte, et elle est éprouvée une fois.
func deleteAccount(username string) (string, error) {
	if err := terminerLeCompte(username); err != nil {
		// On tente la suppression quand même : `userdel` dira lui-même s'il
		// reste de quoi l'empêcher, et son message est plus précis que le nôtre.
		logs.Write_log("WARNING", "revocation: "+err.Error()+" — suppression tentée malgré tout")
	}

	if err := executer("userdel", "-r", username); err != nil {
		return "", fmt.Errorf("suppression du compte : %w", err)
	}

	logs.Write_log("WARNING", "revocation: compte local "+username+" supprimé, répertoire personnel détruit")
	return ResultApplied, nil
}

// executer lance une commande système. Variable, pour que les tests observent
// l'enchaînement des commandes sans verrouiller un vrai compte.
var executer = run

// run exécute une commande système et joint sa sortie à l'erreur.
//
// Sans la sortie, un échec de userdel se résume à « exit status 8 » dans le
// rapport remonté au serveur — inexploitable pour comprendre pourquoi une
// machine n'a pas pu couper un compte.
func run(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		detail := strings.TrimSpace(string(output))
		if detail == "" {
			return err
		}
		return fmt.Errorf("%w : %s", err, detail)
	}
	return nil
}
