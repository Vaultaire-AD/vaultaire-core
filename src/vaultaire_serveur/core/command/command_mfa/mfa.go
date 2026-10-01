// Package commandmfa expose en ligne de commande le second facteur et la
// politique de mot de passe.
//
//	vlt mfa -u <user>                   état du second facteur d'un compte
//	vlt mfa -u <user> --reset           efface le secret (write:mfa)
//	vlt mfa -g <groupe> --require       impose le second facteur au groupe (write:mfa)
//	vlt mfa -g <groupe> --optional      le rend facultatif (write:mfa)
//	vlt mfa policy                      lit la politique d'expiration
//	vlt mfa policy --max-age N --warn N --min-length N   l'écrit (groupe vaultaire)
//
// CE QUI N'EST PAS ICI, ET POURQUOI. L'enrôlement n'a pas de commande. Il
// suppose d'afficher un secret puis d'en valider un code : dans un terminal, le
// secret finirait dans l'historique du shell et dans les journaux de session,
// c'est-à-dire dans deux endroits qu'un second facteur existe pour rendre
// inutiles. L'enrôlement reste sur /profil/mfa, où il n'est ni journalisé ni
// rejouable.
//
// Ce paquet ne décide de rien : il traduit des arguments et appelle exactement
// les mêmes fonctions que l'interface web. Un durcissement posé dans la couche
// base couvre donc les deux d'un coup.
package commandmfa

import (
	"fmt"
	"strconv"
	"strings"

	"vaultaire/core/action"
	commandaction "vaultaire/core/command/commandaction"
	"vaultaire/core/database"
	dbauthpolicy "vaultaire/core/database/db_authpolicy"
	isprotected "vaultaire/core/database/is_protected"
	"vaultaire/core/logs"
)

// MFA_Command traite `vlt mfa ...`.
func MFA_Command(commandList []string, senderGroupIDs []int, senderUsername string) string {
	if len(commandList) == 0 {
		return helpText()
	}

	switch commandList[0] {
	case "-h", "help", "--help":
		return helpText()
	case "policy":
		return handlePolicy(commandList[1:], senderGroupIDs, senderUsername)
	case "ducky":
		return handleDucky(commandList[1:], senderGroupIDs, senderUsername)
	case "-u":
		return handleUser(commandList[1:], senderGroupIDs, senderUsername)
	case "-g":
		return handleGroup(commandList[1:], senderGroupIDs, senderUsername)
	default:
		return "Requête invalide. Essayez 'mfa -h'."
	}
}

// handleUser lit ou réinitialise le second facteur d'un compte.
func handleUser(args []string, senderGroupIDs []int, senderUsername string) string {
	if len(args) == 0 || strings.TrimSpace(args[0]) == "" {
		return "Compte cible requis. Usage : mfa -u <username> [--reset]"
	}
	target := strings.TrimSpace(args[0])
	reset := false
	for _, a := range args[1:] {
		if strings.ToLower(a) == "--reset" {
			reset = true
		}
	}

	db := database.GetDatabase()
	state, err := dbauthpolicy.GetAuthState(db, target)
	if err != nil {
		return fmt.Sprintf("Lecture du compte %s impossible : %v", target, err)
	}
	required, _ := dbauthpolicy.IsMFARequired(db, target)

	if !reset {
		// La LECTURE ne demande pas write:mfa : elle ne révèle ni le secret ni
		// un code, seulement l'état d'un drapeau. Exiger le droit d'écriture
		// pour consulter empêcherait un exploitant d'astreinte de diagnostiquer
		// « pourquoi ce compte ne peut pas se connecter ».
		return fmt.Sprintf("Compte %s\n  Second facteur : %s\n  Imposé par un groupe : %s",
			target, activeLabel(state.MFAEnabled && state.MFASecret != ""), yesNo(required))
	}

	// Le contrôle du droit (write:mfa sur les domaines des groupes de la cible)
	// et la réinitialisation vivent dans l'action user.reset_mfa, partagée avec
	// l'interface web.
	res := commandaction.ExecuterAction("user.reset_mfa",
		action.Params{"username": target}, senderGroupIDs, senderUsername)

	// La précision « son groupe l'impose » est ajoutée ici parce qu'elle dépend
	// d'un état déjà lu plus haut pour l'affichage. L'action ne la porte pas :
	// elle n'a pas à relire la base pour un détail de formulation.
	if required {
		res += " Son groupe l'impose."
	}
	return res
}

// handleGroup pose ou retire l'exigence de second facteur sur un groupe.
func handleGroup(args []string, senderGroupIDs []int, senderUsername string) string {
	if len(args) == 0 || strings.TrimSpace(args[0]) == "" {
		return "Groupe cible requis. Usage : mfa -g <groupe> --require|--optional"
	}
	target := strings.TrimSpace(args[0])

	var required bool
	seen := false
	for _, a := range args[1:] {
		switch strings.ToLower(a) {
		case "--require":
			required, seen = true, true
		case "--optional":
			required, seen = false, true
		}
	}
	if !seen {
		return "Précisez --require ou --optional. L'omission ne peut pas être interprétée : elle vaudrait retrait silencieux d'une protection."
	}

	// Le contrôle (write:mfa sur les domaines du groupe) et l'écriture vivent
	// dans l'action group.set_mfa_required.
	valeur := "non"
	if required {
		valeur = "oui"
	}
	return commandaction.ExecuterAction("group.set_mfa_required",
		action.Params{"group": target, "mfa_required": valeur}, senderGroupIDs, senderUsername)
}

// handlePolicy lit ou écrit la politique globale d'expiration des mots de passe.
func handlePolicy(args []string, senderGroupIDs []int, senderUsername string) string {
	db := database.GetDatabase()

	if len(args) == 0 {
		p := dbauthpolicy.GetPasswordPolicy(db)
		expiration := fmt.Sprintf("%d jours\n  Préavis    : %d jours", p.MaxAgeDays, p.WarnDays)
		if p.MaxAgeDays <= 0 {
			expiration = "désactivée"
		}
		// La longueur minimale s'affiche TOUJOURS, y compris quand l'expiration
		// est désactivée : elle, ne se désactive pas, et une vue qui s'arrêtait
		// à « expiration désactivée » laissait croire qu'aucune règle ne
		// s'appliquait aux mots de passe.
		return fmt.Sprintf("Politique de mot de passe\n  Expiration : %s\n"+
			"  Longueur minimale d'un mot de passe neuf : %d caractères (plancher %d)",
			expiration, p.MinLength, dbauthpolicy.MinLengthPlancher)
	}

	// La politique n'appartient à aucun domaine : elle engage tout l'annuaire.
	// Aucune clé RBAC ne s'y applique proprement, comme pour les restrictions
	// GPO et les certificats — d'où la réserve au groupe superadmin, qui est la
	// règle déjà appliquée par la page web.
	if !isprotected.IsSuperadmin(db, senderUsername) {
		logs.Write_Log("SECURITY", fmt.Sprintf(
			"%s tente de modifier la politique de mot de passe sans appartenir au groupe %s",
			senderUsername, isprotected.ProtectedGroupName))
		return "Permission refusée : réservé aux membres du groupe " + isprotected.ProtectedGroupName + "."
	}

	current := dbauthpolicy.GetPasswordPolicy(db)
	next := current
	for i := 0; i < len(args); i++ {
		switch strings.ToLower(args[i]) {
		case "--max-age", "--warn", "--min-length":
			if i+1 >= len(args) {
				return "Option " + args[i] + " : valeur manquante."
			}
			value, err := strconv.Atoi(strings.TrimSpace(args[i+1]))
			if err != nil {
				return fmt.Sprintf("Option %s : « %s » n'est pas un nombre.", args[i], args[i+1])
			}
			switch strings.ToLower(args[i]) {
			case "--max-age":
				next.MaxAgeDays = value
			case "--warn":
				next.WarnDays = value
			default:
				next.MinLength = value
			}
			i++
		default:
			return "Option inconnue : " + args[i] + ". Essayez 'mfa -h'."
		}
	}

	// Les bornes et la cohérence préavis/expiration sont vérifiées par
	// SetPasswordPolicy, côté base. Les revalider ici ferait deux règles à
	// maintenir, dont une seule couvrirait l'interface web.
	// Le contrôle (appartenance au groupe protégé) et la validation vivent dans
	// l'action authpolicy.set_password_policy.
	return commandaction.ExecuterAction("authpolicy.set_password_policy",
		action.Params{
			"max_age_days": strconv.Itoa(next.MaxAgeDays),
			"warn_days":    strconv.Itoa(next.WarnDays),
			"min_length":   strconv.Itoa(next.MinLength),
		}, senderGroupIDs, senderUsername)
}

// handleDucky lit ou règle l'exigence de second facteur sur le chemin Ducky.
//
// Verbe séparé de « policy », qui porte l'expiration et la robustesse : celui-ci
// n'est pas une politique de mot de passe, c'est un interrupteur de migration.
// Les mêler aurait fait d'une commande de réglage courant une commande qui peut
// couper l'accès au parc.
func handleDucky(args []string, senderGroupIDs []int, senderUsername string) string {
	if len(args) == 0 {
		return commandaction.ExecuterAction("mfa.get_ducky_policy",
			action.Params{}, senderGroupIDs, senderUsername)
	}
	valeur := strings.ToLower(strings.TrimSpace(args[0]))
	if valeur != "on" && valeur != "off" {
		return "Usage : mfa ducky [on|off]"
	}
	// Le contrôle des droits et le garde-fou (aucun compte enrôlé) vivent dans
	// l'action : les recopier ici ferait deux règles à tenir, dont une seule
	// couvrirait l'interface web.
	return commandaction.ExecuterAction("mfa.set_ducky_policy",
		action.Params{"required": valeur}, senderGroupIDs, senderUsername)
}

func activeLabel(on bool) string {
	if on {
		return "actif"
	}
	return "inactif"
}

func yesNo(v bool) string {
	if v {
		return "oui"
	}
	return "non"
}

func helpText() string {
	return `Second facteur et politique de mot de passe.

  mfa -u <user>                          état du second facteur d'un compte
  mfa -u <user> --reset                  efface son secret            (write:mfa)
  mfa -g <groupe> --require              impose le second facteur     (write:mfa)
  mfa -g <groupe> --optional             le rend facultatif           (write:mfa)
  mfa policy                             lit la politique de mot de passe
  mfa policy --max-age <j> --warn <j>    règle l'expiration       (groupe vaultaire)
  mfa policy --min-length <n>            règle la longueur minimale (groupe vaultaire)
  mfa ducky                              dit si un code est exigé à l'ouverture de session
  mfa ducky <on|off>                     l'exige, ou non            (write:server)

L'exigence porte sur le GROUPE, jamais sur un compte : un nouvel arrivant y est
soumis du seul fait de son entrée, sans liste à tenir à jour.

L'enrôlement n'a pas de commande, volontairement : afficher un secret dans un
terminal le déposerait dans l'historique du shell. Il se fait sur /profil/mfa.

« mfa ducky on » exige qu'un agent envoie un code À CHAQUE ouverture de session,
« 0000 » pour un compte qui n'a pas de second facteur. Une machine dont l'agent
est trop ancien pour l'envoyer ne pourra plus ouvrir de session : mettez le parc
à jour AVANT d'activer. « mfa ducky off » retire l'exigence en une commande.

Les comptes qui ONT un second facteur doivent le fournir dans tous les cas, que
cette exigence soit active ou non. LDAP n'est pas concerné : le protocole n'a pas
de place pour un second facteur, et le code s'y accole au mot de passe.

  --max-age 0      désactive l'expiration des mots de passe.
  --min-length     ne se désactive PAS : la valeur est bornée au plancher.
                   La longueur ne s'applique qu'aux mots de passe NEUFS — on ne
                   peut pas recalculer ce qu'on refuserait d'un mot de passe
                   déjà en base, il n'existe nulle part.`
}
