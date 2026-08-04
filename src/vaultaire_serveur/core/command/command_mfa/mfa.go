// Package commandmfa expose en ligne de commande le second facteur et la
// politique de mot de passe.
//
//	vlt mfa -u <user>                   état du second facteur d'un compte
//	vlt mfa -u <user> --reset           efface le secret (write:mfa)
//	vlt mfa -g <groupe> --require       impose le second facteur au groupe (write:mfa)
//	vlt mfa -g <groupe> --optional      le rend facultatif (write:mfa)
//	vlt mfa policy                      lit la politique d'expiration
//	vlt mfa policy --max-age N --warn N l'écrit (groupe vaultaire uniquement)
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

	"vaultaire/core/database"
	dbauthpolicy "vaultaire/core/database/db_authpolicy"
	isprotected "vaultaire/core/database/is_protected"
	"vaultaire/core/logs"
	"vaultaire/core/permission"
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
		return handlePolicy(commandList[1:], senderUsername)
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

	if msg := requireMFARightOnUser(senderGroupIDs, senderUsername, target); msg != "" {
		return msg
	}
	if err := dbauthpolicy.ResetMFA(db, target, senderUsername); err != nil {
		return fmt.Sprintf("Réinitialisation impossible : %v", err)
	}
	logs.Write_Log("SECURITY", fmt.Sprintf("%s a réinitialisé le second facteur de %s", senderUsername, target))
	if required {
		return fmt.Sprintf("Second facteur de %s réinitialisé. Son groupe l'impose : il devra le réenrôler à sa prochaine connexion.", target)
	}
	return fmt.Sprintf("Second facteur de %s réinitialisé. Le compte se connectera avec son seul mot de passe jusqu'à un nouvel enrôlement.", target)
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

	// Le droit est exigé sur TOUS les domaines du groupe. Imposer ou lever le
	// second facteur d'un groupe entier pèse plus lourd que d'y ajouter un
	// membre : c'est la même famille de décision que la réinitialisation, d'où
	// write:mfa et non write:update:group.
	domains, err := permission.GetDomainsFromGroupName(target)
	if err != nil {
		return fmt.Sprintf("Domaines du groupe %s illisibles : %v", target, err)
	}
	ok, reason := permission.CheckPermissionsAllDomains(senderGroupIDs, permission.ActionManageMFA, domains)
	if !ok {
		logs.Write_Log("SECURITY", fmt.Sprintf(
			"%s tente de modifier l'exigence de second facteur du groupe %s (domaines : %v) — %s",
			senderUsername, target, domains, reason))
		return "Permission refusée : " + reason
	}

	if err := dbauthpolicy.SetGroupMFARequired(database.GetDatabase(), target, required, senderUsername); err != nil {
		return fmt.Sprintf("Modification impossible : %v", err)
	}
	if required {
		return fmt.Sprintf("Second facteur imposé au groupe %s. Les membres déjà connectés ne sont pas déconnectés : ils enrôleront à leur prochaine connexion.", target)
	}
	return fmt.Sprintf("Second facteur redevenu facultatif pour le groupe %s.", target)
}

// handlePolicy lit ou écrit la politique globale d'expiration des mots de passe.
func handlePolicy(args []string, senderUsername string) string {
	db := database.GetDatabase()

	if len(args) == 0 {
		p := dbauthpolicy.GetPasswordPolicy(db)
		if p.MaxAgeDays <= 0 {
			return "Politique de mot de passe : expiration désactivée."
		}
		return fmt.Sprintf("Politique de mot de passe\n  Expiration : %d jours\n  Préavis    : %d jours",
			p.MaxAgeDays, p.WarnDays)
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
		case "--max-age", "--warn":
			if i+1 >= len(args) {
				return "Option " + args[i] + " : valeur manquante."
			}
			value, err := strconv.Atoi(strings.TrimSpace(args[i+1]))
			if err != nil {
				return fmt.Sprintf("Option %s : « %s » n'est pas un nombre de jours.", args[i], args[i+1])
			}
			if strings.ToLower(args[i]) == "--max-age" {
				next.MaxAgeDays = value
			} else {
				next.WarnDays = value
			}
			i++
		default:
			return "Option inconnue : " + args[i] + ". Essayez 'mfa -h'."
		}
	}

	// Les bornes et la cohérence préavis/expiration sont vérifiées par
	// SetPasswordPolicy, côté base. Les revalider ici ferait deux règles à
	// maintenir, dont une seule couvrirait l'interface web.
	if err := dbauthpolicy.SetPasswordPolicy(db, next, senderUsername); err != nil {
		return fmt.Sprintf("Enregistrement impossible : %v", err)
	}
	if next.MaxAgeDays <= 0 {
		return "Expiration des mots de passe désactivée."
	}
	return fmt.Sprintf("Politique enregistrée : expiration à %d jours, préavis %d jours.", next.MaxAgeDays, next.WarnDays)
}

// requireMFARightOnUser vérifie write:mfa sur tous les domaines du compte visé.
//
// Sur TOUS et non sur au moins un : un compte présent dans plusieurs domaines
// n'est administrable que par qui les administre tous. Sans cela, un délégué
// d'un seul domaine pourrait retirer le second facteur d'un compte qui a des
// droits ailleurs.
func requireMFARightOnUser(senderGroupIDs []int, senderUsername, target string) string {
	targetGroupIDs, err := permission.GetGroupIDsFromUsername(target)
	if err != nil {
		return fmt.Sprintf("Groupes de %s illisibles : %v", target, err)
	}
	if len(targetGroupIDs) == 0 {
		return fmt.Sprintf("Utilisateur %s introuvable ou sans groupe.", target)
	}
	domains, err := permission.GetDomainListsFromGroupIDs(targetGroupIDs)
	if err != nil {
		return fmt.Sprintf("Domaines de %s illisibles : %v", target, err)
	}
	ok, reason := permission.CheckPermissionsAllDomains(senderGroupIDs, permission.ActionManageMFA, domains)
	if !ok {
		logs.Write_Log("SECURITY", fmt.Sprintf(
			"%s tente de réinitialiser le second facteur de %s (domaines : %v) — %s",
			senderUsername, target, domains, reason))
		return "Permission refusée : " + reason
	}
	return ""
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
  mfa policy                             lit la politique d'expiration
  mfa policy --max-age <j> --warn <j>    l'écrit          (groupe vaultaire)

L'exigence porte sur le GROUPE, jamais sur un compte : un nouvel arrivant y est
soumis du seul fait de son entrée, sans liste à tenir à jour.

L'enrôlement n'a pas de commande, volontairement : afficher un secret dans un
terminal le déposerait dans l'historique du shell. Il se fait sur /profil/mfa.

  --max-age 0    désactive l'expiration des mots de passe.`
}
