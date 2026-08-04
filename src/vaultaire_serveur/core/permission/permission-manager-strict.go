package permission

import (
	"fmt"
	"strings"

	"vaultaire/core/database"
	dbpermission "vaultaire/core/database/db_permission"
	"vaultaire/core/logs"
)

// Contrôle strict sur tous les domaines d'une entité.
//
// Pourquoi une seconde fonction plutôt qu'un correctif de
// CheckPermissionsMultipleDomains : les deux sémantiques sont légitimes, mais
// pas pour les mêmes usages.
//
//   - En LECTURE, « au moins un domaine autorisé » a du sens : on montre à
//     l'appelant la partie qu'il a le droit de voir. C'est le comportement
//     historique, conservé.
//
//   - En ÉCRITURE, il est faux. Une entité peut appartenir à plusieurs
//     domaines : un utilisateur membre de groupes dans compta.example.fr et
//     admin.example.fr appartient aux deux. Avec la règle « au moins un », un
//     administrateur délégué de compta pouvait supprimer ce compte, ou lui
//     ajouter une clé SSH — donc agir sur un compte qui détient des droits dans
//     admin, un domaine sur lequel il n'a rien. L'ajout de clé était le pire
//     cas : la clé posée permettait ensuite de s'authentifier à l'API en tant
//     que ce compte.
//
// La règle appliquée ici est celle voulue : on n'agit sur une entité que si on
// a le droit sur CHACUN de ses domaines. La propagation reste gérée par la même
// logique que la lecture — un droit propagé sur example.fr couvre bien
// compta.example.fr.

// CheckPermissionsAllDomains vérifie qu'une action est autorisée sur TOUS les
// domaines fournis.
//
// Retourne le premier domaine refusé dans le message, pas un résumé de tous :
// devant un refus, ce qu'on veut savoir c'est quel droit il manque.
func CheckPermissionsAllDomains(groupIDs []int, action string, domainsToCheck []string) (bool, string) {
	normalizedAction, ok := IsValidAction(action)
	if !ok {
		logs.Write_LogCode("WARNING", logs.CodeAuthPermission,
			fmt.Sprintf("Action '%s' non valide", action))
		return false, fmt.Sprintf("Action '%s' non valide", action)
	}

	// Aucun domaine connu pour l'entité : on ne peut pas vérifier ce sur quoi on
	// agit. Seul un droit global passe. C'est la même règle que la lecture, et
	// elle est fermée : dans le doute on refuse.
	if len(domainsToCheck) == 0 {
		for _, groupID := range groupIDs {
			content, err := dbpermission.GetPermissionContent(database.GetDatabase(), groupID, normalizedAction)
			if err != nil {
				logs.Write_LogCode("ERROR", logs.CodeDBQuery,
					fmt.Sprintf("Erreur récupération permission pour le groupe %d: %v", groupID, err))
				continue
			}
			if ParsePermissionContent(content).All {
				return true, fmt.Sprintf("Permission globale via groupe %d", groupID)
			}
		}
		logs.Write_LogCode("WARNING", logs.CodeAuthLoginDenied,
			fmt.Sprintf("Action '%s' refusée (aucun domaine identifié et pas de droit global)", normalizedAction))
		return false, "Refusée : aucun domaine identifié pour l'entité et aucun droit global"
	}

	for _, domain := range domainsToCheck {
		if !isDomainAllowed(groupIDs, normalizedAction, domain) {
			logs.Write_LogCode("WARNING", logs.CodeAuthLoginDenied, fmt.Sprintf(
				"Action '%s' refusée : droit manquant sur le domaine '%s' (groupes %v). "+
					"L'entité visée couvre %v, le droit est exigé sur chacun.",
				normalizedAction, domain, groupIDs, domainsToCheck))
			return false, fmt.Sprintf(
				"droit manquant sur le domaine %s (l'entité visée couvre %s, le droit est exigé sur chacun)",
				domain, strings.Join(domainsToCheck, ", "))
		}
	}

	logs.Write_LogCode("DEBUG", logs.CodeNone, fmt.Sprintf(
		"Action '%s' autorisée sur tous les domaines %v", normalizedAction, domainsToCheck))
	return true, fmt.Sprintf("autorisée sur %s", strings.Join(domainsToCheck, ", "))
}

// HasActionAnywhere dit si une action est accordée quelque part : globalement
// ou sur au moins un domaine.
//
// Sert de porte d'entrée aux pages web. Auparavant l'interface exigeait le droit
// global (« * ») pour la moindre action, si bien qu'un administrateur délégué
// sur un domaine pouvait tout faire en ligne de commande et rien dans
// l'interface. Cette fonction répond à « as-tu quelque chose à faire ici ? »,
// pas à « as-tu le droit sur cette entité ? » — cette seconde question reste
// posée entité par entité, par CheckPermissionsAllDomains.
func HasActionAnywhere(groupIDs []int, action string) bool {
	normalizedAction, ok := IsValidAction(action)
	if !ok {
		return false
	}
	for _, groupID := range groupIDs {
		content, err := dbpermission.GetPermissionContent(database.GetDatabase(), groupID, normalizedAction)
		if err != nil {
			logs.Write_LogCode("ERROR", logs.CodeDBQuery,
				fmt.Sprintf("Erreur récupération permission pour le groupe %d: %v", groupID, err))
			continue
		}
		parsed := ParsePermissionContent(content)
		if parsed.Deny {
			continue
		}
		if parsed.All || len(parsed.NoPropagation) > 0 || len(parsed.WithPropagation) > 0 {
			return true
		}
	}
	return false
}

// AllowedDomains décrit sur quels domaines une action est accordée.
//
// Sert au filtrage des LISTES de l'interface web. Répondre « oui » ou « non »
// ne suffit pas là : il faut savoir CE QUE l'appelant a le droit de voir, pour
// ne lui montrer que cela.
type AllowedDomains struct {
	// Global vaut vrai si l'action est accordée partout. Les autres champs sont
	// alors sans objet.
	Global bool
	// Exact liste les domaines accordés sans propagation.
	Exact []string
	// Propagated liste les domaines accordés avec propagation : eux et leurs
	// sous-domaines.
	Propagated []string
}

// Allows dit si un domaine précis entre dans le périmètre.
//
// Un domaine vide n'est jamais autorisé, sauf droit global : une entité dont on
// ignore le domaine ne doit pas apparaître dans une liste filtrée, sinon le
// filtre laisserait passer précisément ce qu'on n'a pas su classer.
func (a AllowedDomains) Allows(domain string) bool {
	if a.Global {
		return true
	}
	domain = strings.TrimSpace(domain)
	if domain == "" {
		return false
	}
	for _, d := range a.Exact {
		if domain == d {
			return true
		}
	}
	for _, d := range a.Propagated {
		if domain == d || strings.HasSuffix(domain, "."+d) {
			return true
		}
	}
	return false
}

// IsEmpty dit si aucun domaine n'est accordé.
func (a AllowedDomains) IsEmpty() bool {
	return !a.Global && len(a.Exact) == 0 && len(a.Propagated) == 0
}

// DomainsWhereAllowed retourne le périmètre d'une action pour un jeu de groupes.
//
// POURQUOI CETTE FONCTION EXISTE. Les pages d'administration vérifiaient
// autrefois le droit GLOBAL avant d'afficher quoi que ce soit ; la question du
// périmètre ne se posait donc pas, puisque seul un administrateur global entrait.
// Depuis que l'ouverture d'une page ne demande plus que le droit sur au moins
// un domaine, la question se pose : sans filtrage, un délégué d'un domaine
// voyait l'annuaire entier.
//
// Un refus explicite (nil) sur un groupe n'annule pas ce qu'un autre groupe
// accorde — même règle que l'évaluation d'accès, pour que voir et pouvoir
// restent cohérents.
func DomainsWhereAllowed(groupIDs []int, action string) AllowedDomains {
	var out AllowedDomains

	normalizedAction, ok := IsValidAction(action)
	if !ok {
		return out
	}

	seenExact := map[string]bool{}
	seenProp := map[string]bool{}

	for _, groupID := range groupIDs {
		content, err := dbpermission.GetPermissionContent(database.GetDatabase(), groupID, normalizedAction)
		if err != nil {
			logs.Write_LogCode("ERROR", logs.CodeDBQuery,
				fmt.Sprintf("Erreur récupération permission pour le groupe %d: %v", groupID, err))
			continue
		}
		parsed := ParsePermissionContent(content)
		if parsed.Deny {
			continue
		}
		if parsed.All {
			out.Global = true
			return out
		}
		for _, d := range parsed.NoPropagation {
			if d != "" && !seenExact[d] {
				seenExact[d] = true
				out.Exact = append(out.Exact, d)
			}
		}
		for _, d := range parsed.WithPropagation {
			if d != "" && !seenProp[d] {
				seenProp[d] = true
				out.Propagated = append(out.Propagated, d)
			}
		}
	}
	return out
}

// isDomainAllowed évalue un domaine unique pour un jeu de groupes.
//
// Reprend exactement la règle utilisée en lecture : un refus explicite (nil)
// n'interrompt pas la boucle — un autre groupe peut accorder le droit —,
// « all » couvre tout, les domaines sans propagation exigent l'égalité, ceux
// avec propagation acceptent les sous-domaines.
func isDomainAllowed(groupIDs []int, action, domain string) bool {
	for _, groupID := range groupIDs {
		content, err := dbpermission.GetPermissionContent(database.GetDatabase(), groupID, action)
		if err != nil {
			logs.Write_LogCode("ERROR", logs.CodeDBQuery,
				fmt.Sprintf("Erreur récupération permission pour le groupe %d: %v", groupID, err))
			continue
		}

		parsed := ParsePermissionContent(content)
		if parsed.Deny {
			continue
		}
		if parsed.All {
			return true
		}
		for _, d := range parsed.NoPropagation {
			if domain == d {
				return true
			}
		}
		for _, d := range parsed.WithPropagation {
			if domain == d || strings.HasSuffix(domain, "."+d) {
				return true
			}
		}
	}
	return false
}
