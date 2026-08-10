package permission

import (
	"fmt"
	"strings"
	"vaultaire/core/database"
	dbpermission "vaultaire/core/database/db_permission"
	"vaultaire/core/logs"
	"vaultaire/core/storage"
)

// CheckPermissionsMultipleDomains vérifie si un ou plusieurs groupes ont le droit d'effectuer une action
// sur une liste de domaines donnés.
// Retourne :
// - bool : true si au moins un domaine est autorisé
// - string : résumé textuel
//
// # Ce que cette fonction journalise, et à quel niveau
//
//	DEBUG    UNE ligne par domaine accordé, portant le motif décisif —
//	         « all », domaine exact, ou propagation, et depuis quel groupe.
//	         Silencieux par défaut, activable par le réglage debug.
//	WARNING  chaque refus, avec les groupes examinés. Visible par défaut :
//	         c'est ce qu'on cherche dans un journal d'exploitation.
//	ERROR    uniquement un vrai problème système, base indisponible en tête.
//
// Le déroulé pas à pas — une ligne par groupe visité, plus une pour le contenu
// brut de sa permission — a été retiré : il produisait une quinzaine de lignes
// par page d'administration sans jamais dire quelle règle avait tranché.
func CheckPermissionsMultipleDomains(groupIDs []int, action string, domainsToCheck []string) (bool, string) {
	anyAllowed := false
	var sb strings.Builder

	// Vérifier validité de l’action
	action, ok := IsValidAction(action)
	if !ok {
		for _, domain := range domainsToCheck {
			logs.Write_LogCode("WARNING", logs.CodeAuthPermission,
				fmt.Sprintf("Action '%s' non valide pour le domaine '%s'", action, domain))
			sb.WriteString(fmt.Sprintf("Action '%s' non valide sur %s", action, domain))
		}
		return false, sb.String()
	}
	var parsedPermission storage.ParsedPermission

	// Cas spécial : aucun domaine à vérifier => on vérifie seulement le super admin (All)
	if len(domainsToCheck) == 0 {
		for _, groupID := range groupIDs {
			content, err := dbpermission.GetPermissionContent(database.GetDatabase(), groupID, action)
			if err != nil {
				logs.Write_LogCode("ERROR", logs.CodeDBQuery,
					fmt.Sprintf("Erreur récupération permission pour le groupe %d: %v", groupID, err))
				continue
			}

			parsedPermission := ParsePermissionContent(content)
			if parsedPermission.All {
				logs.Write_LogCode("DEBUG", logs.CodeNone, fmt.Sprintf(
					"droit %s (aucun domaine) : accordé (all via le groupe %d)", action, groupID))
				return true, fmt.Sprintf("Permission super admin via groupe %d", groupID)
			}
		}
		logs.Write_LogCode("WARNING", logs.CodeAuthLoginDenied,
			fmt.Sprintf("Action '%s' refusée (aucun domaine et pas de super admin)", action))
		return false, "Refusée : aucun domaine pour l'entité et aucun super admin"
	}

	for _, domain := range domainsToCheck {
		allowed := false
		motif := ""

		for _, groupID := range groupIDs {
			content, err := dbpermission.GetPermissionContent(database.GetDatabase(), groupID, action)
			if err != nil {
				logs.Write_LogCode("ERROR", logs.CodeDBQuery,
					fmt.Sprintf("Erreur récupération permission pour le groupe %d: %v", groupID, err))
				continue
			}

			parsedPermission = ParsePermissionContent(content)

			if parsedPermission.Deny {
				continue
			}

			if parsedPermission.All {
				motif = fmt.Sprintf("all via le groupe %d", groupID)
				sb.WriteString(fmt.Sprintf("%s : autorisée partout (*) via groupe %d", domain, groupID))
				allowed = true
				break
			}

			for _, d := range parsedPermission.NoPropagation {
				if domain == d {
					motif = fmt.Sprintf("domaine exact via le groupe %d", groupID)
					sb.WriteString(fmt.Sprintf("%s : autorisée (sans propagation) via groupe %d", domain, groupID))
					allowed = true
					break
				}
			}
			if allowed {
				break
			}

			for _, d := range parsedPermission.WithPropagation {
				if domain == d || strings.HasSuffix(domain, "."+d) {
					motif = fmt.Sprintf("propagation depuis %s via le groupe %d", d, groupID)
					sb.WriteString(fmt.Sprintf("%s : autorisée (avec propagation depuis %s) via groupe %d", domain, d, groupID))
					allowed = true
					break
				}
			}
			if allowed {
				break
			}
		}

		if !allowed {
			logs.Write_LogCode("WARNING", logs.CodeAuthLoginDenied, fmt.Sprintf(
				"Action '%s' refusée sur le domaine '%s' (aucune règle applicable dans les groupes %v)",
				action, domain, groupIDs,
			))
			sb.WriteString(fmt.Sprintf("%s : refusée", domain))
		} else {
			// UNE ligne, et elle porte le MOTIF DÉCISIF.
			//
			// La version antérieure écrivait deux lignes par groupe et par
			// domaine — « Vérification de la permission pour le groupe ID 4 »
			// puis « Permission brute pour le groupe 4 » — plus une troisième
			// à l'acceptation. Pour un compte de trois groupes, l'ouverture
			// d'une seule page d'administration produisait une quinzaine de
			// lignes, dont aucune ne disait ce qu'on cherche.
			//
			// Ce qu'on cherche en déboguant un droit, c'est QUELLE RÈGLE a
			// tranché : « all », un domaine exact, ou une propagation, et
			// depuis quel groupe. C'est exactement ce que porte cette ligne.
			//
			// Le déroulé pas à pas n'apportait rien de plus : les groupes
			// examinés avant celui qui accorde n'ont, par construction, rien
			// accordé.
			logs.Write_LogCode("DEBUG", logs.CodeNone, fmt.Sprintf(
				"droit %s sur %s : accordé (%s)", action, domain, motif))
			anyAllowed = true
		}
	}

	return anyAllowed, sb.String()
}
