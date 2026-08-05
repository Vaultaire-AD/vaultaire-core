// Package commandenroll gère les clés d'enrôlement des clients service.
//
//	vlt enroll create --type <type> [--uses N] [--expires 30m] [--label ...]
//	vlt enroll list
//	vlt enroll show <id>
//	vlt enroll revoke <id>
//	vlt enroll types
//
// # Ce que ces clés permettent
//
// Un client SERVICE — interface web, proxy, extensions — n'est pas créé à
// l'avance sur le core comme un agent de poste. Il génère sa paire de clés
// localement et présente une clé d'enrôlement pour faire enregistrer sa clé
// publique. La clé privée ne quitte donc jamais son hôte.
//
// # Le type vient de la clé, jamais du client
//
// C'est le point de sécurité central. Si le service annonçait son type, il
// suffirait de s'enrôler pour se déclarer `vaultaire_web` et obtenir avec lui le
// droit d'agir au nom de n'importe quel utilisateur de l'annuaire.
package commandenroll

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"vaultaire/core/clienttype"
	"vaultaire/core/database"
	dbenrollment "vaultaire/core/database/db_enrollment"
	isprotected "vaultaire/core/database/is_protected"
	"vaultaire/core/logs"
	"vaultaire/core/permission"
)

// Valeurs par défaut : une seule utilisation, valable trente minutes.
//
// Le défaut le plus restreint possible. Une clé tapée sans option sert à
// installer un service, tout de suite, une fois — pas à rester dans un script de
// déploiement pendant six mois.
const (
	defaultUses    = 1
	defaultTTL     = 30 * time.Minute
	maxTTL         = 7 * 24 * time.Hour
	maxUsesAllowed = 50
)

// Enroll_Command traite `vlt enroll ...`.
//
// # Contrôle d'accès
//
// Émettre une clé d'enrôlement, c'est accorder le droit d'ajouter un programme
// au cluster : c'est donc une création de client, et la clé RBAC est la même
// (`write:create:client`). La révocation l'est aussi — retirer à quelqu'un le
// moyen d'installer un service engage autant que le lui donner.
//
// Le droit est exigé sur « * » et non sur un domaine. Une clé d'enrôlement
// n'appartient à aucun domaine : le service qu'elle fera naître parle au cluster
// entier. C'est la même règle que pour les certificats et les restrictions GPO,
// et pour la même raison.
//
// S'ajoute, pour un type portant AssertsUser, l'appartenance au groupe
// d'amorçage — voir createKey.
func Enroll_Command(commandList []string, senderGroupIDs []int, senderUsername string) string {
	if len(commandList) == 0 {
		return helpText()
	}
	sub := strings.ToLower(commandList[0])

	var actionKey string
	switch sub {
	case "create", "revoke":
		actionKey = "write:create:client"
	case "list", "show":
		actionKey = "read:get:client"
	}
	if actionKey != "" {
		ok, reason := permission.CheckPermissionsMultipleDomains(senderGroupIDs, actionKey, []string{"*"})
		if !ok {
			logs.Write_Log("WARNING", fmt.Sprintf(
				"Permission refused: user=%s action=%s (enroll %s) reason=%s",
				senderUsername, actionKey, sub, reason))
			return "Permission refusée : " + reason
		}
		logs.Write_Log("INFO", fmt.Sprintf(
			"Permission used: user=%s action=%s (enroll %s)", senderUsername, actionKey, sub))
	}

	switch sub {
	case "-h", "help", "--help":
		return helpText()
	case "types":
		// Le catalogue est une information de structure, pas une donnée
		// d'annuaire : le lire n'apprend rien sur le parc.
		return listTypes()
	case "create":
		return createKey(commandList[1:], senderUsername)
	case "list":
		return listKeys()
	case "show":
		return showKey(commandList[1:])
	case "revoke":
		return revokeKey(commandList[1:], senderUsername)
	default:
		return "Requête invalide. Essayez 'enroll -h'."
	}
}

// createKey émet une clé et l'affiche UNE SEULE FOIS.
func createKey(args []string, senderUsername string) string {
	var (
		clientType string
		label      string
		uses       = defaultUses
		ttl        = defaultTTL
	)

	for i := 0; i < len(args); i++ {
		switch strings.ToLower(args[i]) {
		case "--type", "--uses", "--expires", "--label":
			if i+1 >= len(args) {
				return "Option " + args[i] + " : valeur manquante."
			}
			value := strings.TrimSpace(args[i+1])
			switch strings.ToLower(args[i]) {
			case "--type":
				clientType = value
			case "--label":
				label = value
			case "--uses":
				n, err := strconv.Atoi(value)
				if err != nil {
					return fmt.Sprintf("Option --uses : « %s » n'est pas un nombre.", value)
				}
				uses = n
			case "--expires":
				d, err := time.ParseDuration(value)
				if err != nil {
					return fmt.Sprintf("Option --expires : « %s » n'est pas une durée (exemples : 30m, 2h, 24h).", value)
				}
				ttl = d
			}
			i++
		default:
			return "Option inconnue : " + args[i] + ". Essayez 'enroll -h'."
		}
	}

	if clientType == "" {
		return "Type requis. Usage : enroll create --type <type>\nTypes enrôlables : " +
			strings.Join(clienttype.ServiceNames(), ", ")
	}

	// Le type doit exister ET être un service. Un agent se crée sur le core
	// avec sa paire de clés : lui ouvrir l'enrôlement contournerait ce chemin.
	if err := clienttype.Validate(clientType); err != nil {
		return err.Error()
	}
	if !clienttype.IsService(clientType) {
		return fmt.Sprintf(
			"%s est un agent, pas un service : il se crée sur le core avec « create -c ».\nTypes enrôlables : %s",
			clientType, strings.Join(clienttype.ServiceNames(), ", "))
	}

	if uses < 1 || uses > maxUsesAllowed {
		return fmt.Sprintf("Le quota doit être compris entre 1 et %d.", maxUsesAllowed)
	}
	if ttl <= 0 || ttl > maxTTL {
		return fmt.Sprintf("La durée de validité doit être comprise entre 1 seconde et %s.", maxTTL)
	}

	db := database.GetDatabase()

	// Une clé visant un type qui porte AssertsUser donne le pouvoir d'agir au
	// nom de n'importe quel utilisateur. Ce n'est pas un droit qui se délègue
	// par une clé RBAC ordinaire : il est réservé au groupe d'amorçage, comme
	// les restrictions GPO et les certificats, et pour la même raison — ce que
	// la décision engage ne tient dans aucun domaine.
	if clienttype.MayAssertUser(clientType) && !isprotected.IsSuperadmin(db, senderUsername) {
		logs.Write_Log("SECURITY", fmt.Sprintf(
			"enrôlement: %s tente d'émettre une clé %s (assertion d'identité) sans appartenir au groupe %s",
			senderUsername, clientType, isprotected.ProtectedGroupName))
		return fmt.Sprintf(
			"Permission refusée : une clé %s permet d'agir au nom de n'importe quel utilisateur.\n"+
				"Son émission est réservée aux membres du groupe %s.",
			clientType, isprotected.ProtectedGroupName)
	}

	secret, err := dbenrollment.GenerateSecret()
	if err != nil {
		return "Génération impossible : " + err.Error()
	}
	expiresAt := time.Now().Add(ttl)

	id, err := dbenrollment.CreateKey(db, secret, label, clientType, uses, expiresAt, senderUsername)
	if err != nil {
		return "Émission impossible : " + err.Error()
	}

	return fmt.Sprintf(`Clé d'enrôlement %d émise.

  %s

  Type    : %s
  Quota   : %d utilisation(s)
  Expire  : %s

Cette clé ne sera plus jamais affichée : seul son condensat est en base.
Si elle est perdue, révoquez-la et émettez-en une autre.`,
		id, secret, clientType, uses, expiresAt.Format("2006-01-02 15:04:05"))
}

func listKeys() string {
	keys, err := dbenrollment.ListKeys(database.GetDatabase())
	if err != nil {
		return "Lecture impossible : " + err.Error()
	}
	if len(keys) == 0 {
		return "Aucune clé d'enrôlement."
	}

	now := time.Now()
	var b strings.Builder
	fmt.Fprintf(&b, "%-4s %-20s %-12s %-9s %-19s %s\n",
		"ID", "TYPE", "ÉTAT", "USAGES", "EXPIRE", "ÉMISE PAR")
	for _, k := range keys {
		fmt.Fprintf(&b, "%-4d %-20s %-12s %-9s %-19s %s\n",
			k.ID, k.ClientType, k.Status(now),
			fmt.Sprintf("%d/%d", k.UsedCount, k.MaxUses),
			k.ExpiresAt.Format("2006-01-02 15:04"), k.CreatedBy)
	}
	return strings.TrimRight(b.String(), "\n")
}

func showKey(args []string) string {
	if len(args) == 0 {
		return "Identifiant requis. Usage : enroll show <id>"
	}
	id, err := strconv.Atoi(strings.TrimSpace(args[0]))
	if err != nil {
		return fmt.Sprintf("« %s » n'est pas un identifiant.", args[0])
	}

	db := database.GetDatabase()
	keys, err := dbenrollment.ListKeys(db)
	if err != nil {
		return "Lecture impossible : " + err.Error()
	}
	var found bool
	var b strings.Builder
	now := time.Now()
	for _, k := range keys {
		if k.ID != id {
			continue
		}
		found = true
		fmt.Fprintf(&b, "Clé %d\n  Libellé : %s\n  Type    : %s\n  État    : %s\n  Usages  : %d/%d\n  Expire  : %s\n  Émise   : %s par %s\n",
			k.ID, orDash(k.Label), k.ClientType, k.Status(now), k.UsedCount, k.MaxUses,
			k.ExpiresAt.Format("2006-01-02 15:04:05"),
			k.CreatedAt.Format("2006-01-02 15:04:05"), k.CreatedBy)
		if k.RevokedAt.Valid {
			fmt.Fprintf(&b, "  Révoquée: %s par %s\n",
				k.RevokedAt.Time.Format("2006-01-02 15:04:05"), k.RevokedBy.String)
		}
	}
	if !found {
		return fmt.Sprintf("Clé %d introuvable.", id)
	}

	uses, err := dbenrollment.UsesOf(db, id)
	if err != nil {
		return b.String() + "\nConsommations illisibles : " + err.Error()
	}
	if len(uses) == 0 {
		b.WriteString("\nAucun service enrôlé avec cette clé.")
		return b.String()
	}
	b.WriteString("\nServices enrôlés avec cette clé :\n")
	for _, u := range uses {
		fmt.Fprintf(&b, "  %-24s %-20s %-19s %s\n",
			u.ComputeurID, u.ClientType,
			u.UsedAt.Format("2006-01-02 15:04:05"), orDash(u.SourceIP.String))
	}
	return strings.TrimRight(b.String(), "\n")
}

func revokeKey(args []string, senderUsername string) string {
	if len(args) == 0 {
		return "Identifiant requis. Usage : enroll revoke <id>"
	}
	id, err := strconv.Atoi(strings.TrimSpace(args[0]))
	if err != nil {
		return fmt.Sprintf("« %s » n'est pas un identifiant.", args[0])
	}
	if err := dbenrollment.RevokeKey(database.GetDatabase(), id, senderUsername); err != nil {
		return "Révocation impossible : " + err.Error()
	}
	return fmt.Sprintf(
		"Clé %d révoquée. Les services déjà enrôlés avec elle ne sont pas affectés :\n"+
			"ils ont leur propre paire de clés. Pour retirer l'un d'eux, supprimez le client.", id)
}

func listTypes() string {
	var b strings.Builder
	b.WriteString("Types de clients au catalogue :\n\n")
	for _, d := range clienttype.All() {
		famille := "agent   (créé sur le core)"
		if d.Family == clienttype.FamilyService {
			famille = "service (s'enrôle seul)"
		}
		fmt.Fprintf(&b, "  %-20s %s\n", d.Name, famille)
		fmt.Fprintf(&b, "  %-20s %s\n", "", d.Description)
		if d.AssertsUser {
			fmt.Fprintf(&b, "  %-20s ⚠ peut agir au nom d'un utilisateur qu'il authentifie\n", "")
		}
		fmt.Fprintf(&b, "  %-20s trames : %s\n\n", "", strings.Join(d.Frames, " "))
	}
	return strings.TrimRight(b.String(), "\n")
}

func orDash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "—"
	}
	return s
}

func helpText() string {
	return `Clés d'enrôlement des clients service.

  enroll create --type <type> [--uses N] [--expires 30m] [--label texte]
  enroll list                      les clés émises et leur état
  enroll show <id>                 le détail d'une clé et les services entrés avec
  enroll revoke <id>               neutralise une clé sans effacer sa trace
  enroll types                     le catalogue des types de clients

Un client SERVICE génère sa paire de clés lui-même : la clé privée ne quitte
jamais son hôte. La clé d'enrôlement n'autorise que la remise de sa clé PUBLIQUE.

LE TYPE VIENT DE LA CLÉ. Le service ne le déclare pas, il le reçoit — sans quoi
il suffirait de s'enrôler pour se donner les privilèges qu'on veut.

Par défaut : une utilisation, trente minutes. La clé n'est affichée qu'une fois.

Un AGENT de poste ne s'enrôle pas : il se crée sur le core avec « create -c ».`
}
