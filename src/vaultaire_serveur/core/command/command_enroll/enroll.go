// Package commandenroll gère les clés d'enrôlement des clients service.
//
//	vlt enroll create --type <type> [--uses N] [--expires 30m] [--label ...] [--groups a,b]
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

	"vaultaire/core/action"
	"vaultaire/core/clienttype"
	commandaction "vaultaire/core/command/commandaction"
	"vaultaire/core/command/display"
	"vaultaire/core/database"
	dbenrollment "vaultaire/core/database/db_enrollment"
)

// Valeurs par défaut : une seule utilisation, valable trente minutes.
//
// Le défaut le plus restreint possible. Une clé tapée sans option sert à
// installer un service, tout de suite, une fois — pas à rester dans un script de
// déploiement pendant six mois.
const (
	defaultUses = 1
	defaultTTL  = 30 * time.Minute
	// Bornes affichées dans l'aide. Les bornes qui FONT FOI sont celles de
	// l'action enroll.create_key : celles-ci ne sont qu'un rappel à
	// l'utilisateur, et les garder ici sans le dire laisserait croire qu'elles
	// contrôlent quelque chose.
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

	// Seules les LECTURES sont contrôlées ici.
	//
	// « create » et « revoke » passent par le registre, qui porte leur clé et
	// leur portée : les contrôler ici en plus ferait deux endroits où le droit
	// se décide, donc deux endroits à tenir d'accord.
	//
	// Le motif d'origine était fail-open — le switch n'avait pas de `default`,
	// et une sous-commande absente de la table laissait actionKey vide, donc
	// sautait la vérification. « types » en profitait délibérément, mais rien
	// ne le disait : toute sous-commande ajoutée ensuite en aurait profité
	// aussi, sans que personne le remarque.
	//
	// La liste est donc explicite, et « types » y figure avec sa raison.
	switch sub {
	case "list", "show":
		// read:enrollment et non plus read:get:client.
		//
		// Voir la liste des clés en attente exigeait le droit de lire TOUTES
		// les machines de TOUS les domaines. Une clé d'enrôlement n'appartient
		// pourtant à aucun domaine — même cas que le cluster et les
		// certificats.
		//
		// L'émission et la révocation restent sur write:create:client, et
		// délibérément : émettre une clé, c'est accorder le droit d'ajouter un
		// programme au cluster.
		if _, err := action.Defaut.Controler("enroll.list_keys",
			action.Appelant{Username: senderUsername, GroupIDs: senderGroupIDs},
			action.Params{}); err != nil {
			return commandaction.MessageDErreur(err)
		}

	case "types":
		// Aucun contrôle, et c'est voulu : le catalogue des types est une
		// constante du logiciel, pas une donnée d'annuaire. Le lire n'apprend
		// rien sur le parc.

	case "create", "revoke":
		// Contrôlées par le registre. Voir core/action/actions_enroll.go.

	case "-h", "help", "--help":
		// L'aide est publique.

	default:
		// Fail-closed : une sous-commande inconnue est refusée, pas exécutée
		// sans contrôle.
		return "Requête invalide. Essayez 'enroll -h'."
	}

	switch sub {
	case "-h", "help", "--help":
		return helpText()
	case "types":
		// Le catalogue est une information de structure, pas une donnée
		// d'annuaire : le lire n'apprend rien sur le parc.
		return listTypes()
	case "create":
		return creerCle(commandList[1:], senderGroupIDs, senderUsername)
	case "list":
		return listKeys()
	case "show":
		return showKey(commandList[1:])
	case "revoke":
		return revoquerCle(commandList[1:], senderGroupIDs, senderUsername)
	default:
		return "Requête invalide. Essayez 'enroll -h'."
	}
}

// creerCle émet une clé d'enrôlement via l'action enroll.create_key.
//
// # Ce qui a disparu d'ici
//
// La validation du type, celle des bornes, le contrôle du droit RBAC et
// l'exigence d'appartenance au groupe protégé pour les types qui portent
// l'assertion d'identité. Tout cela vivait ici ET dans web_admin_enroll.go, en
// double, avec des messages qui avaient déjà divergé.
//
// Cette fonction ne fait plus qu'une chose : traduire « --type X --uses 3
// --expires 24h » en paramètres nommés. La durée est convertie en minutes,
// parce que c'est ce que l'action attend — et que l'interface web l'exprimait
// déjà ainsi.
func creerCle(args []string, groupIDs []int, senderUsername string) string {
	var clientType, label, groupes string
	uses := 1
	ttl := 24 * time.Hour

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--type", "--uses", "--expires", "--label", "--groups":
			if i+1 >= len(args) {
				return fmt.Sprintf("L'option %s attend une valeur.", args[i])
			}
			valeur := args[i+1]
			i++
			switch args[i-1] {
			case "--type":
				clientType = strings.TrimSpace(valeur)
			case "--label":
				label = strings.TrimSpace(valeur)
			case "--groups":
				// Les groupes de NAISSANCE du service enrôlé par cette clé.
				//
				// Transmis tels quels : c'est l'action qui découpe, parce que
				// le formulaire web envoie la même chaîne. Deux découpages
				// finiraient par ne pas accepter les mêmes séparateurs.
				groupes = strings.TrimSpace(valeur)
			case "--uses":
				n, err := strconv.Atoi(strings.TrimSpace(valeur))
				if err != nil {
					return fmt.Sprintf("Quota invalide : « %s » n'est pas un nombre.", valeur)
				}
				uses = n
			case "--expires":
				d, err := time.ParseDuration(strings.TrimSpace(valeur))
				if err != nil {
					return fmt.Sprintf("Durée invalide : « %s ». Exemples : 30m, 24h, 168h.", valeur)
				}
				ttl = d
			}
		default:
			return fmt.Sprintf("Option inconnue : %s. Voir « enroll -h ».", args[i])
		}
	}

	if clientType == "" {
		return "Type requis. Usage : enroll create --type <type>\nTypes enrôlables : " +
			strings.Join(clienttype.ServiceNames(), ", ")
	}

	// Une durée négative n'a pas de sens et ParseDuration l'accepte pourtant :
	// « -24h » est une durée valide. Sans ce contrôle, elle produirait une clé
	// déjà expirée à sa création — donc inutilisable, sans que rien ne le dise.
	if ttl < 0 {
		return "La durée de validité ne peut pas être négative."
	}

	p := action.Params{
		"client_type":     clientType,
		"label":           label,
		"uses":            strconv.Itoa(uses),
		"expires_minutes": strconv.Itoa(int(ttl.Minutes())),
		"groups":          groupes,
	}

	res, err := action.Executer("enroll.create_key",
		action.Appelant{Username: senderUsername, GroupIDs: groupIDs}, p)
	if err != nil {
		return commandaction.MessageDErreur(err)
	}

	// Le secret est lu dans les données et non dans le message : le message
	// part dans les journaux, et une clé d'enrôlement en clair dans un journal
	// est une clé publiée.
	secret := ""
	if d, ok := res.Donnees.(map[string]string); ok {
		secret = d["secret"]
	}
	if secret == "" {
		return res.Message + "\n(le secret n'a pas pu être lu : la clé existe mais est inutilisable, révoquez-la)"
	}

	return fmt.Sprintf("%s\n\n  %s\n", res.Message, secret)
}

func listKeys() string {
	keys, err := dbenrollment.ListKeys(database.GetDatabase())
	if err != nil {
		return "Lecture impossible : " + err.Error()
	}
	if len(keys) == 0 {
		return "Aucune clé d'enrôlement."
	}

	// « ÉTAT » et « ÉMISE PAR » portent des accents : `%-12s` compte les
	// OCTETS, et « É » en occupe deux pour un seul caractère à l'écran. Chaque
	// accent décalait donc la colonne suivante d'un cran. Le module d'affichage
	// mesure en runes.
	// Les groupes de naissance en UNE requête : une par ligne affichée
	// transformerait un tableau de vingt clés en vingt-et-un allers-retours.
	//
	// Un échec n'interrompt pas la liste — une colonne vide vaut mieux qu'un
	// refus d'afficher les clés.
	groupesParCle, _ := dbenrollment.KeyGroupsByKey(database.GetDatabase())

	now := time.Now()
	tb := display.NouvelleTable("ID", "TYPE", "ÉTAT", "GROUPES DE NAISSANCE",
		"USAGES", "EXPIRE", "ÉMISE PAR")
	for _, k := range keys {
		tb.Ajouter(
			strconv.Itoa(k.ID),
			k.ClientType,
			k.Status(now),
			// Vide = le service naîtra sans groupe, donc sans affinité : il
			// joindra les nœuds du parc sans préférence de site.
			display.Valeur(strings.Join(groupesParCle[k.ID], ", ")),
			usesText(k),
			expiryText(k),
			display.Valeur(k.CreatedBy),
		)
	}
	return strings.TrimRight(tb.String(), "\n")
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
		fmt.Fprintf(&b, "Clé %d\n  Libellé : %s\n  Type    : %s\n  État    : %s\n  Usages  : %s\n  Expire  : %s\n  Émise   : %s par %s\n",
			k.ID, orDash(k.Label), k.ClientType, k.Status(now), usesText(k), expiryText(k),
			k.CreatedAt.Format("2006-01-02 15:04:05"), k.CreatedBy)
		if k.RevokedAt.Valid {
			fmt.Fprintf(&b, "  Révoquée: %s par %s\n",
				k.RevokedAt.Time.Format("2006-01-02 15:04:05"), k.RevokedBy.String)
		}

		// Groupes de naissance : où entrera le service enrôlé avec cette clé.
		//
		// La ligne est écrite même quand il n'y en a aucun. « aucun » répond à
		// la question ; une ligne absente laisse croire que le détail ne la
		// couvre pas, et on va la chercher ailleurs.
		groupes, errG := dbenrollment.KeyGroups(db, k.ID)
		switch {
		case errG != nil:
			fmt.Fprintf(&b, "  Groupes : illisibles (%v)\n", errG)
		case len(groupes) == 0:
			b.WriteString("  Groupes : aucun — le service naîtra sans affinité de site\n")
		default:
			fmt.Fprintf(&b, "  Groupes : %s (appliqués UNE FOIS, à l'enrôlement)\n",
				strings.Join(groupes, ", "))
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

// revoquerCle passe par l'action enroll.revoke_key.
//
// Le contrôle du droit et la validation de l'identifiant vivent dans l'action,
// partagés avec l'interface web.
func revoquerCle(args []string, groupIDs []int, senderUsername string) string {
	if len(args) == 0 {
		return "Identifiant requis. Usage : enroll revoke <id>"
	}
	p := action.Params{"key_id": args[0]}
	return commandaction.ExecuterAction("enroll.revoke_key", p, groupIDs, senderUsername)
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

// usesText et expiryText rendent lisible l'absence de limite, plutôt que
// d'afficher « 3/0 » ou une date à l'an zéro.
func usesText(k dbenrollment.Record) string {
	if k.UnlimitedUses() {
		return fmt.Sprintf("%d/∞", k.UsedCount)
	}
	return fmt.Sprintf("%d/%d", k.UsedCount, k.MaxUses)
}

func expiryText(k dbenrollment.Record) string {
	if k.NeverExpires() {
		return "jamais"
	}
	return k.ExpiresAt.Time.Format("2006-01-02 15:04")
}

func orDash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "—"
	}
	return s
}

func helpText() string {
	return `Clés d'enrôlement des clients service.

  enroll create --type <type> [--uses N] [--expires 30m] [--label texte] [--groups a,b]
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
