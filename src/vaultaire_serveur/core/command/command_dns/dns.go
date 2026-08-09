package commanddns

import (
	"fmt"
	"strings"

	"vaultaire/core/action"
	commandaction "vaultaire/core/command/commandaction"
	"vaultaire/core/command/display"
	dnsdatabase "vaultaire/core/dns/DNS_Database"
	"vaultaire/core/logs"
	"vaultaire/core/permission"
)

// Commande « dns » — zones, enregistrements et résolution inverse.
//
// # Une syntaxe qui se contredisait
//
// L'ancienne forme mélangeait deux conventions :
//
//	dns create_zone <zone>       verbe_objet
//	dns add_record  <fqdn> ...   verbe_objet
//	dns get_zone    <zone>       verbe_objet
//	dns delete zone <zone>       objet en second mot
//	dns delete record <fqdn>     objet en second mot
//
// Autrement dit, on créait une zone avec `create_zone` mais on la supprimait
// avec `delete zone`. Rien ne le laissait deviner : il fallait ouvrir l'aide à
// chaque fois, et l'aide elle-même ne mentionnait pas `delete`.
//
// La forme retenue est `dns <objet> <verbe>`, celle qu'emploient déjà
// `enroll create|revoke` et `certificate list|show`. Elle a l'avantage de se
// lire dans l'ordre où l'on pense — « les zones, en créer une » — et de
// s'étendre sans allonger la liste des mots-clés.
//
// # Les anciennes formes restent acceptées
//
// Elles répondent avec un avertissement plutôt qu'une erreur. Un script qui les
// emploie continue de fonctionner, et son auteur voit qu'il doit le mettre à
// jour — ce qu'un refus sec ne lui aurait pas appris, puisqu'il aurait
// simplement constaté une panne.

// ActionsUtilisees liste les actions du registre appelées ici.
var ActionsUtilisees = []string{
	"dns.create_zone",
	"dns.delete_zone",
	"dns.add_record",
	"dns.delete_record",
	"dns.delete_ptr",
}

// DNS_Command traite « dns … ».
func DNS_Command(commandList []string, senderGroupIDs []int, senderUsername string) string {
	if len(commandList) == 0 {
		return aide()
	}

	objet := strings.ToLower(commandList[0])

	// Les anciennes formes, traduites vers la nouvelle.
	if traduit, ancienne := traduireAncienneForme(commandList); ancienne {
		logs.Write_Log("INFO", fmt.Sprintf(
			"dns : forme obsolète « %s » employée par %s, traduite en « dns %s »",
			strings.Join(commandList, " "), senderUsername, strings.Join(traduit, " ")))
		return avertissementForme(commandList[0], traduit) +
			DNS_Command(traduit, senderGroupIDs, senderUsername)
	}

	switch objet {
	case "-h", "help", "--help":
		return aide()

	case "zone":
		return commandeZone(commandList[1:], senderGroupIDs, senderUsername)

	case "record":
		return commandeRecord(commandList[1:], senderGroupIDs, senderUsername)

	case "ptr":
		return commandePTR(commandList[1:], senderGroupIDs, senderUsername)

	default:
		return "Requête invalide. Essayez « dns -h »."
	}
}

// --- zones ------------------------------------------------------------------

func commandeZone(args []string, groupIDs []int, sender string) string {
	if len(args) == 0 {
		return "Requête invalide : dns zone create|list|show|delete"
	}

	switch strings.ToLower(args[0]) {
	case "create":
		if len(args) < 2 {
			return "Requête invalide : dns zone create <nom.zone>"
		}
		return commandaction.ExecuterAction("dns.create_zone",
			action.Params{"zone_name": args[1]}, groupIDs, sender)

	case "delete":
		if len(args) < 2 {
			return "Requête invalide : dns zone delete <nom.zone>"
		}
		return commandaction.ExecuterAction("dns.delete_zone",
			action.Params{"zone": args[1]}, groupIDs, sender)

	case "list":
		// Lecture : contrôlée ici, le registre ne porte que les écritures.
		if refus := verifierLectureDNS(groupIDs, sender); refus != "" {
			return refus
		}
		return listerZones()

	case "show":
		if len(args) < 2 {
			return "Requête invalide : dns zone show <nom.zone>"
		}
		if refus := verifierLectureDNS(groupIDs, sender); refus != "" {
			return refus
		}
		return afficherZone(args[1])

	default:
		return "Requête invalide : dns zone create|list|show|delete"
	}
}

// --- enregistrements --------------------------------------------------------

func commandeRecord(args []string, groupIDs []int, sender string) string {
	if len(args) == 0 {
		return "Requête invalide : dns record add|delete"
	}

	switch strings.ToLower(args[0]) {
	case "add":
		// dns record add <fqdn> <type> <données> [ttl] [priorité]
		//
		// Le TTL devient FACULTATIF. L'ancienne forme l'exigeait en quatrième
		// position, ce qui obligeait à saisir 300 pour tout enregistrement
		// ordinaire — et une valeur saisie à la hâte vaut moins qu'un défaut
		// choisi.
		if len(args) < 4 {
			return "Requête invalide : dns record add <fqdn> <type> <données> [ttl] [priorité]"
		}
		p := action.Params{
			"zone":        "", // le FQDN est complet : voir plus bas
			"name":        args[1],
			"record_type": args[2],
			"data":        args[3],
		}
		if len(args) >= 5 {
			p["ttl"] = args[4]
		}
		if len(args) >= 6 {
			p["priority"] = args[5]
		}

		// L'action assemble « nom + zone ». Ici le FQDN est déjà complet, et
		// la zone la plus spécifique est déterminée par la base. On passe donc
		// le FQDN comme zone avec « @ » pour nom, ce qui rend le nom inchangé.
		p["zone"] = args[1]
		p["name"] = "@"
		return commandaction.ExecuterAction("dns.add_record", p, groupIDs, sender)

	case "delete":
		if len(args) < 3 {
			return "Requête invalide : dns record delete <fqdn> <type>"
		}
		return commandaction.ExecuterAction("dns.delete_record",
			action.Params{"zone": args[1], "record_name": "@", "record_type": args[2]},
			groupIDs, sender)

	default:
		return "Requête invalide : dns record add|delete"
	}
}

// --- résolution inverse -----------------------------------------------------

func commandePTR(args []string, groupIDs []int, sender string) string {
	if len(args) == 0 {
		return "Requête invalide : dns ptr list|delete"
	}

	switch strings.ToLower(args[0]) {
	case "list":
		if refus := verifierLectureDNS(groupIDs, sender); refus != "" {
			return refus
		}
		return listerPTR()

	case "delete":
		if len(args) < 2 {
			return "Requête invalide : dns ptr delete <ip>"
		}
		return commandaction.ExecuterAction("dns.delete_ptr",
			action.Params{"ip": args[1]}, groupIDs, sender)

	default:
		return "Requête invalide : dns ptr list|delete"
	}
}

// --- compatibilité ----------------------------------------------------------

// traduireAncienneForme convertit les anciens mots-clés.
//
// Rend la commande traduite et un booléen. Le booléen plutôt qu'une comparaison
// avec l'entrée : une traduction peut rendre exactement la même chose, et
// l'appelant doit savoir s'il faut avertir.
func traduireAncienneForme(args []string) ([]string, bool) {
	if len(args) == 0 {
		return nil, false
	}

	switch strings.ToLower(args[0]) {
	case "create_zone":
		return append([]string{"zone", "create"}, args[1:]...), true
	case "get_zone":
		return append([]string{"zone", "show"}, args[1:]...), true
	case "add_record":
		return append([]string{"record", "add"}, args[1:]...), true
	case "get_ptr":
		return append([]string{"ptr", "list"}, args[1:]...), true

	case "delete":
		// « delete zone X » → « zone delete X ». L'inversion est exactement ce
		// qui rendait la syntaxe imprévisible.
		if len(args) >= 2 {
			switch strings.ToLower(args[1]) {
			case "zone", "record", "ptr":
				return append([]string{strings.ToLower(args[1]), "delete"}, args[2:]...), true
			}
		}
	}
	return nil, false
}

func avertissementForme(ancien string, traduit []string) string {
	return fmt.Sprintf(
		"Note : « dns %s » est une forme obsolète, comprise comme « dns %s ». "+
			"Voir « dns -h ».\n\n", ancien, strings.Join(traduit, " "))
}

// --- lectures ---------------------------------------------------------------

// verifierLectureDNS contrôle le droit de consulter la configuration DNS.
//
// Même clé que l'écriture, faute d'une clé de lecture distincte. Le commentaire
// le dit plutôt que de laisser croire à une omission : créer read:dns
// demanderait de l'ajouter aux actions spéciales et de la distribuer aux
// permissions existantes, ce qui n'est pas le sujet de ce changement.
func verifierLectureDNS(groupIDs []int, sender string) string {
	ok, motif := permission.CheckPermissionsAllDomains(groupIDs, "write:dns", []string{"*"})
	if !ok {
		logs.Write_Log("SECURITY", fmt.Sprintf(
			"consultation DNS refusée à %s : droit write:dns exigé — %s", sender, motif))
		return "Permission refusée : " + motif
	}
	return ""
}

func listerZones() string {
	zones, err := dnsdatabase.GetAllDNSZones(dnsdatabase.GetDatabase())
	if err != nil {
		return "Erreur : lecture des zones impossible : " + err.Error()
	}
	if len(zones) == 0 {
		return "Aucune zone DNS. Créez-en une avec « dns zone create <nom.zone> »."
	}

	t := display.NouvelleTable("Zone", "Table")
	for _, z := range zones {
		t.Ajouter(display.Valeur(z.ZoneName), display.Valeur(z.TableName))
	}
	return fmt.Sprintf("%d zone(s)\n\n%s", len(zones), t.String())
}

func afficherZone(zone string) string {
	zone = strings.ToLower(strings.TrimSpace(zone))
	records, err := dnsdatabase.GetZoneRecords(dnsdatabase.GetDatabase(), zone)
	if err != nil {
		return fmt.Sprintf("Erreur : lecture de la zone %q impossible : %v", zone, err)
	}
	if len(records) == 0 {
		return fmt.Sprintf("Zone %s : aucun enregistrement.", zone)
	}

	t := display.NouvelleTable("Nom", "Type", "TTL", "Priorité", "Données")
	for _, r := range records {
		// Priority est un NullInt64 : une priorité absente n'est PAS zéro.
		// Les confondre afficherait « 0 » pour tous les enregistrements qui
		// n'en portent pas, c'est-à-dire tous sauf les MX et SRV — et zéro est
		// une priorité MX valide, la plus haute.
		priorite := "—"
		if r.Priority.Valid {
			priorite = fmt.Sprintf("%d", r.Priority.Int64)
		}
		t.Ajouter(
			display.Valeur(r.Name),
			display.Valeur(r.Type),
			fmt.Sprintf("%d", r.TTL),
			priorite,
			display.Valeur(r.Data),
		)
	}
	return fmt.Sprintf("Zone %s — %d enregistrement(s)\n\n%s", zone, len(records), t.String())
}

func listerPTR() string {
	// Réutilise l'affichage existant plutôt que d'écrire une seconde requête :
	// deux lectures de la même table finiraient par diverger sur ce qu'elles
	// montrent.
	return command_dns_showReverse(nil, dnsdatabase.GetDatabase())
}

func aide() string {
	return `dns — zones, enregistrements et résolution inverse.

  dns zone create <nom.zone>              crée une zone
  dns zone list                           liste les zones
  dns zone show <nom.zone>                affiche les enregistrements d'une zone
  dns zone delete <nom.zone>              supprime une zone ET son contenu

  dns record add <fqdn> <type> <données> [ttl] [priorité]
  dns record delete <fqdn> <type>

  dns ptr list                            enregistrements inverses
  dns ptr delete <ip>                     supprime un enregistrement inverse

Notes :
  Le TTL est facultatif : 300 secondes par défaut. La priorité ne concerne
  que les types MX et SRV.

  L'enregistrement est placé dans la zone la plus spécifique qui contient le
  FQDN — inutile de nommer la zone.

Formes obsolètes, encore comprises : create_zone, get_zone, add_record,
get_ptr, delete zone|record|ptr. Elles répondent avec un avertissement.`
}
