package commanddns

import (
	"fmt"
	"strings"

	"vaultaire/core/action"
	commandaction "vaultaire/core/command/commandaction"
	displaydns "vaultaire/core/command/display/display_dns"
	dnsdatabase "vaultaire/core/dns/DNS_Database"
	dnsstorage "vaultaire/core/dns/DNS_Storage"
	"vaultaire/core/logs"
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
		return listerZones(action.Appelant{Username: sender, GroupIDs: groupIDs})

	case "show":
		if len(args) < 2 {
			return "Requête invalide : dns zone show <nom.zone>"
		}
		return afficherZone(args[1], action.Appelant{Username: sender, GroupIDs: groupIDs})

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
		// Le PTR inverse passe encore par sa propre lecture : elle interroge une
		// table à part (ptr_records) et n'a pas d'action. Le contrôle emploie
		// néanmoins la même clé, par le même chemin de décision.
		if refus := controlerLectureDNS(groupIDs, sender); refus != "" {
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

// controlerLectureDNS contrôle sans exécuter, pour le seul cas restant.
//
// Controler plutôt qu'une vérification recopiée : même clé, même portée, même
// journal que les actions. Rien n'est exécuté — voir Executeur.Controler.
func controlerLectureDNS(groupIDs []int, sender string) string {
	_, err := action.Defaut.Controler("dns.list_zones",
		action.Appelant{Username: sender, GroupIDs: groupIDs}, action.Params{})
	if err != nil {
		return commandaction.MessageDErreur(err)
	}
	return ""
}

// verifierLectureDNS a disparu.
//
// Elle contrôlait les lectures avec `write:dns` — le droit de MODIFIER le DNS —
// faute d'une clé de lecture. Son commentaire l'assumait : « créer read:dns
// demanderait de l'ajouter aux actions spéciales et de la distribuer aux
// permissions existantes, ce qui n'est pas le sujet de ce changement ».
//
// C'est fait. Les lectures passent par dns.list_zones et dns.list_records, qui
// exigent `read:dns`. Voir permission.ActionReadDNS.

func listerZones(a action.Appelant) string {
	res, err := action.Executer("dns.list_zones", a, action.Params{})
	if err != nil {
		return commandaction.MessageDErreur(err)
	}
	zones, _ := res.Donnees.([]dnsstorage.Zone)
	return displaydns.DisplayAllZones(zones)
}

func afficherZone(zone string, a action.Appelant) string {
	res, err := action.Executer("dns.list_records", a, action.Params{"zone": zone})
	if err != nil {
		return commandaction.MessageDErreur(err)
	}
	d, ok := res.Donnees.(action.EnregistrementsDeZone)
	if !ok {
		return res.Message
	}
	return displaydns.DisplayZoneRecords(d.Enregistrements, d.Zone)
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
