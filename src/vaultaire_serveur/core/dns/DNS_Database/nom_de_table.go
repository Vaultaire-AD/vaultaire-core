package dnsdatabase

import (
	"fmt"
	"regexp"
	"strings"
)

// Nom de la table d'une zone DNS (TO-DO 105).
//
// # Le défaut que ce fichier ferme
//
// Chaque zone a sa table, nommée d'après la zone : « zone_ » suivi du nom, les
// points remplacés par des soulignés. Ce nom était construit puis INTERPOLÉ
// dans la requête, sans validation ni citation, à douze endroits — cinq qui le
// fabriquaient depuis le nom de zone, sept qui le relisaient dans
// dns_zones.table_name, où les premiers l'avaient écrit. Seuls les points
// étaient remplacés, malgré une variable nommée « safeTableName ».
//
// Deux chemins y menaient : la création ou la suppression d'une zone par un
// délégué write:dns, mais aussi les requêtes TXT et NS reçues du RÉSEAU, dont
// le nom — octets bruts d'un paquet anonyme — atteignait la requête tel quel.
//
// # La correction
//
//   - le nom de zone est validé par LISTE BLANCHE (lettres, chiffres, tirets,
//     points entre étiquettes) ; allonger une liste de caractères interdits
//     aurait laissé passer le suivant qu'on n'a pas pensé à interdire ;
//   - l'identifiant est CITÉ, et revérifié par motif à chaque usage, y compris
//     quand il est relu en base : une ligne écrite avant ce correctif ne peut
//     plus entrer dans une requête.

// motifZone : étiquettes alphanumériques, tirets intérieurs, séparées par des
// points.
//
// Les MAJUSCULES sont admises : MySQL distingue la casse des noms de table sur
// Linux, et une zone créée avec une majuscule a une table qui la porte.
// Ramener tout en minuscules ferait viser une autre table que la sienne.
var motifZone = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)*$`)

// motifTable : ce qu'un nom de table de zone peut contenir, une fois fabriqué.
var motifTable = regexp.MustCompile(`^zone_[A-Za-z0-9_-]+$`)

// longueurMaxIdentifiant est la limite de MySQL/MariaDB pour un nom de table.
const longueurMaxIdentifiant = 64

// ValiderNomDeZone dit si un nom peut désigner une zone.
func ValiderNomDeZone(zone string) error {
	if zone == "" {
		return fmt.Errorf("nom de zone vide")
	}
	if len(zone) > 253 {
		// RFC 1035 § 2.3.4 : 255 octets encodés, soit 253 en texte.
		return fmt.Errorf("nom de zone de %d caractères, maximum 253", len(zone))
	}
	if !motifZone.MatchString(zone) {
		return fmt.Errorf("nom de zone %q refusé : lettres, chiffres et tirets, "+
			"étiquettes séparées par des points (ex. « acme.lan »)", zone)
	}
	if n := len("zone_") + len(zone); n > longueurMaxIdentifiant {
		return fmt.Errorf("nom de zone %q trop long pour la base : %d caractères au plus",
			zone, longueurMaxIdentifiant-len("zone_"))
	}
	return nil
}

// NomDeTable rend le nom de table d'une zone, après validation.
func NomDeTable(zone string) (string, error) {
	if err := ValiderNomDeZone(zone); err != nil {
		return "", err
	}
	return "zone_" + strings.ReplaceAll(zone, ".", "_"), nil
}

// identifiantTable cite un nom de table pour l'insérer dans une requête.
//
// Le nom est revérifié ICI, au moment de l'usage, et pas seulement à sa
// fabrication : les noms relus dans dns_zones ont pu y être écrits avant ce
// correctif. Un nom hors motif n'entre dans aucune requête.
func identifiantTable(nom string) (string, error) {
	if len(nom) > longueurMaxIdentifiant || !motifTable.MatchString(nom) {
		return "", fmt.Errorf("nom de table de zone %q refusé", nom)
	}
	return "`" + nom + "`", nil
}

// tableDeZone fabrique et cite le nom de table d'une zone, en un geste.
func tableDeZone(zone string) (string, error) {
	nom, err := NomDeTable(zone)
	if err != nil {
		return "", err
	}
	return identifiantTable(nom)
}
