package displaydns

import (
	"sort"
	"strconv"

	"vaultaire/core/command/display"
	dnsstorage "vaultaire/core/dns/DNS_Storage"
)

// DisplayAllZones affiche les zones DNS connues du serveur.
//
// L'ancienne version mêlait `tabwriter` et `%-30s` : deux mécanismes
// d'alignement incompatibles, et le second comptait les codes couleur des
// en-têtes dans la largeur. Les colonnes étaient donc décalées de la longueur
// exacte des séquences d'échappement, ce qui ne se voyait qu'en terminal
// coloré. Le module display mesure la largeur VISIBLE et calcule les colonnes
// sur le contenu réel.
func DisplayAllZones(zones []dnsstorage.Zone) string {
	if len(zones) == 0 {
		return "Aucune zone DNS enregistrée.\n"
	}

	// Ordre stable : la base ne garantit aucun tri, et deux appels successifs
	// affichant les mêmes zones dans un ordre différent laissent croire à un
	// changement.
	tri := make([]dnsstorage.Zone, len(zones))
	copy(tri, zones)
	sort.Slice(tri, func(i, j int) bool { return tri[i].ZoneName < tri[j].ZoneName })

	tb := display.NouvelleTable("Zone", "Table de stockage")
	for _, z := range tri {
		tb.Ajouter(display.Valeur(z.ZoneName), display.Valeur(z.TableName))
	}

	suffixe := " zone"
	if len(tri) > 1 {
		suffixe = " zones"
	}
	return "Zones DNS (" + strconv.Itoa(len(tri)) + suffixe + ")\n\n" + tb.String()
}
