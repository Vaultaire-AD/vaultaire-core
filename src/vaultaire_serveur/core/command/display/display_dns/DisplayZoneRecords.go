package displaydns

import (
	"sort"
	"strconv"
	"vaultaire/core/command/display"
	dnsstorage "vaultaire/core/dns/DNS_Storage"
)

// pluriel accorde le décompte affiché en titre.
func pluriel(n int) string {
	if n <= 1 {
		return strconv.Itoa(n) + " entrée"
	}
	return strconv.Itoa(n) + " entrées"
}

// DisplayZoneRecords affiche les enregistrements d'une zone.
//
// # Le défaut corrigé ici n'était pas cosmétique
//
// La boucle appelait :
//
//	fmt.Println(w, "%-25s %-8s %-6d ...\n", record.Name, ...)
//
// `fmt.Println` — et non `fmt.Fprintf`. Le writer était donc traité comme une
// simple valeur à afficher, la chaîne de format était imprimée telle quelle
// avec ses verbes, et le tout partait sur la SORTIE STANDARD au lieu d'être
// écrit dans le tampon rendu.
//
// Conséquence : la fonction rendait un tableau vide — en-têtes, filets, aucune
// ligne — pendant que les enregistrements s'échappaient sur stdout sous une
// forme illisible. Un utilisateur lisant « aucun enregistrement » sur une zone
// qui en contenait pouvait en conclure que sa zone était vide.
//
// La reconstruction sur le module display supprime le writer intermédiaire :
// il n'y a plus de second canal où la sortie puisse se perdre.
func DisplayZoneRecords(records []dnsstorage.ZoneRecord, zone string) string {
	if len(records) == 0 {
		return "Zone " + zone + " : aucun enregistrement.\n"
	}

	tri := make([]dnsstorage.ZoneRecord, len(records))
	copy(tri, records)
	sort.Slice(tri, func(i, j int) bool {
		if tri[i].Name != tri[j].Name {
			return tri[i].Name < tri[j].Name
		}
		if tri[i].Type != tri[j].Type {
			return tri[i].Type < tri[j].Type
		}
		return tri[i].ID < tri[j].ID
	})

	tb := display.NouvelleTable("ID", "Nom", "Type", "TTL", "Données", "Priorité")
	for _, r := range tri {
		tb.Ajouter(
			strconv.FormatInt(r.ID, 10),
			display.Valeur(r.Name),
			display.Valeur(r.Type),
			strconv.Itoa(r.TTL),
			display.Valeur(r.Data),
			priorite(r),
		)
	}

	return "Zone " + zone + " (" + pluriel(len(tri)) + ")\n\n" + tb.String()
}

// priorite rend la priorité d'un enregistrement.
//
// `Priority` est un sql.NullInt64 et non un entier : la distinction porte du
// sens. Un enregistrement A n'a pas de priorité — la colonne est NULL — tandis
// qu'un MX de priorité 0 en a une, et c'est la plus haute. Afficher « 0 » dans
// les deux cas confondrait « sans objet » avec « prioritaire ».
func priorite(r dnsstorage.ZoneRecord) string {
	if !r.Priority.Valid {
		return "—"
	}
	return strconv.FormatInt(r.Priority.Int64, 10)
}
