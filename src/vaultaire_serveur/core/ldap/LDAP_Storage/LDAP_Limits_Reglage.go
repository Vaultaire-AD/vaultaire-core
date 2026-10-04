package ldapstorage

import (
	"fmt"
	"sort"
	"strings"
)

// Le réglage des bornes depuis `serveur_conf.yaml` — TO-DO 152.
//
// # Ce qui manquait
//
// LDAP_Limits.go annonçait des variables « destinées à être relues depuis la
// configuration au démarrage ». Deux l'étaient. Les sept bornes de recherche
// et de pagination ne l'étaient pas : les changer demandait de recompiler.
//
// # Pourquoi chaque borne a un PLANCHER
//
// Dans le code, zéro ou une valeur négative DÉSACTIVE une borne — c'est ainsi
// que les tests s'en affranchissent. Laisser passer cette convention jusqu'au
// fichier de configuration ferait d'une faute de frappe un retrait de
// protection : `max_search_entries: 0` saisi pour « la valeur par défaut »
// donnerait un serveur qui rend l'annuaire entier en une réponse, et
// `max_paged_entries_held: 0` un serveur dont la mémoire n'est plus bornée.
//
// Aucune borne ne se désactive donc depuis le fichier. Qui veut « sans
// limite » écrit un grand nombre, en sachant lequel.
//
// # Pourquoi un plafond aussi
//
// Pour la même raison, dans l'autre sens : `max_page_size: 10000000` n'est pas
// un réglage, c'est l'absence de réglage écrite autrement. Les plafonds sont
// larges — ils arrêtent l'ordre de grandeur aberrant, pas l'exploitant qui sait
// ce qu'il fait.
//
// # Une valeur refusée ARRÊTE le démarrage
//
// Elle n'est ni corrigée ni ignorée. Le serveur tournerait sinon avec une
// borne différente de celle écrite dans son fichier, et rien ne le dirait
// ailleurs que dans une ligne de journal du démarrage — lue une fois, par
// quelqu'un qui regarde si le service monte.

// borneReglable décrit une borne : sa clé dans `ldap.limites`, la variable
// qu'elle règle, et l'intervalle admis.
type borneReglable struct {
	cle      string
	cible    *int
	min, max int
	unite    string
}

// bornesReglables est LA liste des clés de `ldap.limites`.
//
// Les clés sont le nom de la variable Go, en minuscules soulignées : le nom
// qu'on lit dans un message du journal (« plafond MaxPagedEntriesHeld ») se
// retrouve tel quel dans le fichier.
func bornesReglables() []borneReglable {
	return []borneReglable{
		{"max_search_entries", &MaxSearchEntries, 1, 1_000_000, "entrées"},
		{"max_search_duration_seconds", &MaxSearchDurationSeconds, 1, 3600, "secondes"},
		{"max_page_size", &MaxPageSize, 1, 100_000, "entrées"},
		{"max_paged_search_entries", &MaxPagedSearchEntries, 1, 10_000_000, "entrées"},
		{"max_paged_entries_held", &MaxPagedEntriesHeld, 1, 50_000_000, "entrées"},
		{"max_paged_cursors_per_connection", &MaxPagedCursorsPerConnection, 1, 64, "recherches"},
		{"paged_cursor_ttl_seconds", &PagedCursorTTLSeconds, 10, 86_400, "secondes"},
	}
}

// ClesDesLimites rend les clés admises dans `ldap.limites`, triées.
func ClesDesLimites() []string {
	bornes := bornesReglables()
	cles := make([]string, len(bornes))
	for i, b := range bornes {
		cles[i] = b.cle
	}
	sort.Strings(cles)
	return cles
}

// AppliquerLimites règle les bornes à partir de la section `ldap.limites`.
//
// TOUT OU RIEN : les valeurs sont d'abord toutes vérifiées, seules et entre
// elles, et ne sont posées que si l'ensemble est cohérent. Une erreur ne laisse
// donc jamais le serveur avec la moitié d'un réglage.
//
// Une clé absente garde sa valeur. Une clé INCONNUE est une erreur, et non une
// ligne ignorée : `max_page_sizes` ne réglerait rien, et l'exploitant lirait
// dans son fichier une borne qui n'existe pas.
func AppliquerLimites(valeurs map[string]int) error {
	bornes := bornesReglables()
	connues := make(map[string]borneReglable, len(bornes))
	for _, b := range bornes {
		connues[b.cle] = b
	}

	// Les clés sont parcourues triées : deux démarrages sur le même fichier
	// fautif doivent rendre le même message.
	cles := make([]string, 0, len(valeurs))
	for cle := range valeurs {
		cles = append(cles, cle)
	}
	sort.Strings(cles)

	futures := make(map[string]int, len(bornes))
	for _, b := range bornes {
		futures[b.cle] = *b.cible
	}
	for _, cle := range cles {
		b, connue := connues[cle]
		if !connue {
			return fmt.Errorf("ldap.limites.%s : clé inconnue (clés admises : %s)",
				cle, strings.Join(ClesDesLimites(), ", "))
		}
		v := valeurs[cle]
		if v < b.min || v > b.max {
			return fmt.Errorf("ldap.limites.%s : %d refusé, attendu de %d à %d %s — "+
				"une borne ne se désactive pas depuis le fichier", cle, v, b.min, b.max, b.unite)
		}
		futures[cle] = v
	}

	// Les bornes ENTRE ELLES.
	//
	// La pagination existe pour lire au-delà de la borne d'une recherche
	// ordinaire : une borne paginée plus basse ferait rendre MOINS à qui pagine.
	if futures["max_paged_search_entries"] < futures["max_search_entries"] {
		return fmt.Errorf("ldap.limites : max_paged_search_entries (%d) est inférieur à "+
			"max_search_entries (%d) — paginer rendrait moins qu'une recherche ordinaire",
			futures["max_paged_search_entries"], futures["max_search_entries"])
	}
	// Une recherche paginée tient son reste en mémoire entre deux pages. Si le
	// plafond de ce qui est tenu est plus bas que ce qu'une seule recherche
	// peut rendre, la plus grande recherche permise est refusée (`busy`) à tout
	// coup — une borne que l'autre rend inatteignable.
	if futures["max_paged_entries_held"] < futures["max_paged_search_entries"] {
		return fmt.Errorf("ldap.limites : max_paged_entries_held (%d) est inférieur à "+
			"max_paged_search_entries (%d) — la plus grande recherche paginée permise "+
			"serait toujours refusée", futures["max_paged_entries_held"],
			futures["max_paged_search_entries"])
	}
	// Une page plus grande que ce qu'une recherche paginée peut rendre en tout
	// n'a pas de sens ; ce n'est pas dangereux, c'est une saisie inversée.
	if futures["max_page_size"] > futures["max_paged_search_entries"] {
		return fmt.Errorf("ldap.limites : max_page_size (%d) dépasse max_paged_search_entries (%d)",
			futures["max_page_size"], futures["max_paged_search_entries"])
	}

	for _, b := range bornes {
		*b.cible = futures[b.cle]
	}
	return nil
}

// LimitesEnVigueur rend les bornes sous la forme « clé=valeur », dans l'ordre
// de la documentation. Pour la ligne de démarrage.
func LimitesEnVigueur() string {
	bornes := bornesReglables()
	parties := make([]string, len(bornes))
	for i, b := range bornes {
		parties[i] = fmt.Sprintf("%s=%d", b.cle, *b.cible)
	}
	return strings.Join(parties, " ")
}
