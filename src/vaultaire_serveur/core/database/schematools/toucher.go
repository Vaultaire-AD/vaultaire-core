package schematools

import (
	"database/sql"
	"fmt"

	"vaultaire/core/logs"
)

// Les tables de l'annuaire dont LDAP sert les horodatages, et la clé de chacune.
//
// Ici et pas dans `db_schema` : ces fonctions sont appelées depuis `db_groups`,
// et `db_schema` dépend déjà de lui. Un paquet bas comme celui-ci est le seul
// endroit d'où tout le monde peut appeler sans créer de cycle.
const (
	TableUtilisateurs = "users"
	TableGroupes      = "groups"

	// ColonneModifieLe est tenue par la base — `ON UPDATE CURRENT_TIMESTAMP` —
	// pour tout ce qui écrit la ligne. Ces fonctions servent au reste.
	ColonneModifieLe = "updated_at"
)

// ToucherLigne marque une entrée de l'annuaire comme modifiée — point 126.
//
// # Quand l'appeler
//
// Quand ce qui change n'est PAS une colonne de la ligne. En pratique : une
// appartenance. Ajouter un compte à un groupe écrit `users_group`, pas `users`
// ni `groups` — `ON UPDATE CURRENT_TIMESTAMP` ne voit donc rien, alors que les
// deux entrées LDAP ont changé : le compte a gagné un `memberOf`, le groupe un
// `member`.
//
// Sans cet appel, une synchronisation incrémentale ne verrait jamais un
// changement d'appartenance — c'est-à-dire précisément ce que les clients LDAP
// synchronisent.
//
// # Pourquoi l'erreur n'est pas remontée
//
// Une date de modification manquée dégrade une synchronisation. Faire échouer
// pour ce motif l'ajout au groupe, qui vient de réussir, échangerait un défaut
// discret contre une panne visible — et laisserait la base dans un état où
// l'appartenance existe mais l'appelant croit le contraire.
//
// La ligne de journal, elle, est indispensable : c'est la seule trace qu'une
// synchronisation risque de manquer ce changement.
func ToucherLigne(db *sql.DB, table string, id int) {
	if db == nil || id <= 0 {
		return
	}
	if !identifierPattern.MatchString(table) {
		logs.Write_Log("ERROR", "schematools: table refusée pour l'horodatage : "+table)
		return
	}

	// L'échec est journalisé, jamais remonté. La colonne EXISTE — la migration qui
	// la pose est fatale au démarrage, justement parce que les lectures LDAP la
	// nomment —, donc une erreur ici est autre chose : une base momentanément
	// indisponible, un verrou, une ligne supprimée entre-temps.
	requete := "UPDATE `" + table + "` SET `" + ColonneModifieLe +
		"` = CURRENT_TIMESTAMP WHERE " + cleDe(table) + " = ?"
	if _, err := db.Exec(requete, id); err != nil {
		logs.Write_Log("WARNING", fmt.Sprintf(
			"schematools: date de modification de %s #%d non mise à jour, une "+
				"synchronisation incrémentale peut manquer ce changement : %v", table, id, err))
	}
}

// cleDe rend le nom de la clé primaire d'une table de l'annuaire.
//
// Deux tables, deux conventions de nommage héritées : `id_user` et `id_group`.
// Les énumérer ici plutôt que de les passer en paramètre évite qu'un appelant se
// trompe de colonne — une mise à jour sur la mauvaise clé toucherait la mauvaise
// ligne, en silence.
func cleDe(table string) string {
	switch table {
	case TableGroupes:
		return "id_group"
	default:
		return "id_user"
	}
}

// ToucherVoisinsAvantSuppression marque comme modifiées les entrées qui perdront
// une appartenance quand `id` sera supprimé.
//
// # Le trou qu'elle ferme
//
// `ON DELETE CASCADE` vide `users_group` tout seul, ce qui est bien — mais
// silencieusement : les lignes des groupes et des comptes restants ne sont pas
// écrites, donc leur date de modification ne bouge pas. Un client qui synchronise
// en incrémental garde alors un `member` ou un `memberOf` FANTÔME, sans limite
// de temps : il ne relira jamais ces entrées, puisque rien ne dit qu'elles ont
// changé.
//
// C'est la même panne que celle des ajouts au groupe, à l'autre bout : ce sont
// les deux seuls moments où l'annuaire change sans qu'une ligne d'annuaire soit
// écrite.
//
// À appeler AVANT la suppression — après, la jointure ne rend plus rien.
func ToucherVoisinsAvantSuppression(db *sql.DB, table string, id int) {
	if db == nil || id <= 0 {
		return
	}

	var requete, tableVoisine string
	switch table {
	case TableUtilisateurs:
		// Les groupes dont ce compte est membre.
		requete = `SELECT d_id_group FROM users_group WHERE d_id_user = ?`
		tableVoisine = TableGroupes
	case TableGroupes:
		// Les comptes membres de ce groupe.
		requete = `SELECT d_id_user FROM users_group WHERE d_id_group = ?`
		tableVoisine = TableUtilisateurs
	default:
		logs.Write_Log("ERROR", "schematools: table sans voisins connue : "+table)
		return
	}

	rows, err := db.Query(requete, id)
	if err != nil {
		logs.Write_Log("WARNING", fmt.Sprintf(
			"schematools: voisins de %s #%d illisibles, leur date de modification ne "+
				"bougera pas et une synchronisation incrémentale gardera une "+
				"appartenance fantôme : %v", table, id, err))
		return
	}

	// Les identifiants sont rassemblés AVANT d'écrire : une écriture pendant qu'un
	// curseur est ouvert sur la même connexion est un piège classique de
	// database/sql, et il se manifeste en « busy buffer » sous charge.
	var voisins []int
	for rows.Next() {
		var voisin int
		if err := rows.Scan(&voisin); err != nil {
			logs.Write_Log("WARNING", "schematools: lecture d'un voisin : "+err.Error())
			continue
		}
		voisins = append(voisins, voisin)
	}
	if err := rows.Err(); err != nil {
		logs.Write_Log("WARNING", "schematools: parcours des voisins : "+err.Error())
	}
	if err := rows.Close(); err != nil {
		logs.Write_Log("DEBUG", "schematools: fermeture du curseur : "+err.Error())
	}

	for _, voisin := range voisins {
		ToucherLigne(db, tableVoisine, voisin)
	}
}
