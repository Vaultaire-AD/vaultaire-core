package dbschema

import (
	"database/sql"
	"fmt"

	"vaultaire/core/database/schematools"
	"vaultaire/core/logs"
)

// Complément de schéma de `cluster_nodes` sur une base DÉJÀ créée.
//
// # Pourquoi ce fichier existe
//
// `owner_client_id` a été ajoutée au texte du CREATE TABLE. Sur une base neuve,
// cela suffit. Sur une base en service, la clause `IF NOT EXISTS` ne fait
// RIEN — elle ne compare pas les colonnes — et le core démarrait normalement
// pour échouer à la première requête qui nomme la colonne :
//
//	Error 1054 (42S22): Unknown column 'owner_client_id' in 'WHERE'
//
// Le message arrive loin du fichier de schéma, en exploitation, sur un chemin
// qui marchait la veille. Corriger à la main sur chaque base reviendrait à
// dépendre de ce que quelqu'un se souvienne de le faire.

// ColonneProprietaire porte le propriétaire d'une ligne de cluster_nodes.
//
// La définition est identique à celle du CREATE TABLE. Les deux doivent le
// rester : une base neuve prend l'une, une base existante l'autre, et une
// divergence produirait deux schémas selon l'âge de l'installation. Un test le
// vérifie.
const (
	TableNoeuds        = "cluster_nodes"
	ColonneProprietaire = "owner_client_id"
	DefinitionProprietaire = "VARCHAR(191) NOT NULL DEFAULT ''"
	IndexProprietaire  = "uk_owner"
)

// EnsureClusterNodesSchema complète cluster_nodes sur une base existante.
//
// # L'ordre des trois gestes n'est pas indifférent
//
//	1. la colonne, sinon rien de ce qui suit n'a de sens ;
//	2. la PURGE des lignes sans propriétaire ;
//	3. l'index UNIQUE, qui échouerait sur ces lignes.
//
// # Pourquoi purger, et pourquoi c'est sans danger ICI
//
// Les lignes antérieures à la colonne portent toutes la valeur par défaut, donc
// la même : l'index unique les refuserait. Il faut choisir entre leur inventer
// un propriétaire et les supprimer.
//
// Leur en inventer un serait faux — on ne sait pas à qui elles sont, et c'est
// précisément la question à laquelle la colonne répond. Les garder sans
// propriétaire serait pire : plus personne ne pourrait les mettre à jour, et
// elles resteraient annoncées aux agents en se périmant.
//
// `cluster_nodes` est de l'ÉTAT VIVANT, pas de la donnée : chaque core réécrit
// sa ligne au démarrage, chaque proxy et chaque service à sa reconnexion. La
// table se reconstruit seule en une poignée de secondes.
//
// Ce qui est réellement perdu tient en deux colonnes — `priorite` et
// `expose_aux_agents` —, les seules décisions d'exploitation de cette table. Le
// journal le dit explicitement, parce que personne n'ira le chercher.
func EnsureClusterNodesSchema(db *sql.DB) error {
	if db == nil {
		return fmt.Errorf("connexion base indisponible")
	}

	if err := schematools.EnsureColumn(db, "cluster",
		TableNoeuds, ColonneProprietaire, DefinitionProprietaire); err != nil {
		return err
	}

	res, err := db.Exec(
		"DELETE FROM `" + TableNoeuds + "` WHERE `" + ColonneProprietaire + "` = ''")
	if err != nil {
		return fmt.Errorf("purge des nœuds sans propriétaire : %w", err)
	}
	if n, _ := res.RowsAffected(); n > 0 {
		logs.Write_Log("WARNING", fmt.Sprintf(
			"cluster: %d nœud(s) antérieur(s) à la notion de propriétaire supprimé(s) — "+
				"ils se réenregistreront seuls au prochain battement. Une priorité ou un "+
				"retrait de rotation (expose_aux_agents) posé à la main sur ces lignes est "+
				"à refaire.", n))
	}

	return schematools.EnsureUniqueIndex(db, "cluster",
		TableNoeuds, IndexProprietaire, ColonneProprietaire)
}
