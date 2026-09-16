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
	TableNoeuds            = "cluster_nodes"
	ColonneProprietaire    = "owner_client_id"
	DefinitionProprietaire = "VARCHAR(191) NOT NULL DEFAULT ''"
	IndexProprietaire      = "uk_owner"
)

// Colonnes d'EXPOSITION : par où les agents joignent le nœud.
//
// Distinctes d'`ip_address` et de `ducky_port`, qui sont ce que le nœud voit de
// lui-même. Un nœud derrière une redirection NAT ne peut pas connaître l'adresse
// par laquelle le parc l'atteint : il ne voit pas son infrastructure de
// l'extérieur. C'est une décision d'exploitation, au même titre que `priorite`.
//
// Vide et zéro valent « aucune déclaration » : ce sont alors l'adresse et le
// port du nœud qui sont servis, donc le comportement d'avant ces colonnes.
const (
	ColonneAdressePublique    = "adresse_publique"
	DefinitionAdressePublique = "VARCHAR(255) NOT NULL DEFAULT ''"
	ColonnePortPublic         = "port_public"
	DefinitionPortPublic      = "INT NOT NULL DEFAULT 0"
)

// colonnesAjoutees liste les colonnes posées après coup sur cluster_nodes.
//
// Une table, et non trois appels recopiés : c'est elle que parcourt le test qui
// vérifie que chaque colonne est définie à l'identique dans le CREATE TABLE.
// Écrite à la main, la liste du test finirait par ne plus couvrir la dernière
// colonne ajoutée — et ne le dirait pas.
var colonnesAjoutees = []struct{ Nom, Definition string }{
	{ColonneProprietaire, DefinitionProprietaire},
	{ColonneAdressePublique, DefinitionAdressePublique},
	{ColonnePortPublic, DefinitionPortPublic},
}

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

	// Le propriétaire D'ABORD, et seul : la purge et l'index qui suivent ne
	// portent que sur lui. Les colonnes d'exposition viennent après, une fois la
	// table dans son état définitif — les poser avant ferait les écrire sur des
	// lignes que la purge s'apprête à supprimer.
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

	if err := schematools.EnsureUniqueIndex(db, "cluster",
		TableNoeuds, IndexProprietaire, ColonneProprietaire); err != nil {
		return err
	}

	// Adresse et port d'exposition. Aucun index, aucune purge : deux nœuds
	// peuvent parfaitement partager une adresse publique — c'est même le cas
	// courant de deux services derrière la même redirection, distingués par le
	// port.
	if err := schematools.EnsureColumn(db, "cluster",
		TableNoeuds, ColonneAdressePublique, DefinitionAdressePublique); err != nil {
		return err
	}
	return schematools.EnsureColumn(db, "cluster",
		TableNoeuds, ColonnePortPublic, DefinitionPortPublic)
}
