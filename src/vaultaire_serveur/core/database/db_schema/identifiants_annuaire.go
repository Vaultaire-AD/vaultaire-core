package dbschema

import (
	"database/sql"
	"fmt"

	"vaultaire/core/database/schematools"
	"vaultaire/core/identifiant"
	"vaultaire/core/logs"
)

// L'identifiant stable des entrées de l'annuaire — point 129.
//
// # Ce qui manquait
//
// L'annuaire servait `entryUUID` — et ses variantes `objectGUID`, `nsUniqueId`,
// `ipaUniqueID` — avec pour valeur le NOM du compte. Ce n'était donc pas un
// identifiant : renommer un compte le faisait apparaître comme un compte neuf
// chez tout client qui s'y fie. Keycloak créait un doublon au lieu de renommer.
//
// Un identifiant d'entrée doit survivre au renommage. Il lui faut donc une
// colonne à lui, posée à la création de la ligne et jamais réattribuée.
//
// # Pourquoi les groupes aussi
//
// La RFC 4530 attend un `entryUUID` sur toute entrée, et un client qui tient un
// cache des groupes — Nextcloud — cherche le même attribut qu'il emploie pour
// les comptes. Un groupe ne se renomme pas aujourd'hui ; mais un groupe supprimé
// puis recréé sous le même nom est un AUTRE groupe, et c'est ce que
// l'identifiant permet enfin de voir.
const (
	// ColonneIdentifiant porte l'UUID, en texte canonique (36 caractères).
	ColonneIdentifiant = "entry_uuid"

	// NULL permis, et c'est voulu : la colonne est ajoutée VIDE sur une base en
	// service, puis remplie ligne à ligne. Une valeur par défaut commune à
	// toutes les lignes interdirait l'index unique ; une expression par défaut
	// (`DEFAULT (UUID())`) lierait le schéma à une version du moteur.
	//
	// L'unicité, elle, tient malgré les NULL : un index unique en admet autant
	// qu'on veut.
	DefinitionIdentifiant = "CHAR(36) NULL DEFAULT NULL"
)

// tablesIdentifiees liste les tables dont chaque ligne est une entrée de
// l'annuaire. Les noms sont des constantes du code : ils entrent dans le texte
// des requêtes, où un paramètre lié n'est pas permis.
var tablesIdentifiees = []struct {
	Table, Cle, Index string
}{
	{"users", "id_user", "uniq_users_entry_uuid"},
	{"groups", "id_group", "uniq_groups_entry_uuid"},
}

// EnsureIdentifiantsAnnuaire pose la colonne, donne un identifiant à chaque
// ligne qui n'en a pas, puis pose l'index unique.
//
// # L'ordre n'est pas libre
//
// La colonne d'abord, l'index EN DERNIER : il ne coûte rien sur des NULL, mais
// le poser après le remplissage garantit que ce qu'il protège est déjà juste.
//
// # Ce que la migration fait aux lignes déjà là
//
// Chaque compte et chaque groupe reçoit un UUID tiré au hasard. Il n'y avait
// rien à préserver : l'ancienne valeur était le nom, qui n'est pas un UUID et
// qu'aucune syntaxe d'UUID n'accepte.
//
// La conséquence est à connaître, et elle n'arrive qu'UNE fois : un client déjà
// synchronisé voit l'identifiant de chaque entrée changer. Pour Keycloak, les
// comptes importés sont à resynchroniser — voir
// docs/exploitation/ldaps_keycloak.md. Ensuite l'identifiant ne bouge plus,
// renommage compris, et c'est ce qu'on achète.
//
// La date de modification bouge avec l'identifiant (ON UPDATE CURRENT_TIMESTAMP)
// et ce n'est PAS neutralisé : l'entrée a réellement changé, et un client
// incrémental doit la relire pour apprendre son nouvel identifiant.
//
// # Elle tourne à CHAQUE démarrage
//
// Pas seulement à la mise à jour : les deux lignes initiales (`vaultaire`, son
// groupe) sont insérées par le texte du schéma, qui ne sait pas tirer un UUID,
// et reçoivent le leur ici. C'est aussi le filet d'une insertion qui aurait
// oublié la colonne — un test interdit cet oubli, celui-ci le répare.
//
// # Deux cores qui démarrent ensemble
//
// Chacun peut tirer un UUID pour la même ligne. L'écriture est conditionnée à
// « toujours vide » : le premier arrivé gagne, le second ne change rien.
//
// FATALE pour l'appelant, pour la raison des horodatages : les requêtes de
// lecture LDAP nomment cette colonne.
func EnsureIdentifiantsAnnuaire(db *sql.DB) error {
	if db == nil {
		return fmt.Errorf("connexion base indisponible")
	}

	for _, t := range tablesIdentifiees {
		// Relevé AVANT d'ajouter la colonne : c'est ce qui distingue la mise à
		// jour d'une base en service du démarrage ordinaire, où seules les lignes
		// initiales attendent leur identifiant.
		dejaLa, err := colonneExiste(db, t.Table, ColonneIdentifiant)
		if err != nil {
			return fmt.Errorf("%s.%s : %w", t.Table, ColonneIdentifiant, err)
		}
		if err := schematools.EnsureColumn(db, "annuaire", t.Table, ColonneIdentifiant, DefinitionIdentifiant); err != nil {
			return fmt.Errorf("%s.%s : %w", t.Table, ColonneIdentifiant, err)
		}
		attribues, err := attribuerIdentifiants(db, t.Table, t.Cle)
		if err != nil {
			return fmt.Errorf("%s : %w", t.Table, err)
		}
		if attribues > 0 {
			logs.Write_Log("INFO", fmt.Sprintf(
				"annuaire: %d ligne(s) de %s ont reçu leur identifiant stable (entryUUID)",
				attribues, t.Table))
		}
		// L'avertissement ne part qu'à la MIGRATION : colonne neuve, sur une table
		// qui portait déjà autre chose que sa ligne initiale. Sur une
		// installation neuve il n'y a aucun client à prévenir, et l'écrire à
		// chaque première mise en route apprendrait à l'ignorer.
		if !dejaLa && attribues > 1 {
			logs.Write_Log("WARNING", fmt.Sprintf(
				"annuaire: mise à jour — les %d entrées de %s changent d'identifiant LDAP (entryUUID), UNE fois. "+
					"Un client déjà synchronisé (Keycloak, Nextcloud) est à resynchroniser : "+
					"voir docs/exploitation/ldaps_keycloak.md", attribues, t.Table))
		}
		if err := schematools.EnsureUniqueIndex(db, "annuaire", t.Table, t.Index, ColonneIdentifiant); err != nil {
			return fmt.Errorf("%s.%s : %w", t.Table, t.Index, err)
		}
	}

	logs.Write_Log("DEBUG", "database: identifiants de l'annuaire en place (users, groups)")
	return nil
}

// colonneExiste dit si la colonne est déjà dans la table.
func colonneExiste(db *sql.DB, table, colonne string) (bool, error) {
	var n int
	err := db.QueryRow(`SELECT COUNT(*) FROM information_schema.COLUMNS
		WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ? AND COLUMN_NAME = ?`,
		table, colonne).Scan(&n)
	if err != nil {
		return false, fmt.Errorf("inspection de la colonne : %w", err)
	}
	return n > 0, nil
}

// attribuerIdentifiants donne un UUID à chaque ligne qui n'en a pas.
//
// Les identifiants sont tirés ICI, en Go, et non par la fonction UUID() du
// moteur : elle rend des UUID de version 1, qui portent l'adresse matérielle du
// serveur de base et l'heure — deux choses qu'un identifiant diffusé à tous les
// clients de l'annuaire n'a pas à révéler.
func attribuerIdentifiants(db *sql.DB, table, cle string) (int, error) {
	rows, err := db.Query("SELECT `" + cle + "` FROM `" + table + "` WHERE `" +
		ColonneIdentifiant + "` IS NULL OR `" + ColonneIdentifiant + "` = ''")
	if err != nil {
		return 0, fmt.Errorf("recherche des lignes sans identifiant : %w", err)
	}
	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return 0, fmt.Errorf("lecture d'une ligne sans identifiant : %w", err)
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return 0, fmt.Errorf("parcours des lignes sans identifiant : %w", err)
	}
	rows.Close()

	if len(ids) == 0 {
		return 0, nil
	}

	// Conditionnée à « toujours vide » : voir « deux cores » plus haut.
	ecrire := "UPDATE `" + table + "` SET `" + ColonneIdentifiant + "` = ? WHERE `" + cle +
		"` = ? AND (`" + ColonneIdentifiant + "` IS NULL OR `" + ColonneIdentifiant + "` = '')"

	// Par lots, chacun dans une transaction : une écriture validée seule coûte
	// une synchronisation du journal de la base, et dix mille comptes en
	// coûteraient dix mille. Le lot borne aussi ce qu'une transaction retient.
	const tailleLot = 500
	attribues := 0
	for debut := 0; debut < len(ids); debut += tailleLot {
		fin := debut + tailleLot
		if fin > len(ids) {
			fin = len(ids)
		}
		n, err := attribuerLot(db, ecrire, ids[debut:fin])
		attribues += n
		if err != nil {
			return attribues, err
		}
	}
	return attribues, nil
}

// attribuerLot écrit un lot d'identifiants dans une transaction.
func attribuerLot(db *sql.DB, ecrire string, ids []int64) (int, error) {
	tx, err := db.Begin()
	if err != nil {
		return 0, fmt.Errorf("ouverture de la transaction : %w", err)
	}
	attribues := 0
	for _, id := range ids {
		uuid, err := identifiant.NouvelUUID()
		if err != nil {
			_ = tx.Rollback()
			return 0, err
		}
		res, err := tx.Exec(ecrire, uuid, id)
		if err != nil {
			_ = tx.Rollback()
			return 0, fmt.Errorf("écriture de l'identifiant de la ligne %d : %w", id, err)
		}
		if n, err := res.RowsAffected(); err == nil && n > 0 {
			attribues++
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("validation du lot : %w", err)
	}
	return attribues, nil
}
