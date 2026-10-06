package dbschema

import (
	"database/sql"
	"fmt"

	"vaultaire/core/database/schematools"
	"vaultaire/core/logs"
)

// Unicité de `did_login` sur le couple (compte, machine) — TO-DO 107.
//
// # Ce que l'absence de contrainte produisait
//
// `did_login` vaut « une ligne = une session Ducky », et `status -c` la lit pour
// énumérer les machines connectées. Son unicité était tenue par le CODE :
// `AddLoginEntry` faisait `SELECT EXISTS` puis `INSERT`, `RafraichirConnexion`
// faisait `COUNT(*)` puis `UPDATE`.
//
// Deux séquences lecture-puis-écriture, donc deux courses. Deux
// authentifications simultanées de la même paire y trouvent toutes les deux
// « la ligne n'existe pas » et insèrent chacune la leur : la machine apparaît
// DEUX FOIS dans `status -c`.
//
// Ce n'est pas théorique. Le `--fetch-key` de sshd ouvre une session à chaque
// connexion SSH, en parallèle du tunnel permanent : la fenêtre s'ouvre en
// fonctionnement normal, sans que personne ne cherche à la provoquer.
//
// C'est exactement le doublon que le point 92 a fermé pour les sessions PAM, par
// une autre porte — et par une course, donc intermittent et difficile à imputer.
//
// # Pourquoi la base, et pas mieux de code
//
// `user_sessions` porte déjà son unicité en base, et le commentaire de son
// schéma souligne la différence sans la corriger. Une garantie tenue par deux
// fonctions dans deux fichiers est une garantie qu'on croit avoir ; la même
// posée par la base est une garantie qu'on a.
//
// # L'ordre : dédoublonner PUIS contraindre
//
// `ALTER TABLE … ADD UNIQUE KEY` échoue si la table porte déjà des doublons —
// c'est-à-dire précisément sur les bases qui en ont besoin. On les retire donc
// d'abord, et l'échec de cette étape ARRÊTE la migration : poser la contrainte
// sur une table qu'on n'a pas pu nettoyer ne peut que rater, et réessayer à
// chaque démarrage remplirait le journal d'une erreur qu'on ne sait pas lire.

const (
	tableDidLogin     = "did_login"
	indexDidLoginUniq = "uq_did_login"
)

// EnsureDidLoginUnicite dédoublonne `did_login` puis pose l'unicité.
//
// Idempotente : l'index est inspecté avant d'être posé, et le dédoublonnage ne
// trouve rien à faire sur une base saine.
func EnsureDidLoginUnicite(db *sql.DB) error {
	retirees, err := dedoublonnerDidLogin(db)
	if err != nil {
		return err
	}
	if retirees > 0 {
		logs.Write_Log("WARNING", fmt.Sprintf(
			"sessions: %d ligne(s) de did_login en double retirée(s) avant la pose de "+
				"l'unicité (compte, machine) — ces machines apparaissaient plusieurs fois "+
				"dans « status -c »", retirees))
	}

	return schematools.EnsureUniqueIndex(db, "sessions",
		tableDidLogin, indexDidLoginUniq, "d_id_user", "d_id_logiciel")
}

// dedoublonnerDidLogin garde UNE ligne par couple (compte, machine).
//
// # Laquelle on garde
//
// Celle dont l'identifiant est le plus grand, c'est-à-dire la dernière insérée.
// C'est aussi celle qui porte la clé de session la plus récente : garder une
// ancienne ferait échouer la prochaine tentative de rafraîchissement, qui la
// cherche par sa clé.
//
// La colonne d'échéance aurait semblé plus naturelle, mais deux lignes créées
// dans la même seconde la portent identique — et c'est exactement le cas qui
// produit le doublon.
func dedoublonnerDidLogin(db *sql.DB) (int64, error) {
	if db == nil {
		return 0, fmt.Errorf("sessions: connexion base indisponible")
	}

	// Sous-requête nommée : MySQL refuse de lire la table qu'il modifie dans
	// une sous-requête directe (erreur 1093). L'alias force la matérialisation.
	res, err := db.Exec(`
		DELETE FROM did_login
		 WHERE id_login NOT IN (
		       SELECT id_garde FROM (
		              SELECT MAX(id_login) AS id_garde
		                FROM did_login
		            GROUP BY d_id_user, d_id_logiciel
		       ) AS derniers
		 )`)
	if err != nil {
		logs.Write_LogCode("ERROR", logs.CodeDBQuery,
			"sessions: dédoublonnage de did_login échoué : "+err.Error())
		return 0, fmt.Errorf("dédoublonnage de did_login : %w", err)
	}

	n, _ := res.RowsAffected()
	return n, nil
}
