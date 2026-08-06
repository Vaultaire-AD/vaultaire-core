package dbclients

import (
	"database/sql"
	"fmt"
	"vaultaire/core/database"
)

// Update_Client_Software_PublicKey enregistre la clé publique d'un client.
//
// # Pourquoi la clé arrive après la création
//
// L'enrôlement crée le client dès 01_05, à la validation de la clé
// d'enrôlement — avant que le service n'ait envoyé sa clé publique, qui vient en
// 01_07. Entre les deux, la ligne existe avec une clé vide.
//
// C'est la conséquence assumée d'un flux qui laisse le service générer sa paire
// APRÈS avoir appris son identifiant. Un client sans clé publique ne peut rien
// faire : la poignée de main 01_01 lui répondrait un chiffré illisible. La
// fenêtre est donc inerte, pas dangereuse.
func Update_Client_Software_PublicKey(db *sql.DB, computeurID, publicKey string) error {
	if injection := database.SanitizeIdentifier(computeurID); injection != nil {
		return injection
	}
	res, err := db.Exec(
		`UPDATE id_logiciels SET public_key = ? WHERE computeur_id = ?`,
		publicKey, computeurID)
	if err != nil {
		return fmt.Errorf("mise à jour de la clé publique de %s : %w", computeurID, err)
	}
	// RowsAffected vaut 0 si l'identifiant n'existe pas, MAIS AUSSI si la clé
	// enregistrée était déjà identique. Seul le premier cas est une erreur, d'où
	// la vérification d'existence plutôt qu'un test sur le compteur.
	if n, _ := res.RowsAffected(); n == 0 {
		var exists bool
		if err := db.QueryRow(
			`SELECT EXISTS(SELECT 1 FROM id_logiciels WHERE computeur_id = ?)`,
			computeurID).Scan(&exists); err != nil {
			return fmt.Errorf("vérification de l'existence de %s : %w", computeurID, err)
		}
		if !exists {
			return fmt.Errorf("client %s inconnu", computeurID)
		}
	}
	return nil
}
