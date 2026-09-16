package dbusers

import (
	"fmt"
	"strings"
	"vaultaire/core/database"
)

// AddUserKey ajoute une nouvelle clé publique pour un utilisateur.
//
// UNE CLÉ N'APPARTIENT QU'À UN SEUL COMPTE. La contrainte `unique_pubkey` de
// user_public_keys est globale, pas par utilisateur, et c'est délibéré : l'API
// authentifie par signature SSH (voir core/api), donc une clé partagée entre
// deux comptes permettrait à son porteur d'agir sous l'une ou l'autre identité,
// au choix, à chaque requête. Le journal d'audit n'enregistrerait alors que le
// nom qu'il a bien voulu déclarer. Et révoquer une clé compromise obligerait à
// la chercher sur tous les comptes au lieu d'un seul.
//
// L'erreur brute de MySQL — « Error 1062 (23000): Duplicate entry 'ssh-rsa
// AAAAB3...' » — remontait telle quelle jusqu'à l'administrateur : illisible, et
// muette sur la seule information utile, à savoir QUEL compte détient déjà la
// clé. On la traduit.
func AddUserKey(userID int, publicKey, label string) error {
	db := database.GetDatabase()
	_, err := db.Exec("INSERT INTO user_public_keys (id_user, public_key, label) VALUES (?, ?, ?)", userID, publicKey, label)
	if err == nil {
		return nil
	}

	// La détection porte sur le texte de l'erreur plutôt que sur le type
	// *mysql.MySQLError : le pilote n'est importé qu'en effet de bord dans tout
	// le projet, et le remonter ici pour un seul message ferait entrer un
	// détail de pilote dans une couche qui n'en a pas besoin ailleurs.
	if strings.Contains(err.Error(), "1062") || strings.Contains(err.Error(), "Duplicate entry") {
		if owner, lookupErr := usernameHoldingKey(db, publicKey); lookupErr == nil && owner != "" {
			return fmt.Errorf(
				"cette clé publique est déjà enregistrée sur le compte %q — une clé n'appartient qu'à un seul compte, "+
					"sans quoi son porteur pourrait agir sous l'une ou l'autre identité sans que le journal permette de trancher. "+
					"Retirez-la de %q, ou générez une clé distincte pour ce compte", owner, owner)
		}
		return fmt.Errorf(
			"cette clé publique est déjà enregistrée sur un autre compte — une clé n'appartient qu'à un seul compte")
	}

	return fmt.Errorf("ajout de la clé publique impossible : %v", err)
}
