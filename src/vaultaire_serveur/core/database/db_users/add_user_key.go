package dbusers

import (
	"fmt"
	"strings"
	"vaultaire/core/database"
)

// MaxClesParCompte borne le nombre de clés publiques SSH d'un compte.
const MaxClesParCompte = 10

// LongueurMaxCle borne la longueur d'une clé publique, commentaire compris.
// Une clé RSA de 16384 bits, la plus longue qu'OpenSSH produise, tient en
// moins de 2 900 caractères.
const LongueurMaxCle = 4096

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
//
// # Deux bornes, et pourquoi (TO-DO 101)
//
// Toutes les clés d'un compte partent dans UNE trame, la 02_04, à chaque
// authentification Ducky sur un poste. Une trame Ducky ne peut pas dépasser
// 65535 octets. Sans borne, n'importe quel utilisateur pouvait, depuis sa page
// de profil, garnir son compte jusqu'à rendre cette trame impossible à émettre.
//
// MaxClesParCompte × LongueurMaxCle tient dans une trame, chiffrement et base64
// compris, avec de la marge : c'est vérifié par
// TestLesClesDUnCompteTiennentDansUneTrame, qui échouera si l'une des deux
// bornes est relevée sans l'autre.
func AddUserKey(userID int, publicKey, label string) error {
	db := database.GetDatabase()

	if len(publicKey) > LongueurMaxCle {
		return fmt.Errorf("clé publique de %d caractères : au-delà de %d, elle ne serait pas transmise aux postes",
			len(publicKey), LongueurMaxCle)
	}
	var nombre int
	if err := db.QueryRow("SELECT COUNT(*) FROM user_public_keys WHERE id_user = ?", userID).Scan(&nombre); err != nil {
		return fmt.Errorf("ajout de la clé publique impossible : comptage des clés existantes : %v", err)
	}
	if nombre >= MaxClesParCompte {
		return fmt.Errorf(
			"ce compte a déjà %d clés publiques, le maximum : retirez-en une avant d'en ajouter une autre. "+
				"Toutes les clés d'un compte sont envoyées aux postes à chaque connexion, et le message qui les porte a une taille bornée",
			nombre)
	}

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
