package dbusers

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"

	dbdomains "vaultaire/core/database/db_domains"
	"vaultaire/core/logs"
)

// L'adresse e-mail d'un compte — TO-DO 271. Voir db_schema/email_personnalise.go
// pour le sens du drapeau.

// ErrEmailUtilise : l'adresse appartient déjà à un autre compte (la colonne
// est UNIQUE). Le message ne nomme PAS ce compte : un administrateur délégué
// d'un domaine apprendrait sinon qui, dans un autre, porte une adresse donnée.
var ErrEmailUtilise = errors.New("adresse déjà utilisée par un autre compte")

// requeteur : *sql.DB ou *sql.Tx.
type requeteur interface {
	QueryRow(query string, args ...any) *sql.Row
}

func lireEmail(q requeteur, userID int) (email string, personnalise bool, err error) {
	if err := q.QueryRow(`SELECT email, email_personnalise FROM users WHERE id_user = ?`, userID).
		Scan(&email, &personnalise); err != nil {
		logs.Write_LogCode("ERROR", logs.CodeDBQuery, "database: lecture de l'adresse du compte : "+err.Error())
		return "", false, fmt.Errorf("lecture de l'adresse du compte %d : %v", userID, err)
	}
	return email, personnalise, nil
}

// EmailUtiliseParAutre dit si l'adresse est portée par un autre compte que
// saufID (0 : aucun compte exclu, pour une création).
func EmailUtiliseParAutre(db *sql.DB, email string, saufID int) (bool, error) {
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM users WHERE email = ? AND id_user <> ?`, email, saufID).Scan(&n); err != nil {
		logs.Write_LogCode("ERROR", logs.CodeDBQuery, "database: contrôle d'unicité de l'adresse : "+err.Error())
		return false, fmt.Errorf("contrôle de l'adresse : %v", err)
	}
	return n > 0, nil
}

// AdresseAutomatique rend « compte@domaine » pour un retour à l'adresse
// automatique : le domaine est le PREMIER domaine des groupes du compte, en
// entier — c'est la forme de la création (create -u alice users.admin.local
// → alice@users.admin.local), pas les deux derniers labels.
//
// Un compte sans groupe n'a pas de domaine : l'erreur le dit, et invite à
// donner une adresse.
func AdresseAutomatique(db *sql.DB, userID int, username string) (string, error) {
	domaines, err := dbdomains.GetDomainsForUser(db, userID)
	if err != nil {
		return "", fmt.Errorf("lecture des domaines du compte : %v", err)
	}
	if len(domaines) == 0 {
		return "", fmt.Errorf("%s n'appartient à aucun groupe, donc à aucun domaine : "+
			"pas d'adresse automatique possible — donnez une adresse", username)
	}
	return username + "@" + strings.ToLower(domaines[0]), nil
}

// DefinirEmail écrit l'adresse et son drapeau. L'unicité est contrôlée avant,
// pour un message clair ; la contrainte de la base reste le dernier mot (deux
// écritures simultanées).
func DefinirEmail(db *sql.DB, userID int, email string, personnalise bool) error {
	pris, err := EmailUtiliseParAutre(db, email, userID)
	if err != nil {
		return err
	}
	if pris {
		return ErrEmailUtilise
	}
	if _, err := db.Exec(`UPDATE users SET email = ?, email_personnalise = ? WHERE id_user = ?`,
		email, personnalise, userID); err != nil {
		if strings.Contains(err.Error(), "Duplicate entry") {
			return ErrEmailUtilise
		}
		logs.Write_LogCode("ERROR", logs.CodeDBQuery, "database: écriture de l'adresse : "+err.Error())
		return fmt.Errorf("écriture de l'adresse : %v", err)
	}
	return nil
}
