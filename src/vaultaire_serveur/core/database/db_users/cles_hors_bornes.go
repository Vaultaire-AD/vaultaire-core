package dbusers

import (
	"database/sql"
	"fmt"
)

// CompteHorsBornes décrit un compte dont les clés SSH dépassent ce que
// AddUserKey accepte aujourd'hui.
type CompteHorsBornes struct {
	Utilisateur string
	// Cles est le nombre de clés du compte.
	Cles int
	// Caracteres est la somme de leurs longueurs : c'est elle, et non le
	// nombre, qui décide si la trame 02_04 part.
	Caracteres int
	// PlusLongue est la longueur de la plus longue.
	PlusLongue int
}

// Motif dit en quoi le compte dépasse.
func (c CompteHorsBornes) Motif() string {
	switch {
	case c.Cles > MaxClesParCompte && c.PlusLongue > LongueurMaxCle:
		return fmt.Sprintf("%d clés (maximum %d), dont une de %d caractères (maximum %d)",
			c.Cles, MaxClesParCompte, c.PlusLongue, LongueurMaxCle)
	case c.Cles > MaxClesParCompte:
		return fmt.Sprintf("%d clés (maximum %d)", c.Cles, MaxClesParCompte)
	default:
		return fmt.Sprintf("une clé de %d caractères (maximum %d)", c.PlusLongue, LongueurMaxCle)
	}
}

// ComptesHorsBornes rend les comptes qui portent plus de clés, ou des clés
// plus longues, que AddUserKey n'en laisse ajouter (TO-DO 138).
//
// # Pourquoi il peut y en avoir
//
// Les deux bornes datent de la 2.2 et ne valent qu'à l'AJOUT. Un compte garni
// avant elles garde tout ce qu'il avait — et c'est voulu : retirer une clé,
// c'est retirer un accès, et personne ne l'a décidé.
//
// # Ce que cela coûte
//
// Rien, tant que la trame 02_04 tient dans 65 535 octets une fois chiffrée.
// Au-delà elle n'est plus émise, et le compte ne peut plus ouvrir de session
// Ducky sur aucun poste. Ce relevé nomme les comptes AVANT que cela arrive :
// dépasser une borne n'est pas encore être refusé, c'est ne plus être garanti.
//
// La lecture est UNE requête, pas une par compte : elle tourne au démarrage du
// core, sur une table qui peut porter tout le parc.
func ComptesHorsBornes(db *sql.DB) ([]CompteHorsBornes, error) {
	rows, err := db.Query(`
		SELECT u.username, COUNT(*), COALESCE(SUM(CHAR_LENGTH(k.public_key)), 0),
		       COALESCE(MAX(CHAR_LENGTH(k.public_key)), 0)
		  FROM user_public_keys k
		  JOIN users u ON u.id_user = k.id_user
		 GROUP BY u.id_user, u.username
		HAVING COUNT(*) > ? OR MAX(CHAR_LENGTH(k.public_key)) > ?
		 ORDER BY u.username`, MaxClesParCompte, LongueurMaxCle)
	if err != nil {
		return nil, fmt.Errorf("relevé des comptes au-delà des bornes de clés SSH : %w", err)
	}
	defer rows.Close()

	var comptes []CompteHorsBornes
	for rows.Next() {
		var c CompteHorsBornes
		if err := rows.Scan(&c.Utilisateur, &c.Cles, &c.Caracteres, &c.PlusLongue); err != nil {
			return nil, fmt.Errorf("relevé des comptes au-delà des bornes de clés SSH : %w", err)
		}
		comptes = append(comptes, c)
	}
	// Une lecture interrompue rendrait une liste PARTIELLE présentée comme
	// complète — c'est-à-dire des comptes qu'on croirait sains.
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("relevé des comptes au-delà des bornes de clés SSH : %w", err)
	}
	return comptes, nil
}
