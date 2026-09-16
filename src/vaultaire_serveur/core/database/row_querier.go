package database

import (
	"database/sql"
)

// RowQuerier couvre *sql.DB ET *sql.Tx.
//
// Plusieurs appelants ouvrent une transaction avant de résoudre un identifiant.
// Un helper qui n'accepterait que *sql.DB lirait HORS de cette transaction : sur
// une lecture de clé primaire c'est aujourd'hui sans conséquence, mais le jour
// où la résolution suit une écriture dans la même transaction, elle ne verrait
// pas cette écriture. Le paramètre est une interface pour que la question ne se
// pose jamais.
type RowQuerier interface {
	QueryRow(query string, args ...any) *sql.Row
}
