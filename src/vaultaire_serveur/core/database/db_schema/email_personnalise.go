package dbschema

import (
	"database/sql"

	"vaultaire/core/database/schematools"
)

// L'adresse e-mail choisie — TO-DO 271.
//
// users.email_personnalise dit QUI a écrit l'adresse :
//
//   - 0, l'adresse est AUTOMATIQUE (« compte@domaine », posée à la création) :
//     elle suit le compte quand il est renommé ;
//   - 1, quelqu'un l'a CHOISIE (`create … --email`, `update -u … --email`,
//     portail, API) : plus rien ne la réécrit, sauf un nouveau choix ou un
//     retour explicite à l'automatique (`--email auto`).
//
// Sans ce drapeau, rien ne distinguerait une adresse choisie d'une adresse
// déduite, et le premier renommage écraserait la première.
//
// DEFAULT 0 : les comptes existants gardent le comportement qu'ils avaient.

// EnsureEmailPersonnalise pose la colonne si elle manque.
func EnsureEmailPersonnalise(db *sql.DB) error {
	return schematools.EnsureColumn(db, "annuaire", "users", "email_personnalise",
		"TINYINT(1) NOT NULL DEFAULT 0")
}
