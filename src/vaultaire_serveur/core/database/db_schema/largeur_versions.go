package dbschema

import (
	"database/sql"
	"fmt"

	"vaultaire/core/database/schematools"
)

// Colonnes de version élargies — TO-DO 264.
//
// # Le défaut
//
// La version écrite en base est celle que rend version.Complete() :
// « 2.3.0+g908b800 (2026-11-06) ». L'image de la release 2.3.0 a été construite
// avec le SHA complet et l'horodatage ISO, soit ~74 caractères, pour une
// colonne `version_code` de 50 : le core de l'image publiée ne pouvait pas
// inscrire sa ligne de nœud (« Error 1406 Data too long for column
// 'version_code' »), et un agent installé depuis elle aurait fait échouer
// l'inventaire de son poste (`agent_version`, 64).
//
// La CI construit de nouveau une identité courte. Les colonnes sont élargies
// en plus : un build fait à la main, ou une forme de version future, ne doit
// pas suffire à casser l'inscription d'un nœud.

// LargeurVersion est la largeur des colonnes qui portent une version.
const LargeurVersion = 128

// colonnesVersion : chaque définition est AUSSI dans le CREATE TABLE (même
// texte), pour qu'une base neuve et une base complétée aient le même schéma —
// voir TestLesVersionsSontDefiniesALIdentique.
var colonnesVersion = []struct{ Table, Nom, Definition string }{
	{TableNoeuds, "version_code", fmt.Sprintf("VARCHAR(%d) NOT NULL", LargeurVersion)},
	{TableNoeuds, "sdk_version", fmt.Sprintf("VARCHAR(%d) NOT NULL DEFAULT ''", LargeurVersion)},
	{"id_logiciels", "agent_version", fmt.Sprintf("VARCHAR(%d) NOT NULL DEFAULT ''", LargeurVersion)},
	{"id_logiciels", "sdk_version", fmt.Sprintf("VARCHAR(%d) NOT NULL DEFAULT ''", LargeurVersion)},
}

// EnsureLargeurVersions élargit les colonnes de version d'une base existante.
func EnsureLargeurVersions(db *sql.DB) error {
	if db == nil {
		return fmt.Errorf("connexion base indisponible")
	}
	for _, c := range colonnesVersion {
		if err := schematools.EnsureColumnWidth(db, "database", c.Table, c.Nom, LargeurVersion, c.Definition); err != nil {
			return err
		}
	}
	return nil
}
