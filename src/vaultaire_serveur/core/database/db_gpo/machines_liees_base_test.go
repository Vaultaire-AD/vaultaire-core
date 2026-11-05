package dbgpo

import (
	"database/sql"
	"os"
	"strings"
	"testing"

	_ "github.com/go-sql-driver/mysql"
)

// Les machines d'une GPO, contre une VRAIE base — TO-DO 169. Sauté sans
// VAULTAIRE_TEST_DSN.
//
// Les quatre tables de la jointure sont créées TEMPORAIRES, sur une connexion
// unique : elles masquent celles qui existeraient déjà dans la base de test, et
// disparaissent avec la connexion. Seules les colonnes lues y figurent.
func TestEnBaseLesMachinesDUneGPOSontCellesDeSesGroupes(t *testing.T) {
	dsn := os.Getenv("VAULTAIRE_TEST_DSN")
	if dsn == "" {
		t.Skip("VAULTAIRE_TEST_DSN absent : pas de base de test MariaDB")
	}
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)

	for _, requete := range []string{
		`CREATE TEMPORARY TABLE gpo_group (d_id_gpo INT, d_id_group INT)`,
		`CREATE TEMPORARY TABLE logiciel_group (d_id_logiciel INT, d_id_group INT)`,
		`CREATE TEMPORARY TABLE id_logiciels (id_logiciel INT, computeur_id VARCHAR(255))`,
		`INSERT INTO id_logiciels VALUES (1, 'PC-B'), (2, 'PC-A'), (3, 'PC-C'), (4, 'PC-AILLEURS')`,
		// GPO 7 : liée aux groupes 10 et 11. GPO 8 : au groupe 12.
		`INSERT INTO gpo_group VALUES (7, 10), (7, 11), (8, 12)`,
		// PC-A est dans les DEUX groupes de la GPO 7.
		`INSERT INTO logiciel_group VALUES (1, 10), (2, 10), (2, 11), (3, 11), (4, 12)`,
	} {
		if _, err := db.Exec(requete); err != nil {
			t.Fatalf("%s : %v", requete, err)
		}
	}

	ids, err := MachinesLieesA(db, 7)
	if err != nil {
		t.Fatal(err)
	}
	// Triées, sans doublon, et sans la machine de l'autre GPO.
	if got := strings.Join(ids, ","); got != "PC-A,PC-B,PC-C" {
		t.Errorf("machines de la GPO 7 : %s — attendu PC-A,PC-B,PC-C", got)
	}
	if ids, err := MachinesLieesA(db, 99); err != nil || len(ids) != 0 {
		t.Errorf("GPO liée à aucun groupe : %v, %v", ids, err)
	}
	if _, err := MachinesLieesA(nil, 7); err == nil {
		t.Error("une base absente ne rend pas d'erreur")
	}
}
