package scope

import (
	"database/sql"
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	_ "github.com/go-sql-driver/mysql"

	"vaultaire/core/ldap/LDAP_SEARCH-REQUEST/newmodule/candidate"
)

// TO-DO 155, contre une VRAIE base : les recherches du constat, jouées par le
// résolveur lui-même.
//
// Sauté sans VAULTAIRE_TEST_DSN, donc en intégration continue. La base doit
// porter le schéma de l'annuaire tel qu'un core le pose — ce test n'en invente
// pas une copie, qui finirait par ne plus lui ressembler :
//
//	VAULTAIRE_TEST_DSN='vt:vt@tcp(127.0.0.1:3307)/vaultaire_e2e?parseTime=true' go test ./core/ldap/...
//
// Il n'y écrit que des noms qui lui sont propres, et les retire en sortant.
func baseDAnnuaire(t *testing.T) *sql.DB {
	t.Helper()
	dsn := os.Getenv("VAULTAIRE_TEST_DSN")
	if dsn == "" {
		t.Skip("VAULTAIRE_TEST_DSN absent : pas de base de test MariaDB")
	}
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if _, err := db.Exec(`SELECT u.entry_uuid, u.updated_at, g.entry_uuid, dg.domain_name
		FROM users u, groups g, domain_group dg, users_group ug LIMIT 0`); err != nil {
		t.Skipf("cette base ne porte pas le schéma de l'annuaire (%v) : viser une base préparée par un core", err)
	}
	return db
}

type annuaireDEssai struct {
	db                         *sql.DB
	racine, sous, cote         string
	equipe, dev, secrets, hors string
	alice, bob                 string
}

// monterLAnnuaire pose le cas du constat : alice a un groupe dans le domaine,
// deux dans un sous-domaine, et un dans un domaine voisin.
func monterLAnnuaire(t *testing.T, db *sql.DB) annuaireDEssai {
	t.Helper()
	n := fmt.Sprint(time.Now().UnixNano())
	a := annuaireDEssai{
		db:     db,
		racine: "t" + n + ".lan", sous: "dev.t" + n + ".lan", cote: "ops.t" + n + ".lan",
		equipe: "Equipe" + n, dev: "Dev" + n, secrets: "Secrets" + n, hors: "Astreinte" + n,
		alice: "alice" + n, bob: "bob" + n,
	}

	exec := func(requete string, args ...any) int64 {
		t.Helper()
		res, err := db.Exec(requete, args...)
		if err != nil {
			t.Fatalf("%s : %v", requete, err)
		}
		id, _ := res.LastInsertId()
		return id
	}
	utilisateur := func(nom string) int64 {
		return exec(`INSERT INTO users (username, firstname, lastname, email, password, salt)
			VALUES (?, 'Prenom', 'Nom', ?, 'x', 'x')`, nom, nom+"@essai.invalid")
	}
	groupe := func(nom, domaine string) int64 {
		id := exec(`INSERT INTO groups (group_name) VALUES (?)`, nom)
		exec(`INSERT INTO domain_group (d_id_group, domain_name) VALUES (?, ?)`, id, domaine)
		return id
	}

	idAlice, idBob := utilisateur(a.alice), utilisateur(a.bob)
	gEquipe, gDev := groupe(a.equipe, a.racine), groupe(a.dev, a.sous)
	gSecrets, gHors := groupe(a.secrets, a.sous), groupe(a.hors, a.cote)
	t.Cleanup(func() {
		_, _ = db.Exec(`DELETE FROM users WHERE id_user IN (?, ?)`, idAlice, idBob)
		_, _ = db.Exec(`DELETE FROM groups WHERE id_group IN (?, ?, ?, ?)`, gEquipe, gDev, gSecrets, gHors)
	})
	for _, g := range []int64{gEquipe, gDev, gSecrets, gHors} {
		exec(`INSERT INTO users_group (d_id_user, d_id_group) VALUES (?, ?)`, idAlice, g)
	}
	exec(`INSERT INTO users_group (d_id_user, d_id_group) VALUES (?, ?)`, idBob, gDev)
	return a
}

// dnRacine écrit un domaine comme le résolveur écrit ses DN.
func dnDe(domaine string) string {
	parties := strings.Split(domaine, ".")
	if len(parties) > 2 {
		parties = parties[len(parties)-2:]
	}
	return "dc=" + strings.Join(parties, ",dc=")
}

// memberOfDe joue une recherche et rend le memberOf du compte, tel que rendu.
func memberOfDe(t *testing.T, a annuaireDEssai, base string, scope int, baseObject, compte string) []string {
	t.Helper()
	entrees, err := Resolve(a.db, base, scope, nil, "", baseObject, nil)
	if err != nil {
		t.Fatalf("recherche scope=%d sur %s : %v", scope, base, err)
	}
	for _, e := range entrees {
		if u, ok := e.(candidate.UserEntry); ok && u.Uid == compte {
			out := make([]string, len(u.Groups))
			for i, g := range u.Groups {
				out[i] = g.DN + " [" + g.Domaine + "]"
			}
			return out
		}
	}
	t.Fatalf("recherche scope=%d sur %s : le compte %s n'est pas rendu (%d entrées)", scope, base, compte, len(entrees))
	return nil
}

// Le tableau du TO-DO : la même réponse, quelle que soit la base de la
// recherche — et dans le même ordre.
func TestEnBaseLeMemberOfNeDependPasDeLaBase(t *testing.T) {
	a := monterLAnnuaire(t, baseDAnnuaire(t))
	dnAlice := "uid=" + a.alice + ",ou=users," + dnDe(a.racine)

	parBase := memberOfDe(t, a, a.racine, 0, dnAlice, a.alice)
	recherches := map[string][]string{
		"sub sur le domaine":      memberOfDe(t, a, a.racine, 2, dnDe(a.racine), a.alice),
		"sub sur le sous-domaine": memberOfDe(t, a, a.sous, 2, dnDe(a.sous), a.alice),
		"one sur le sous-domaine": memberOfDe(t, a, a.sous, 1, dnDe(a.sous), a.alice),
		"sub sur le voisin":       memberOfDe(t, a, a.cote, 2, dnDe(a.cote), a.alice),
	}

	if len(parBase) != 4 {
		t.Fatalf("recherche base : %d groupe(s), attendu 4 : %v", len(parBase), parBase)
	}
	for nom, obtenu := range recherches {
		if strings.Join(obtenu, "|") != strings.Join(parBase, "|") {
			t.Errorf("%s ne rend pas le memberOf de la recherche base :\n  rendu   %v\n  attendu %v", nom, obtenu, parBase)
		}
	}

	// Le groupe du domaine PARENT, celui qui manquait.
	manque := true
	for _, g := range recherches["sub sur le sous-domaine"] {
		if strings.HasPrefix(g, "cn="+a.equipe+",") && strings.HasSuffix(g, "["+a.racine+"]") {
			manque = false
		}
	}
	if manque {
		t.Errorf("le groupe du domaine parent manque à la recherche sous le sous-domaine : %v",
			recherches["sub sur le sous-domaine"])
	}
}

// Un compte qui n'a de groupe que dans le sous-domaine ne gagne rien.
func TestEnBaseUnCompteNeGagneAucunGroupe(t *testing.T) {
	a := monterLAnnuaire(t, baseDAnnuaire(t))
	obtenu := memberOfDe(t, a, a.racine, 2, dnDe(a.racine), a.bob)
	if len(obtenu) != 1 || !strings.HasPrefix(obtenu[0], "cn="+a.dev+",") {
		t.Errorf("memberOf de bob = %v, attendu le seul groupe %s", obtenu, a.dev)
	}
}

// Les rattachements — ce qui décide du DROIT de lire le compte — ne changent
// pas : ils restent ceux du domaine cherché. Élargir memberOf ne doit pas
// élargir ce qui autorise.
func TestEnBaseLesRattachementsRestentCeuxDeLaRecherche(t *testing.T) {
	a := monterLAnnuaire(t, baseDAnnuaire(t))
	entrees, err := Resolve(a.db, a.sous, 2, nil, "", dnDe(a.sous), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entrees {
		u, ok := e.(candidate.UserEntry)
		if !ok || u.Uid != a.alice {
			continue
		}
		rattachements := append([]string(nil), u.Rattachements...)
		sort.Strings(rattachements)
		if len(rattachements) != 1 || rattachements[0] != a.sous {
			t.Errorf("rattachements d'alice sous %s = %v, attendu ce seul domaine", a.sous, rattachements)
		}
		return
	}
	t.Fatal("alice n'est pas rendue")
}
