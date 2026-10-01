package dbjournaux

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"vaultaire/core/logs"
)

// La lecture et la purge du journal commun.
//
// # La confrontation SQL / mémoire
//
// Le filtre existe deux fois : en SQL pour la base, en Go pour le repli sur la
// mémoire du core quand la base ne répond pas. Rien ne les oblige à
// concorder. S'ils divergent, le portail montre d'autres lignes selon que la
// base répond — c'est-à-dire que la même question change de réponse en plein
// incident. Les cas ci-dessous sont passés aux deux.

var reference = time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC)

type casFiltre struct {
	nom    string
	filtre Filtre
	// garde : l'entrée doit être rendue
	garde, ecarte logs.LogEntry
}

func ligne(niveau, core, code string, decalage time.Duration) logs.LogEntry {
	sev, _ := logs.SeveriteDe(niveau)
	return logs.LogEntry{Timestamp: reference.Add(decalage), Severity: sev,
		Level: niveau, Hostname: core, Code: code, Message: "m"}
}

var casFiltres = []casFiltre{
	{"seuil de niveau", Filtre{SeveriteMax: logs.SeverityWarning},
		ligne("ERROR", "c1", "", 0), ligne("INFO", "c1", "", 0)},
	{"le seuil garde son propre niveau", Filtre{SeveriteMax: logs.SeverityWarning},
		ligne("WARNING", "c1", "", 0), ligne("NOTICE", "c1", "", 0)},
	{"core émetteur", Filtre{SeveriteMax: -1, Core: "c2"},
		ligne("INFO", "c2", "", 0), ligne("INFO", "c1", "", 0)},
	{"code", Filtre{SeveriteMax: -1, Code: "VLT-DB001"},
		ligne("INFO", "c1", "VLT-DB001", 0), ligne("INFO", "c1", "VLT-DB002", 0)},
	{"depuis est inclus", Filtre{SeveriteMax: -1, Depuis: reference},
		ligne("INFO", "c1", "", 0), ligne("INFO", "c1", "", -time.Microsecond)},
	{"jusqu'à est exclu", Filtre{SeveriteMax: -1, Jusqua: reference},
		ligne("INFO", "c1", "", -time.Second), ligne("INFO", "c1", "", 0)},
}

// evaluerSQL rejoue la clause WHERE de requeteLecture sur une entrée.
//
// Une seconde expression de la règle, lue dans la requête produite : c'est la
// requête qu'on éprouve, pas le filtre Go qu'on recopierait.
func evaluerSQL(t *testing.T, f Filtre, e logs.LogEntry) bool {
	t.Helper()
	q, args := requeteLecture(f)
	where := ""
	if i := strings.Index(q, " WHERE "); i >= 0 {
		where = q[i+len(" WHERE ") : strings.Index(q, " ORDER BY ")]
	}
	if where == "" {
		return true
	}
	for i, cond := range strings.Split(where, " AND ") {
		a := args[i]
		var ok bool
		switch cond {
		case "severity <= ?":
			ok = e.Severity <= a.(int)
		case "core_name = ?":
			ok = e.Hostname == a.(string)
		case "code = ?":
			ok = e.Code == a.(string)
		case "created_at >= ?":
			ok = !e.Timestamp.Before(a.(time.Time))
		case "created_at < ?":
			ok = e.Timestamp.Before(a.(time.Time))
		default:
			t.Fatalf("condition inconnue du test : %q", cond)
		}
		if !ok {
			return false
		}
	}
	return true
}

func TestLeFiltreSQLEtLeFiltreMemoireConcordent(t *testing.T) {
	for _, c := range casFiltres {
		t.Run(c.nom, func(t *testing.T) {
			for _, cote := range []struct {
				nom   string
				garde func(logs.LogEntry) bool
			}{
				{"mémoire", c.filtre.Accepte},
				{"SQL", func(e logs.LogEntry) bool { return evaluerSQL(t, c.filtre, e) }},
			} {
				if !cote.garde(c.garde) {
					t.Errorf("%s : écarte une ligne qui aurait dû être rendue", cote.nom)
				}
				if cote.garde(c.ecarte) {
					t.Errorf("%s : rend une ligne qui aurait dû être écartée", cote.nom)
				}
			}
		})
	}
}

func TestSansFiltreAucuneCondition(t *testing.T) {
	q, args := requeteLecture(Filtre{SeveriteMax: -1})
	if strings.Contains(q, "WHERE") {
		t.Errorf("requête sans filtre porteuse d'une condition : %s", q)
	}
	if len(args) != 2 {
		t.Errorf("args = %v, attendu seulement LIMIT et OFFSET", args)
	}
}

func TestLaPageDemandeUneLigneTemoin(t *testing.T) {
	_, args := requeteLecture(Filtre{SeveriteMax: -1, Page: 3, ParPage: 20})
	limite, decalage := args[len(args)-2].(int), args[len(args)-1].(int)
	if limite != 21 || decalage != 40 {
		t.Fatalf("LIMIT %d OFFSET %d, attendu 21 et 40 : la page 3 de 20 commence "+
			"à la 41e ligne, et la 21e dit s'il y a une suite", limite, decalage)
	}
}

func TestLaPaginationEstBornee(t *testing.T) {
	f := Filtre{Page: -2, ParPage: 100000}.Normaliser()
	if f.Page != 1 || f.ParPage != ParPageMax {
		t.Fatalf("normalisé = page %d, %d par page", f.Page, f.ParPage)
	}
	if f := (Filtre{}).Normaliser(); f.ParPage != ParPageDefaut {
		t.Fatalf("par page par défaut = %d", f.ParPage)
	}
}

func TestLaMemoireSePagineCommeLaBase(t *testing.T) {
	var entrees []logs.LogEntry
	for i := 0; i < 7; i++ {
		e := ligne("INFO", "c1", "", -time.Duration(i)*time.Second)
		e.Message = fmt.Sprintf("n%d", i)
		entrees = append(entrees, e)
		// Une ligne écartée entre chaque : la pagination porte sur les lignes
		// RETENUES, pas sur la mémoire brute.
		entrees = append(entrees, ligne("DEBUG", "c1", "", 0))
	}

	f := Filtre{SeveriteMax: logs.SeverityInformational, ParPage: 3}
	p1 := PaginerEnMemoire(entrees, f)
	f.Page = 3
	p3 := PaginerEnMemoire(entrees, f)

	if len(p1.Lignes) != 3 || p1.Lignes[0].Message != "n0" || !p1.Suivante {
		t.Fatalf("page 1 = %+v", p1)
	}
	if len(p3.Lignes) != 1 || p3.Lignes[0].Message != "n6" || p3.Suivante {
		t.Fatalf("page 3 = %+v : la dernière page annoncerait une suite qui n'existe pas", p3)
	}
}

// --- purge -------------------------------------------------------------------

func remplacerPurge(t *testing.T, lots []int64, echecAu int) *int {
	t.Helper()
	appels := 0
	ancien, anciennePause := supprimerLot, pause
	supprimerLot = func(*sql.DB, time.Time) (int64, error) {
		appels++
		if appels == echecAu {
			return 0, errors.New("verrou")
		}
		if appels > len(lots) {
			return 0, nil
		}
		return lots[appels-1], nil
	}
	pause = func(time.Duration) {}
	t.Cleanup(func() { supprimerLot, pause = ancien, anciennePause })
	return &appels
}

func TestLaPurgeEnchaineLesLotsPleins(t *testing.T) {
	appels := remplacerPurge(t, []int64{LotPurge, LotPurge, 12}, 0)
	n, err := Purger(&sql.DB{}, 30*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if *appels != 3 || n != 2*LotPurge+12 {
		t.Fatalf("%d lot(s), %d ligne(s) : un passage par jour qui ne fait qu'un "+
			"lot ne rattraperait jamais un emballement", *appels, n)
	}
}

func TestLaPurgeSArreteAuPlafondDePassage(t *testing.T) {
	pleins := make([]int64, LotsParPassage+10)
	for i := range pleins {
		pleins[i] = LotPurge
	}
	appels := remplacerPurge(t, pleins, 0)
	if _, err := Purger(&sql.DB{}, 30*24*time.Hour); err != nil {
		t.Fatal(err)
	}
	if *appels != LotsParPassage {
		t.Fatalf("%d lots en un passage, plafond %d", *appels, LotsParPassage)
	}
}

func TestLaPurgeRefuseUneRetentionAbsurde(t *testing.T) {
	appels := remplacerPurge(t, nil, 0)
	if _, err := Purger(&sql.DB{}, 0); err == nil {
		t.Fatal("rétention nulle acceptée : la table serait vidée à chaque passage")
	}
	if *appels != 0 {
		t.Fatal("une suppression a eu lieu malgré le refus")
	}
}

func TestLaPurgeRendSonErreur(t *testing.T) {
	remplacerPurge(t, []int64{LotPurge}, 2)
	n, err := Purger(&sql.DB{}, 30*24*time.Hour)
	if err == nil || n != LotPurge {
		t.Fatalf("n=%d err=%v : l'échec d'un lot doit se dire, avec ce qui a déjà été supprimé", n, err)
	}
}
