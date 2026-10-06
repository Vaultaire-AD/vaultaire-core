package dbjournaux

import (
	"database/sql"
	"fmt"
	"strings"
	"time"

	"vaultaire/core/logs"
)

// Bornes de la pagination.
//
// 500 au plus : au-delà, une page ne se lit plus, elle se parcourt — et le
// navigateur comme le terminal peinent avant le lecteur.
const (
	ParPageDefaut = 50
	ParPageMax    = 500
)

// Filtre décrit une consultation du journal.
//
// Toutes les conditions se cumulent. Une valeur nulle n'en pose aucune.
type Filtre struct {
	// SeveriteMax garde les lignes AU MOINS aussi graves que ce niveau : 4
	// (WARNING) rend WARNING, ERROR, CRITICAL… Négatif : tous les niveaux.
	//
	// Un seuil plutôt qu'un niveau exact : devant un incident on demande
	// « ce qui ne va pas », pas « les WARNING mais pas les ERROR ».
	SeveriteMax int

	Core string // nom exact du core émetteur
	Code string // code exact, ex. VLT-DB001

	Depuis time.Time // inclus
	Jusqua time.Time // exclu

	Page    int // à partir de 1
	ParPage int
}

// Normaliser borne la pagination.
func (f Filtre) Normaliser() Filtre {
	if f.Page < 1 {
		f.Page = 1
	}
	if f.ParPage < 1 {
		f.ParPage = ParPageDefaut
	}
	if f.ParPage > ParPageMax {
		f.ParPage = ParPageMax
	}
	return f
}

// Accepte applique le filtre à une entrée — pour le repli en mémoire.
//
// C'est la MÊME règle que la clause WHERE de requeteLecture, écrite une seconde
// fois parce que l'une parle SQL et l'autre Go. Un test les confronte sur les
// mêmes cas : sinon le portail montrerait des lignes différentes selon que la
// base répond ou non, et personne ne le remarquerait.
func (f Filtre) Accepte(e logs.LogEntry) bool {
	if f.SeveriteMax >= 0 && e.Severity > f.SeveriteMax {
		return false
	}
	if f.Core != "" && e.Hostname != f.Core {
		return false
	}
	if f.Code != "" && e.Code != f.Code {
		return false
	}
	if !f.Depuis.IsZero() && e.Timestamp.Before(f.Depuis) {
		return false
	}
	if !f.Jusqua.IsZero() && !e.Timestamp.Before(f.Jusqua) {
		return false
	}
	return true
}

// Page est une page de journal, la ligne la plus récente en premier.
type Page struct {
	Lignes  []logs.LogEntry `json:"lignes"`
	Page    int             `json:"page"`
	ParPage int             `json:"par_page"`

	// Suivante dit s'il existe des lignes plus anciennes.
	//
	// Pas de total : un COUNT(*) sur des semaines de journaux coûte plus cher
	// que la page elle-même, et la question qu'on se pose en lisant est
	// « y en a-t-il d'autres », pas « combien ».
	Suivante bool `json:"suivante"`
}

// requeteLecture rend la requête d'une page et ses arguments.
//
// Une ligne de plus que la page est demandée : c'est elle qui dit s'il existe
// une page suivante, sans compter la table.
func requeteLecture(f Filtre) (string, []any) {
	f = f.Normaliser()

	var conds []string
	var args []any
	if f.SeveriteMax >= 0 {
		conds = append(conds, "severity <= ?")
		args = append(args, f.SeveriteMax)
	}
	if f.Core != "" {
		conds = append(conds, "core_name = ?")
		args = append(args, f.Core)
	}
	if f.Code != "" {
		conds = append(conds, "code = ?")
		args = append(args, f.Code)
	}
	if !f.Depuis.IsZero() {
		conds = append(conds, "created_at >= ?")
		args = append(args, f.Depuis.UTC())
	}
	if !f.Jusqua.IsZero() {
		conds = append(conds, "created_at < ?")
		args = append(args, f.Jusqua.UTC())
	}

	q := "SELECT " + colonnes + " FROM " + Table
	if len(conds) > 0 {
		q += " WHERE " + strings.Join(conds, " AND ")
	}
	// `id` départage deux lignes de la même microseconde : sans lui, l'ordre
	// entre elles changerait d'une page à l'autre, et une ligne pourrait
	// apparaître sur deux pages — ou sur aucune.
	q += " ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?"
	args = append(args, f.ParPage+1, (f.Page-1)*f.ParPage)
	return q, args
}

// Lister lit une page du journal commun.
func Lister(db *sql.DB, f Filtre) (Page, error) {
	f = f.Normaliser()
	page := Page{Page: f.Page, ParPage: f.ParPage, Lignes: []logs.LogEntry{}}
	if db == nil {
		return page, fmt.Errorf("connexion base indisponible")
	}

	q, args := requeteLecture(f)
	rows, err := db.Query(q, args...)
	if err != nil {
		return page, fmt.Errorf("lecture du journal commun : %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var e logs.LogEntry
		if err := rows.Scan(&e.Timestamp, &e.Severity, &e.Level, &e.Code,
			&e.Hostname, &e.Message, &e.RequestID, &e.UserID); err != nil {
			return page, fmt.Errorf("lecture du journal commun : %w", err)
		}
		e.Priority = logs.Facility*8 + e.Severity
		page.Lignes = append(page.Lignes, e)
	}
	if err := rows.Err(); err != nil {
		return page, fmt.Errorf("lecture du journal commun : %w", err)
	}
	return couperPage(page), nil
}

// couperPage retire la ligne témoin demandée en plus, et en déduit Suivante.
func couperPage(p Page) Page {
	if len(p.Lignes) > p.ParPage {
		p.Lignes = p.Lignes[:p.ParPage]
		p.Suivante = true
	}
	return p
}

// PaginerEnMemoire applique le filtre et la pagination à des entrées déjà
// triées de la plus récente à la plus ancienne (logs.EntreesEnMemoire).
func PaginerEnMemoire(entrees []logs.LogEntry, f Filtre) Page {
	f = f.Normaliser()
	page := Page{Page: f.Page, ParPage: f.ParPage, Lignes: []logs.LogEntry{}}

	aSauter := (f.Page - 1) * f.ParPage
	for _, e := range entrees {
		if !f.Accepte(e) {
			continue
		}
		if aSauter > 0 {
			aSauter--
			continue
		}
		page.Lignes = append(page.Lignes, e)
		if len(page.Lignes) > f.ParPage {
			break
		}
	}
	return couperPage(page)
}

// Cores rend les cores qui ont écrit dans le journal, par ordre alphabétique.
//
// Lus dans le journal et non dans cluster_nodes : un core retiré du cluster a
// laissé des lignes qu'on doit pouvoir filtrer. L'index (core_name, created_at)
// sert ce DISTINCT sans parcourir la table.
func Cores(db *sql.DB) ([]string, error) {
	if db == nil {
		return nil, fmt.Errorf("connexion base indisponible")
	}
	rows, err := db.Query("SELECT DISTINCT core_name FROM " + Table + " ORDER BY core_name")
	if err != nil {
		return nil, fmt.Errorf("liste des cores du journal : %w", err)
	}
	defer rows.Close()

	var cores []string
	for rows.Next() {
		var c string
		if err := rows.Scan(&c); err != nil {
			return nil, fmt.Errorf("liste des cores du journal : %w", err)
		}
		cores = append(cores, c)
	}
	return cores, rows.Err()
}
