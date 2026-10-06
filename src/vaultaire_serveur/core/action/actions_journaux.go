package action

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"vaultaire/core/database"
	dbjournaux "vaultaire/core/database/db_journaux"
	"vaultaire/core/logs"
	"vaultaire/core/permission"
)

// Consultation du journal commun des cores (TO-DO 91).
//
// # Une action, deux façades
//
// `vlt logs` et la page Logs du portail appellent toutes deux `log.list`.
// Le filtre, la pagination et surtout le REPLI sur la mémoire du core quand la
// base ne répond pas sont donc écrits ici, une fois : un repli qui n'existerait
// que dans le portail laisserait la ligne de commande muette au moment précis
// où la base est en cause.
//
// # La clé : read:log, sans délégation
//
// Une ligne de journal ne porte pas de domaine, et le journal couvre TOUT le
// parc : tentatives d'authentification, refus de droits, kill switch. C'est la
// clé que la page exigeait déjà.

// JournalVue est ce que rend `log.list`.
type JournalVue struct {
	dbjournaux.Page

	// Source dit d'où viennent les lignes : "base" (tous les cores) ou
	// "memoire" (ce core seulement). Les façades l'affichent : une page tirée
	// de la mémoire d'UN core, présentée comme le journal commun, ferait
	// conclure qu'il ne s'est rien passé ailleurs.
	Source string `json:"source"`

	// Avertissement explique un repli, vide sinon.
	Avertissement string `json:"avertissement,omitempty"`

	// Cores sont les cores qui ont écrit dans le journal, pour le filtre.
	Cores []string `json:"cores"`

	// CeCore est le core qui a répondu.
	CeCore string `json:"ce_core"`
}

// Sources des lignes.
const (
	SourceBase    = "base"
	SourceMemoire = "memoire"
)

// EnregistrerActionsJournaux ajoute la consultation du journal.
func EnregistrerActionsJournaux(r *Registre) {
	r.MustEnregistrer(Definition{
		Nom:     "log.list",
		CleRBAC: permission.ActionReadLog,
		Portee:  PorteeGlobale,
		// Inerte sous PorteeGlobale, déclaré pour l'invariant : toute lecture
		// le déclare.
		UnDomaineSuffit: true,
		FiltreInutile: "une ligne de journal ne porte aucun domaine ; il n'y a " +
			"pas de périmètre selon lequel réduire la liste",
		Resume:   "consulte le journal commun des cores, filtré et paginé",
		Executer: listerJournal,
	})
}

func listerJournal(_ Appelant, p Params) (Resultat, error) {
	f, err := FiltreJournal(p, time.Now())
	if err != nil {
		return Resultat{}, err
	}

	vue := JournalVue{Source: SourceBase, CeCore: logs.NomDuCore()}
	db := database.GetDatabase()

	page, errBase := dbjournaux.Lister(db, f)
	if errBase == nil {
		vue.Page = page
		// La liste des cores est un confort : son échec ne retire pas la page.
		if cores, err := dbjournaux.Cores(db); err == nil {
			vue.Cores = cores
		}
	} else {
		// Le REPLI. La base ne répond pas : c'est le moment où l'on a le plus
		// besoin de lire un journal, et le seul où le journal commun ne peut
		// pas le donner. La mémoire de ce core le peut, pour lui seul.
		vue.Source = SourceMemoire
		vue.Page = dbjournaux.PaginerEnMemoire(logs.EntreesEnMemoire(), f)
		vue.Cores = []string{vue.CeCore}
		vue.Avertissement = fmt.Sprintf(
			"journal commun illisible (%v) : lignes de la mémoire du core %s "+
				"seulement, %d dernières au plus. Les autres cores ne sont pas visibles.",
			errBase, vue.CeCore, logs.CapaciteMemoire())
	}

	msg := fmt.Sprintf("%d ligne(s), page %d", len(vue.Lignes), vue.Page.Page)
	if vue.Suivante {
		msg += " — suite à la page " + strconv.Itoa(vue.Page.Page+1)
	}
	return Resultat{Message: msg, Donnees: vue}, nil
}

// FiltreJournal traduit les paramètres de `log.list` en filtre.
//
// Paramètres : level (seuil), core, code, since, until, page, per_page.
//
// Exportée : c'est la même lecture des paramètres pour les deux façades, et les
// messages d'erreur disent la forme attendue — c'est à la saisie qu'on la
// cherche.
func FiltreJournal(p Params, maintenant time.Time) (dbjournaux.Filtre, error) {
	f := dbjournaux.Filtre{SeveriteMax: -1}

	if niveau := p.Get("level"); niveau != "" {
		sev, ok := logs.SeveriteDe(niveau)
		if !ok {
			return f, fmt.Errorf("niveau %q inconnu. Connus, du plus grave au "+
				"moins grave : CRITICAL, ERROR, WARNING, NOTICE, INFO, DEBUG", niveau)
		}
		f.SeveriteMax = sev
	}
	f.Core = p.Get("core")
	f.Code = strings.ToUpper(p.Get("code"))

	var err error
	if f.Depuis, err = lireInstant(p.Get("since"), maintenant); err != nil {
		return f, fmt.Errorf("début de période : %w", err)
	}
	if f.Jusqua, err = lireInstant(p.Get("until"), maintenant); err != nil {
		return f, fmt.Errorf("fin de période : %w", err)
	}
	if !f.Depuis.IsZero() && !f.Jusqua.IsZero() && !f.Depuis.Before(f.Jusqua) {
		return f, fmt.Errorf("période vide : le début (%s) n'est pas avant la fin (%s)",
			f.Depuis.Format("2006-01-02 15:04"), f.Jusqua.Format("2006-01-02 15:04"))
	}

	if f.Page, err = lireEntierPositif(p.Get("page"), "page"); err != nil {
		return f, err
	}
	if f.ParPage, err = lireEntierPositif(p.Get("per_page"), "nombre de lignes par page"); err != nil {
		return f, err
	}
	return f.Normaliser(), nil
}

// formatsInstant sont les formes absolues acceptées, en heure LOCALE du core.
//
// « 2006-01-02T15:04 » est ce que rend un champ `datetime-local` du navigateur.
var formatsInstant = []string{
	"2006-01-02 15:04:05",
	"2006-01-02 15:04",
	"2006-01-02T15:04:05",
	"2006-01-02T15:04",
	"2006-01-02",
}

// lireInstant lit un instant absolu, ou relatif à `maintenant`.
//
// Le relatif — « 2h », « 30m », « 3j » — est ce qu'on tape devant un
// incident : « depuis deux heures ». L'obliger à calculer une date le ferait
// taper de travers au pire moment.
func lireInstant(s string, maintenant time.Time) (time.Time, error) {
	if s == "" {
		return time.Time{}, nil
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, nil
	}
	for _, format := range formatsInstant {
		if t, err := time.ParseInLocation(format, s, time.Local); err == nil {
			return t, nil
		}
	}

	// Relatif. « j » et « d » pour les jours, que time.ParseDuration ignore.
	if strings.HasSuffix(s, "j") || strings.HasSuffix(s, "d") {
		if jours, err := strconv.Atoi(s[:len(s)-1]); err == nil && jours > 0 {
			return maintenant.Add(-time.Duration(jours) * 24 * time.Hour), nil
		}
	}
	if d, err := time.ParseDuration(s); err == nil && d > 0 {
		return maintenant.Add(-d), nil
	}
	return time.Time{}, fmt.Errorf("%q illisible. Formes acceptées : « 2026-09-24 », "+
		"« 2026-09-24 14:30 », ou une durée écoulée — « 30m », « 2h », « 3j »", s)
}

func lireEntierPositif(s, quoi string) (int, error) {
	if s == "" {
		return 0, nil
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < 1 {
		return 0, fmt.Errorf("%s %q invalide : un entier positif est attendu", quoi, s)
	}
	return n, nil
}
