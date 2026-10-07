package dbrevocation

import (
	"database/sql"
	"fmt"
	"sort"
	"strings"

	"vaultaire/core/revocation"
)

// Le suivi d'un ordre, machine par machine — TO-DO 164.
//
// # Ce qui manquait
//
// Le compte rendu de `kill -u` dit combien de machines ont REÇU l'ordre. Ce
// qu'elles en ont fait — appliqué, en échec parce que des processus survivent,
// toujours en attente — s'écrivait en base, cible par cible, et ne se lisait
// que dans le journal du core. Or c'est la question qu'on se pose pendant un
// incident : « où ce compte travaille-t-il encore ? ».
//
// # Une seule lecture, pour les deux façades
//
// La ligne de commande (`kill -u <compte> --status`) et la fiche du compte du
// portail passent par l'action `revocation.get_status`, qui rend un Suivi. Le
// tri, les libellés, le décompte et le commentaire d'une cible sont décidés
// ICI : deux façades qui les recomposeraient chacune finiraient par ne plus
// dire la même chose, sur la vue qu'on consulte quand quelque chose ne va pas.

// MaxOrdresSuivis borne le nombre d'ordres détaillés. Les plus récents
// d'abord : ce sont eux qui disent où en est le compte. Les autres sont
// comptés, et restent dans l'historique.
const MaxOrdresSuivis = 5

// OrdreSuivi est un ordre et l'état de chacune de ses cibles.
type OrdreSuivi struct {
	Record
	// Cibles, triées : ce qui n'est pas réglé d'abord (voir TrierCibles).
	Cibles []TargetRecord
	// Masquees : cibles hors du périmètre de qui lit, retirées de Cibles par
	// le filtre de l'action. Record.Total et Record.Pending les comptent
	// toujours : le total d'un ordre ne dépend pas de qui le regarde.
	Masquees int
}

// Suivi est ce que rend la lecture pour un compte.
type Suivi struct {
	Username string
	// Verrouille : un verrouillage est en vigueur sur ce compte.
	Verrouille bool
	Ordres     []OrdreSuivi
	// PlusAnciens : ordres non détaillés, au-delà de MaxOrdresSuivis.
	PlusAnciens int
}

// SuiviPour lit les derniers ordres visant un compte, avec leurs cibles.
func SuiviPour(db *sql.DB, username string) (Suivi, error) {
	out := Suivi{Username: username}
	ordres, err := HistoryFor(db, username)
	if err != nil {
		return out, err
	}
	out.Verrouille = IsRevoked(db, username)

	if len(ordres) > MaxOrdresSuivis {
		out.PlusAnciens = len(ordres) - MaxOrdresSuivis
		ordres = ordres[:MaxOrdresSuivis]
	}
	for _, o := range ordres {
		cibles, err := TargetsOf(db, o.ID)
		if err != nil {
			return out, fmt.Errorf("cibles de l'ordre %d : %w", o.ID, err)
		}
		TrierCibles(cibles)
		out.Ordres = append(out.Ordres, OrdreSuivi{Record: o, Cibles: cibles})
	}
	return out, nil
}

// rangDe ordonne les états : ce qui demande un regard d'abord.
func rangDe(s revocation.TargetStatus) int {
	switch s {
	case revocation.StatusFailed:
		return 0 // la machine a essayé et n'a pas pu : le compte y travaille peut-être encore
	case revocation.StatusPending:
		return 1 // rien n'est encore revenu
	case revocation.StatusLifted:
		return 2 // sans objet, mais jamais appliqué
	case revocation.StatusAcked:
		return 3
	}
	return 4
}

// TrierCibles met devant ce qui n'est pas réglé : les échecs, puis ce qui
// attend, puis les levées, puis ce qui est appliqué. À état égal, la machine la
// plus sollicitée d'abord — c'est celle qui résiste —, puis par nom.
func TrierCibles(cibles []TargetRecord) {
	sort.SliceStable(cibles, func(i, j int) bool {
		a, b := cibles[i], cibles[j]
		if ra, rb := rangDe(a.Status), rangDe(b.Status); ra != rb {
			return ra < rb
		}
		if a.Attempts != b.Attempts {
			return a.Attempts > b.Attempts
		}
		return strings.ToLower(a.ComputeurID) < strings.ToLower(b.ComputeurID)
	})
}

// Decompte compte les cibles par état.
type Decompte struct {
	EnEchec, EnAttente, Levees, Appliquees int
}

// Compter rend le décompte des cibles données.
func Compter(cibles []TargetRecord) Decompte {
	var d Decompte
	for _, c := range cibles {
		switch c.Status {
		case revocation.StatusFailed:
			d.EnEchec++
		case revocation.StatusPending:
			d.EnAttente++
		case revocation.StatusLifted:
			d.Levees++
		case revocation.StatusAcked:
			d.Appliquees++
		}
	}
	return d
}

// Total des cibles comptées.
func (d Decompte) Total() int { return d.EnEchec + d.EnAttente + d.Levees + d.Appliquees }

// ResteAFaire : machines où l'ordre n'est pas appliqué et sera encore remis.
func (d Decompte) ResteAFaire() int { return d.EnEchec + d.EnAttente }

// Lisible dit le décompte en une phrase, ce qui ne va pas d'abord.
func (d Decompte) Lisible() string {
	if d.Total() == 0 {
		return "aucune machine visée"
	}
	var parts []string
	ajouter := func(n int, libelle string) {
		if n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, libelle))
		}
	}
	ajouter(d.EnEchec, "en échec")
	ajouter(d.EnAttente, "en attente")
	ajouter(d.Levees, "levé(s) avant application")
	ajouter(d.Appliquees, "appliqué(s)")
	return fmt.Sprintf("%d machine(s) : %s", d.Total(), strings.Join(parts, ", "))
}

// Commentaire dit en clair où en est la cible : ce que la machine a répondu, ou
// pourquoi elle n'a rien répondu.
//
// C'est ici que « en attente » se départage : une machine à qui l'ordre n'a
// jamais été remis est absente depuis l'ordre ; une machine à qui il a été
// remis dix fois sans réponse est là, et ne répond pas — ce n'est pas le même
// incident.
func (t TargetRecord) Commentaire() string {
	switch t.Status {
	case revocation.StatusAcked:
		if r := revocation.Result(strings.TrimSpace(t.Detail)); revocation.IsValidResult(r) {
			return r.Libelle()
		}
		return strings.TrimSpace(t.Detail)
	case revocation.StatusFailed:
		if d := strings.TrimSpace(t.Detail); d != "" {
			return d
		}
		return "échec signalé sans motif"
	case revocation.StatusLifted:
		return "verrouillage levé avant que la machine ne l'applique : il ne lui sera plus remis"
	case revocation.StatusPending:
		if t.Attempts == 0 {
			return "jamais remis : machine hors ligne depuis l'ordre"
		}
		return fmt.Sprintf("remis %d fois, aucune réponse de la machine", t.Attempts)
	}
	return strings.TrimSpace(t.Detail)
}

// Echange dit quand a eu lieu le dernier échange avec la machine au sujet de
// l'ordre : « il y a 12 s », ou « — » s'il n'y en a eu aucun.
func (t TargetRecord) Echange() string {
	if !t.DepuisLeDernier.Valid {
		return "—"
	}
	return DureeLisible(t.DepuisLeDernier.Int64)
}

// DureeLisible rend un nombre de secondes écoulées. À la seconde près sous la
// minute : pendant un incident, « il y a 8 s » et « il y a 55 s » ne disent pas
// la même chose d'un ordre rejoué toutes les dix secondes.
func DureeLisible(secondes int64) string {
	switch {
	case secondes < 0:
		// L'horloge de la base a reculé, ou une date est dans le futur : on ne
		// fabrique pas un âge.
		return "à l'instant"
	case secondes < 5:
		return "à l'instant"
	case secondes < 60:
		return fmt.Sprintf("il y a %d s", secondes)
	case secondes < 3600:
		return fmt.Sprintf("il y a %d min", secondes/60)
	case secondes < 48*3600:
		return fmt.Sprintf("il y a %d h", secondes/3600)
	default:
		return fmt.Sprintf("il y a %d j", secondes/86400)
	}
}
