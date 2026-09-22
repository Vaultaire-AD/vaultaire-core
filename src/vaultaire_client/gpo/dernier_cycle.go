package gpo

import (
	"sort"
	"sync"
	"time"
)

// CycleNote résume le dernier cycle d'un scope, pour le rapport de debug.
type CycleNote struct {
	Scope    string
	Username string
	Debut    time.Time
	Duree    time.Duration
	Rapport  Report
	Motif    string // code d'erreur, « politique inchangée », ou vide
}

var (
	cyclesMu sync.Mutex
	cycles   = map[string]CycleNote{}
)

func noterCycle(scope, username string, debut time.Time, r Report, motif string) {
	cyclesMu.Lock()
	defer cyclesMu.Unlock()
	cycles[scope+"\x00"+username] = CycleNote{
		Scope: scope, Username: username, Debut: debut,
		Duree: time.Since(debut), Rapport: r, Motif: motif,
	}
}

// DerniersCycles rend le dernier cycle de chaque scope depuis le démarrage :
// machine d'abord, puis utilisateurs par nom.
func DerniersCycles() []CycleNote {
	cyclesMu.Lock()
	out := make([]CycleNote, 0, len(cycles))
	for _, c := range cycles {
		out = append(out, c)
	}
	cyclesMu.Unlock()
	sort.Slice(out, func(i, j int) bool {
		if out[i].Scope != out[j].Scope {
			return out[i].Scope == ScopeMachine
		}
		return out[i].Username < out[j].Username
	})
	return out
}
