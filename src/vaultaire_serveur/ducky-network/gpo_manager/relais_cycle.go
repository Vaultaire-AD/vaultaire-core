package gpomanager

import (
	"database/sql"
	"fmt"
	"os"
	"strings"
	"sync/atomic"
	"time"

	dbgpo "vaultaire/core/database/db_gpo"
	"vaultaire/core/logs"
	"vaultaire/ducky-network/sessionmgr"
)

// La remise des demandes de cycle relayées par la base — TO-DO 172.
//
// Chaque core relève les demandes en attente toutes les PasDuRelais. Pour une
// machine dont il tient le tunnel, il PREND la demande — un seul core y
// parvient — puis pousse 05_18 comme pour une demande faite chez lui. Il ne
// touche pas aux autres : elles sont peut-être pour un autre core.
//
// Le demandeur relit la ligne (dbgpo.IssuesDesDemandes) pour savoir qui l'a
// remise : voir action.RafraichirMachines.

// PasDuRelais : une demande ne doit pas attendre plus qu'un clic de portail.
// La requête est une lecture indexée de quelques lignes au plus.
var PasDuRelais = 2 * time.Second

// relaisDemarre : une seule boucle par processus.
var relaisDemarre atomic.Bool

// NomDuCoreLocal nomme ce core dans les demandes : le nom d'hôte, celui de sa
// ligne dans cluster_nodes.
func NomDuCoreLocal() string {
	h, err := os.Hostname()
	if err != nil || strings.TrimSpace(h) == "" {
		return "core"
	}
	return h
}

// DemarrerRelaisDesCycles lance la boucle. Sans effet au second appel.
func DemarrerRelaisDesCycles(db *sql.DB) {
	if db == nil || !relaisDemarre.CompareAndSwap(false, true) {
		return
	}
	moi := NomDuCoreLocal()
	go func() {
		// Une panique ici arrêterait le relais pour toujours, sans arrêter le
		// core : elle est dite, et la boucle relancée.
		defer func() {
			if r := recover(); r != nil {
				logs.Write_Log("CRITICAL", fmt.Sprintf("gpo: relais des demandes de cycle arrêté : %v", r))
				relaisDemarre.Store(false)
				DemarrerRelaisDesCycles(db)
			}
		}()
		tours := 0
		for {
			time.Sleep(PasDuRelais)
			RemettreLesDemandes(relaisReel(db), moi)
			// Le ménage, une fois toutes les dix minutes environ : la table ne
			// garde qu'une heure de demandes.
			if tours++; tours%300 == 0 {
				if n, err := dbgpo.OublierDemandesDeCycle(db); err == nil && n > 0 {
					logs.Write_LogCode("DEBUG", logs.CodeGPOTransport, fmt.Sprintf(
						"gpo: %d demande(s) de cycle de plus d'une heure oubliée(s)", n))
				}
			}
		}
	}()
}

// relais rassemble ce que la remise emploie : la base, le registre des
// sessions, la poussée. Une structure de fonctions pour l'éprouver sans core.
type relais struct {
	enAttente func() ([]dbgpo.DemandeDeCycle, error)
	tient     func(computeurID string) bool
	prendre   func(id int64, par string) (bool, error)
	pousser   func(computeurID, motif string) (bool, error)
	noter     func(id int64, remise bool) error
}

func relaisReel(db *sql.DB) relais {
	return relais{
		enAttente: func() ([]dbgpo.DemandeDeCycle, error) { return dbgpo.DemandesDeCycleEnAttente(db) },
		tient: func(id string) bool {
			return len(sessionmgr.Sessions.SessionsMachine(id, sessionmgr.FraicheurTunnel())) > 0
		},
		prendre: func(id int64, par string) (bool, error) { return dbgpo.PrendreDemandeDeCycle(db, id, par) },
		pousser: DemanderRafraichissement,
		noter:   func(id int64, remise bool) error { return dbgpo.NoterRemise(db, id, remise) },
	}
}

// RemettreLesDemandes traite un tour : rend le nombre de demandes remises par
// ce core.
func RemettreLesDemandes(r relais, moi string) int {
	demandes, err := r.enAttente()
	if err != nil {
		logs.Write_LogCode("WARNING", logs.CodeGPOTransport,
			"gpo: demandes de cycle illisibles : "+err.Error())
		return 0
	}
	remises := 0
	for _, d := range demandes {
		// Le tunnel AVANT la prise : prendre une demande pour une machine qu'on
		// ne tient pas la retirerait au core qui la tient.
		if !r.tient(d.ComputeurID) {
			continue
		}
		pris, err := r.prendre(d.ID, moi)
		if err != nil || !pris {
			continue // un autre core l'a prise, ou la base a flanché : il la remettra
		}
		motif := d.Motif
		if d.DemandePar != "" {
			motif += " (relayée par " + d.DemandePar + ")"
		}
		ok, errP := r.pousser(d.ComputeurID, motif)
		_ = r.noter(d.ID, ok)
		if ok {
			remises++
			logs.Write_LogCode("INFO", logs.CodeGPOTransport, fmt.Sprintf(
				"gpo: demande de cycle de %s remise à %s", d.DemandePar, d.ComputeurID))
		} else {
			logs.Write_LogCode("WARNING", logs.CodeGPOTransport, fmt.Sprintf(
				"gpo: demande de cycle de %s prise pour %s mais non remise : %v", d.DemandePar, d.ComputeurID, errP))
		}
	}
	return remises
}
