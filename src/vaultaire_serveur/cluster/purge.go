package cluster

import (
	"database/sql"
	"fmt"
	"sync/atomic"
	"time"

	clusterdatabase "vaultaire/cluster/cluster_database"
	clusterstorage "vaultaire/cluster/cluster_storage"
	"vaultaire/core/logs"
	hosthandler "vaultaire/ducky-network/host_handler"
	"vaultaire/ducky-network/sessionmgr"
)

// La purge d'un core en maintenance — TO-DO 147.
//
// # Pourquoi c'est le core visé qui la fait
//
// Ses sessions vivent dans sa mémoire ; aucun autre core ne les voit, ni ne
// peut les fermer. L'action ne fait donc qu'ÉCRIRE la demande sur la ligne du
// nœud, et chaque core, à son battement, regarde la sienne.
//
// # Deux temps : prévenir, puis fermer ce qui reste
//
//  1. Chaque machine qui tient un tunnel ici reçoit une 04_17 (« redemande ta
//     liste »). Le core étant en maintenance, il n'est plus dans la liste
//     qu'elle reçoit : un agent qui sait basculer (bascule.go) voit que son
//     nœud courant a disparu, ferme son tunnel et se reconnecte AILLEURS, à
//     son rythme. C'est la sortie douce, et la plupart du parc la prend.
//  2. Après un délai de grâce, ce qui reste — agents anciens, postes Windows,
//     proxies, sessions de compte, poignées de main — est fermé une session à
//     la fois, ÉTALÉ sur la durée demandée : un site entier qui se reconnecte
//     dans la même seconde, c'est une tempête sur les autres cores.
//
// # Ce qu'elle ne ferme pas
//
// Les sessions WEB du portail et l'API : ce ne sont pas des sessions Ducky.
// L'administrateur qui purge depuis le portail de ce core garde sa page — on ne
// se coupe pas la branche sur laquelle on est assis.

// GracePurge laisse aux agents le temps de redemander leur liste et de
// basculer d'eux-mêmes : une 04_03, une 04_04, une reconnexion.
const GracePurge = 60 * time.Second

// EtalementParDefaut s'applique quand la demande n'en précise pas.
const EtalementParDefaut = 60 * time.Second

// registrePurge est ce que la purge emploie du registre des sessions.
// Une interface pour l'éprouver sans connexion réelle.
type registrePurge interface {
	MachinesConnectees() []string
	IDs() []string
	Fermer(id string) bool
}

type purgeur struct {
	sessions registrePurge
	// prevenir pousse la 04_17 à une machine ; rend si elle est partie.
	prevenir func(machine, motif string) (bool, error)
	dormir   func(time.Duration)
	grace    time.Duration
}

// BilanPurge : ce que la purge a fait.
type BilanPurge struct {
	Prevenues int // machines qui ont reçu la 04_17
	Fermees   int // sessions fermées par la purge elle-même
}

// purger exécute les deux temps.
func (p purgeur) purger(etalement time.Duration, motif string) BilanPurge {
	var b BilanPurge
	for _, m := range p.sessions.MachinesConnectees() {
		if ok, _ := p.prevenir(m, motif); ok {
			b.Prevenues++
		}
	}
	if b.Prevenues > 0 {
		p.dormir(p.grace)
	}

	restantes := p.sessions.IDs()
	if len(restantes) == 0 {
		return b
	}
	pas := etalement / time.Duration(len(restantes))
	for i, id := range restantes {
		if p.sessions.Fermer(id) {
			b.Fermees++
		}
		if i < len(restantes)-1 && pas > 0 {
			p.dormir(pas)
		}
	}
	return b
}

// purgeEnCours empêche deux purges simultanées sur ce core : le battement
// revient toutes les trente secondes, une purge en dure plusieurs minutes.
var purgeEnCours atomic.Bool

// derniereFaite retient la demande déjà exécutée par ce processus.
//
// Garde-fou contre une boucle : si l'écriture de la fin échouait — base
// injoignable à ce moment-là, ou date relue autrement qu'écrite —, la ligne
// dirait toujours « en cours », et chaque battement relancerait la même purge
// sur un parc qui vient de se reconnecter. Une demande n'est exécutée qu'une
// fois par processus ; une NOUVELLE demande porte une autre date.
var derniereFaite atomic.Int64

// lancerPurgeSiDemandee lit la ligne de ce core et lance la purge demandée.
func lancerPurgeSiDemandee(db *sql.DB, node clusterstorage.Node) {
	if purgeEnCours.Load() {
		return
	}
	demande, afaire, err := clusterdatabase.PurgeAFaire(db, node.Proprietaire)
	if err != nil {
		logs.Write_Log("WARNING", "cluster: demande de purge illisible : "+err.Error())
		return
	}
	if !afaire || demande.Demandee.Unix() == derniereFaite.Load() {
		return
	}
	if !purgeEnCours.CompareAndSwap(false, true) {
		return
	}
	derniereFaite.Store(demande.Demandee.Unix())

	etalement := demande.Etalement
	if etalement <= 0 {
		etalement = EtalementParDefaut
	}
	go func() {
		defer purgeEnCours.Store(false)
		avant := sessionmgr.Sessions.Compter()
		logs.Write_Log("WARNING", fmt.Sprintf(
			"cluster: PURGE de %s (en maintenance) : %d machine(s), %d session(s) — 04_17 à "+
				"chaque machine, puis fermeture du reste sur %s",
			node.Hostname, avant.Machines, avant.Tunnels+avant.Comptes+avant.Poignees, etalement))

		p := purgeur{
			sessions: sessionmgr.Sessions,
			prevenir: hosthandler.DemanderActualisationListe,
			dormir:   time.Sleep,
			grace:    GracePurge,
		}
		b := p.purger(etalement, "maintenance du core "+node.Hostname)

		if err := clusterdatabase.TerminerPurge(db, node.Proprietaire, demande.Demandee, b.Fermees); err != nil {
			logs.Write_Log("ERROR", "cluster: fin de purge non enregistrée : "+err.Error())
		}
		apres := sessionmgr.Sessions.Compter()
		logs.Write_Log("WARNING", fmt.Sprintf(
			"cluster: purge de %s terminée : %d machine(s) prévenue(s), %d session(s) fermée(s) "+
				"par la purge ; il reste %d machine(s), %d session(s) — revenues depuis (agent à "+
				"liste statique), ou ouvertes pendant",
			node.Hostname, b.Prevenues, b.Fermees, apres.Machines, apres.Tunnels+apres.Comptes+apres.Poignees))
	}()
}
