package miseajourmanager

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"vaultaire/core/database"
	dbclients "vaultaire/core/database/db_clients"
	"vaultaire/core/logs"
	"vaultaire/core/miseajour"
	"vaultaire/ducky-network/sendmessage"
	"vaultaire/ducky-network/sessionmgr"
)

// La poussée opportuniste — 09_06.
//
// # Chaque core sert ses propres machines
//
// Comme le rejeu des révocations : toutes les PasDeLaPoussee, ce core regarde
// les agents CONNECTÉS À LUI et pousse l'ordre à ceux qui en ont un. La base
// est commune : une cible posée sur un nœud atteint en une minute une machine
// tenue par un autre, sans message entre cores. Une écriture de cible réveille
// le tour du core où elle a été tapée (Reveiller).
//
// # Une fois par version et par heure
//
// Un ordre poussé est noté en mémoire ; il ne repart pas vers la même machine,
// pour la même version, avant RepousseApres — l'agent rend compte en quelques
// secondes, et son compte rendu clôt l'affaire (un échec retient l'ordre, voir
// miseajour.Decider). La mémoire est perdue au redémarrage du core : au pire,
// un ordre de plus, que l'agent sait reconnaître.
//
// # Seuls les agents qui lisent la catégorie 09
//
// Un agent antérieur à miseajour.VersionQuiComprend n'a pas de gestionnaire
// pour la 09_06 : on ne la lui envoie pas.
const (
	PasDeLaPoussee = time.Minute
	RepousseApres  = time.Hour
)

type envoi struct {
	version string
	le      time.Time
}

var (
	envoisMu sync.Mutex
	envois   = map[string]envoi{}
	reveil   = make(chan struct{}, 1)
)

func cleMachine(id string) string { return strings.ToLower(strings.TrimSpace(id)) }

func noterLEnvoi(computeurID, version string) {
	envoisMu.Lock()
	envois[cleMachine(computeurID)] = envoi{version: version, le: time.Now()}
	envoisMu.Unlock()
}

func oublierLEnvoi(computeurID string) {
	envoisMu.Lock()
	delete(envois, cleMachine(computeurID))
	envoisMu.Unlock()
}

func recemmentEnvoye(computeurID, version string, maintenant time.Time) bool {
	envoisMu.Lock()
	defer envoisMu.Unlock()
	e, ok := envois[cleMachine(computeurID)]
	return ok && e.version == version && maintenant.Sub(e.le) < RepousseApres
}

// Reveiller lance un tour tout de suite, sans attendre le pas. Non bloquant.
func Reveiller() {
	select {
	case reveil <- struct{}{}:
	default:
	}
}

// sourceDePoussee : ce dont un tour a besoin, remplaçable par les tests.
type sourceDePoussee struct {
	connectees func() []string
	parc       func() ([]dbclients.AgentEtCibles, string, string, error)
	pousser    func(computeurID string, o miseajour.Ordre) bool
}

// unTour fait un passage et rend le nombre d'ordres poussés.
func unTour(src sourceDePoussee, maintenant time.Time) int {
	connectees := src.connectees()
	if len(connectees) == 0 {
		return 0
	}
	ici := make(map[string]string, len(connectees))
	for _, id := range connectees {
		ici[cleMachine(id)] = id
	}
	agents, parc, depot, err := src.parc()
	if err != nil {
		logs.Write_Log("ERROR", "miseajour: tour de poussée — lecture du parc échouée : "+err.Error())
		return 0
	}
	pousses := 0
	for _, a := range agents {
		id, connecte := ici[cleMachine(a.ComputeurID)]
		if !connecte {
			continue
		}
		d := miseajour.Decider(situationDe(a, parc, depot))
		if d.Ordre == nil {
			oublierLEnvoi(a.ComputeurID)
			continue
		}
		if !miseajour.ComprendLaCategorie(a.Declaree) || recemmentEnvoye(a.ComputeurID, d.Ordre.Version, maintenant) {
			continue
		}
		if !src.pousser(id, *d.Ordre) {
			continue
		}
		noterLEnvoi(a.ComputeurID, d.Ordre.Version)
		pousses++
		niveau := "INFO"
		if d.Ordre.Retrograder {
			niveau = "SECURITY"
		}
		logs.Write_Log(niveau, fmt.Sprintf("miseajour: ordre %s poussé à %s (déclare %q, rétrogradation : %v)",
			d.Ordre.Version, a.ComputeurID, a.Declaree, d.Ordre.Retrograder))
	}
	return pousses
}

// pousserA envoie une 09_06 par le tunnel de la machine, le plus frais
// d'abord — même choix de session que la révocation (TO-DO 89).
func pousserA(computeurID string, o miseajour.Ordre) bool {
	for _, sess := range sessionmgr.Sessions.SessionsMachine(computeurID, sessionmgr.FraicheurTunnel()) {
		msg := strings.Join(append([]string{"09_06", "serveur_central", sess.SessionID}, o.Contenu()...), "\n")
		if err := sendmessage.SendMessage(msg, sess.ClientSoftwareID, sess.DuckySession); err != nil {
			logs.Write_Log("WARNING", fmt.Sprintf("miseajour: ordre non remis à %s par la session %s : %v",
				computeurID, sess.SessionID, err))
			continue
		}
		return true
	}
	return false
}

var sourceReelle = sourceDePoussee{
	connectees: func() []string { return sessionmgr.Sessions.MachinesConnectees() },
	parc: func() ([]dbclients.AgentEtCibles, string, string, error) {
		agents, err := dbclients.AgentsEtCibles(database.GetDatabase())
		if err != nil {
			return nil, "", "", err
		}
		parc, depot, err := reglagesDuParc()
		return agents, parc, depot, err
	},
	pousser: pousserA,
}

// PousserLesOrdres est la boucle de fond. Ne rend jamais la main.
func PousserLesOrdres() {
	logs.Write_Log("INFO", fmt.Sprintf(
		"miseajour: poussée des ordres armée (tour toutes les %s, une fois par version et par %s)",
		PasDeLaPoussee, RepousseApres))
	for {
		select {
		case <-time.After(PasDeLaPoussee):
		case <-reveil:
		}
		unTour(sourceReelle, time.Now())
	}
}

// Relance est le résultat de « vlt agent update ».
type Relance struct {
	Ordre   *miseajour.Ordre
	Motif   string
	Envoyee bool // poussée maintenant, par ce core
}

// Relancer efface le compte rendu de la machine, décide, et pousse si la
// machine est connectée à CE core. Sinon elle aura son ordre à sa prochaine
// demande, ou au prochain tour du core qui la tient — sauf une rétrogradation,
// qui n'est pas durable : elle ne vaut que poussée.
func Relancer(computeurID string, retrograder bool) (Relance, error) {
	db := database.GetDatabase()
	if err := dbclients.EffacerCompteRendu(db, computeurID); err != nil {
		return Relance{}, err
	}
	s, err := lireSituation(computeurID)
	if err != nil {
		return Relance{}, err
	}
	d, err := miseajour.DeciderPourRelance(s, retrograder)
	if err != nil {
		return Relance{}, err
	}
	r := Relance{Ordre: d.Ordre, Motif: d.Motif}
	if d.Ordre == nil {
		return r, nil
	}
	oublierLEnvoi(computeurID)
	if pousserA(computeurID, *d.Ordre) {
		noterLEnvoi(computeurID, d.Ordre.Version)
		r.Envoyee = true
		niveau := "INFO"
		if d.Ordre.Retrograder {
			niveau = "SECURITY"
		}
		logs.Write_Log(niveau, fmt.Sprintf("miseajour: ordre %s poussé à %s à la demande (rétrogradation : %v)",
			d.Ordre.Version, computeurID, d.Ordre.Retrograder))
	}
	return r, nil
}
