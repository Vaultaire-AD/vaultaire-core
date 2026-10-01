package debugreport

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"
	"time"

	"duckynetworkclient/V1/duckynetwork/decouverte"
	"duckynetworkclient/V1/duckynetwork/serveurauth"
	"duckynetworkclient/V1/duckynetwork/storage"
	"duckynetworkclient/V1/duckynetwork/storage/stosession"
	"duckynetworkclient/V1/sessionmgr"

	"vaultaire_client/config"
	"vaultaire_client/gpo"
	pamcommunication "vaultaire_client/pam_communication"
	"vaultaire_client/revocation"
	serveurcommunication "vaultaire_client/serveur_communication"
	"vaultaire_client/serveur_communication/module"
	"vaultaire_client/sshauth"
	localuser "vaultaire_client/tools/local_user_management"
	"vaultaire_client/tools/sshreq"
	"vaultaire_client/version"
)

// Etat est tout ce que contient un rapport. Collecté d'abord, mis en forme
// ensuite : la mise en forme se teste sans machine.
type Etat struct {
	Instant   time.Time
	Agent     Agent
	Connexion Connexion

	DerniereListe time.Time
	Noeuds        []NoeudOrdre

	Sessions                 []Session
	SessionsUtilisateurDucky int

	SessionsLocales []SessionLocale
	ErreurSessions  string
	Comptes         []Compte
	ErreurComptes   string

	PAM         PAM
	GPO         GPO
	Revocations []string
	Groupes     Groupes

	Alertes []string
}

type Agent struct {
	ComputeurID, Hostname, Type, Version, VersionSDK string
	Serveur, DebugJournal                            bool
	PID                                              int
	Uptime, Intervalle                               time.Duration
	Config, Cles, Journaux                           string
}

type Connexion struct {
	Supervise               bool
	Adresse, Hostname, Role string
	Depuis                  time.Time
	EtatTunnel              string
	Etablissements          int
	DernierEchec            string
	DernierEchecA           time.Time
	EmpreinteCle            string
	NbEmpreintes            int
	FichierEmpreintes       string
}

type NoeudOrdre struct {
	Adresse, Role, Hostname, Source string
	Courant                         bool
}

type Session struct {
	SessionID, Username, Statut, Local, Distant string
	Creee, Vue                                  time.Time
	Sure, Cle                                   bool
}

type SessionLocale struct {
	Utilisateur, Terminal, Depuis, Origine string
	Vaultaire                              bool
}

type Compte struct {
	Nom      string
	UID      int
	Connecte bool
}

type PAM struct {
	EnAttente int
	Refusees  int64
}

type ScopeGPO struct {
	Nom, Empreinte, AppliqueeLe, Statut          string
	Version, Modules, Audit, Fichiers, Controles int
}

type CycleGPO struct {
	Scope, Username, Resume, Motif string
	Debut                          time.Time
	Duree                          time.Duration
	Echecs                         []string
}

type GPO struct {
	Machine      *ScopeGPO
	Utilisateurs []ScopeGPO
	Cycles       []CycleGPO
}

type Groupes struct {
	Crees   int
	Cadence time.Duration
}

// Sources, en variables pour les tests.
var (
	lireSessionsLocales = sessionsParWho
	maintenant          = time.Now
)

// Collecter relève l'état de l'agent. Ne bloque pas : aucune attente de
// session, aucun appel réseau.
func Collecter(debut time.Time, intervalle time.Duration) Etat {
	e := Etat{Instant: maintenant()}

	info := version.Info()
	e.Agent = Agent{
		ComputeurID:  storage.Computeur_ID,
		Hostname:     hostname(),
		Type:         storage.LogicielType,
		Serveur:      storage.IsServeur,
		Version:      info.Complete(),
		VersionSDK:   version.SDK().Complete(),
		PID:          os.Getpid(),
		Uptime:       e.Instant.Sub(debut),
		Intervalle:   intervalle,
		Config:       config.Chemin(),
		Cles:         storage.KeyPathResolu(),
		Journaux:     storage.LogPathResolu(),
		DebugJournal: storage.DEBUG,
	}

	// --- connexion ---
	ec := module.Etat()
	appris := decouverte.Appris()
	parAdresse := map[string]decouverte.Noeud{}
	for _, n := range appris {
		parAdresse[n.Adresse()] = n
	}
	learned := config.GetLearned()
	servers := config.GetServers()
	infoFichier := map[string]config.ServerConfig{}
	for _, l := range [][]config.ServerConfig{servers, learned} {
		for _, s := range l {
			infoFichier[s.Adresse()] = s
		}
	}

	e.Connexion = Connexion{
		Supervise:         serveurcommunication.TunnelSupervise(),
		Adresse:           ec.Adresse,
		Depuis:            ec.Depuis,
		Etablissements:    ec.Etablissements,
		DernierEchec:      ec.DernierEchec,
		DernierEchecA:     ec.DernierEchecA,
		FichierEmpreintes: serveurauth.CoreFingerprintPath(),
	}
	if n, ok := parAdresse[ec.Adresse]; ok {
		e.Connexion.Hostname, e.Connexion.Role = n.Hostname, n.Role
	} else if s, ok := infoFichier[ec.Adresse]; ok {
		e.Connexion.Hostname, e.Connexion.Role = s.Hostname, s.Role
	}
	if pem, err := os.ReadFile(storage.CheminDansKeyPath("serveurpublickey.pem")); err == nil {
		if emp, err := serveurauth.EmpreinteClePublique(string(pem)); err == nil {
			e.Connexion.EmpreinteCle = emp
		} else {
			e.Connexion.EmpreinteCle = "illisible : " + err.Error()
		}
	} else {
		e.Connexion.EmpreinteCle = "absente (sera demandée au prochain contact)"
	}
	if liste, err := serveurauth.EmpreintesAttendues(); err == nil {
		e.Connexion.NbEmpreintes = len(liste)
	}

	// --- sessions Ducky ---
	tunnelOK := false
	for _, s := range stosession.SessionsUser.Snapshot() {
		e.Sessions = append(e.Sessions, Session{
			SessionID: s.SessionID, Username: s.Username, Statut: s.Status.String(),
			Local: s.Local, Distant: s.Distant, Creee: s.CreatedAt, Vue: s.LastSeen,
			Sure: s.Sure, Cle: s.AUneCle,
		})
		if s.Username == "vaultaire" && s.Status == sessionmgr.SessionAuthenticated {
			tunnelOK = true
		} else if s.Username != "vaultaire" {
			e.SessionsUtilisateurDucky++
		}
	}
	e.Connexion.EtatTunnel = "authentifié"
	if !tunnelOK {
		e.Connexion.EtatTunnel = "ABSENT ou non authentifié"
	}

	// --- ordre d'essai ---
	e.DerniereListe = decouverte.DerniereReception()
	enMemoire := map[string]bool{}
	for _, n := range appris {
		enMemoire[n.Adresse()] = true
	}
	dansLearned := map[string]bool{}
	for _, s := range learned {
		dansLearned[s.Adresse()] = true
	}
	for _, a := range decouverte.FusionnerAdresses(config.AdressesConnues()) {
		n := NoeudOrdre{Adresse: a, Courant: a == ec.Adresse}
		switch {
		case enMemoire[a]:
			n.Source = "appris (04_04)"
			n.Role, n.Hostname = parAdresse[a].Role, parAdresse[a].Hostname
		case dansLearned[a]:
			n.Source = "appris, persisté"
			n.Role, n.Hostname = infoFichier[a].Role, infoFichier[a].Hostname
		default:
			n.Source = "installation"
			n.Role, n.Hostname = infoFichier[a].Role, infoFichier[a].Hostname
		}
		e.Noeuds = append(e.Noeuds, n)
	}

	// --- machine ---
	connectes := map[string]bool{}
	sessions, err := lireSessionsLocales()
	if err != nil {
		e.ErreurSessions = err.Error()
	}
	for _, s := range sessions {
		s.Vaultaire = strings.Contains(s.Utilisateur, "@")
		connectes[s.Utilisateur] = true
		e.SessionsLocales = append(e.SessionsLocales, s)
	}
	if carte, err := localuser.LoadUIDMap(); err != nil {
		e.ErreurComptes = err.Error()
	} else {
		for nom, u := range carte {
			e.Comptes = append(e.Comptes, Compte{Nom: nom, UID: u.UID, Connecte: connectes[nom]})
		}
		sort.Slice(e.Comptes, func(i, j int) bool { return e.Comptes[i].Nom < e.Comptes[j].Nom })
	}

	e.PAM = PAM{EnAttente: sshreq.Count(), Refusees: pamcommunication.ConnexionsRefusees()}

	// --- GPO ---
	st := gpo.LoadState()
	if st.Machine != nil {
		m := scopeGPO("machine", st.Machine)
		e.GPO.Machine = &m
	}
	noms := make([]string, 0, len(st.Users))
	for n := range st.Users {
		noms = append(noms, n)
	}
	sort.Strings(noms)
	for _, n := range noms {
		if st.Users[n] != nil {
			e.GPO.Utilisateurs = append(e.GPO.Utilisateurs, scopeGPO(n, st.Users[n]))
		}
	}
	for _, c := range gpo.DerniersCycles() {
		cg := CycleGPO{Scope: c.Scope, Username: c.Username, Debut: c.Debut, Duree: c.Duree,
			Resume: c.Rapport.Summary(), Motif: c.Motif}
		for _, m := range c.Rapport.Modules {
			if m.Result == gpo.ResultFailed {
				cg.Echecs = append(cg.Echecs, fmt.Sprintf("%s (%s) : %s", m.ModuleType, m.StateKey, m.Detail))
			}
		}
		e.GPO.Cycles = append(e.GPO.Cycles, cg)
	}

	// --- révocations, groupes ---
	rs := revocation.LoadState()
	ids := make([]string, 0, len(rs.Orders))
	for id := range rs.Orders {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		o := rs.Orders[id]
		e.Revocations = append(e.Revocations, fmt.Sprintf("ordre %s : %s %s — %s, %s", id, o.Mode, o.Username, o.Result, o.AppliedAt))
	}
	if crees, err := localuser.ChargerGroupesCrees(); err == nil {
		e.Groupes.Crees = len(crees)
	}
	e.Groupes.Cadence = sshauth.Cadence()

	e.Alertes = alertes(e)
	return e
}

func scopeGPO(nom string, s *gpo.ScopeState) ScopeGPO {
	out := ScopeGPO{Nom: nom, Empreinte: gpo.ShortFingerprint(s.Fingerprint), Version: s.Version,
		AppliqueeLe: s.AppliedAt, Statut: s.Status, Modules: len(s.Modules),
		Fichiers: len(s.Files), Controles: len(s.Checks)}
	for _, m := range s.Modes {
		if m == string(gpo.DriftAudit) {
			out.Audit++
		}
	}
	return out
}

// alertes relève ce qu'un lecteur pressé doit voir en premier.
func alertes(e Etat) []string {
	var a []string
	if !e.Connexion.Supervise {
		a = append(a, "le tunnel machine n'est pas supervisé : il ne se rouvrira pas seul")
	}
	if e.Connexion.EtatTunnel != "authentifié" {
		a = append(a, "aucune session machine authentifiée : ni GPO, ni révocation, ni authentification PAM")
	}
	if e.Connexion.NbEmpreintes == 0 {
		a = append(a, "aucune empreinte de confiance : la machine accepte la première clé de core reçue")
	}
	if len(e.Noeuds) == 1 {
		a = append(a, "un seul nœud connu : aucun repli si celui-ci tombe")
	}
	if e.DerniereListe.IsZero() && e.Agent.Uptime > 5*time.Minute {
		a = append(a, "aucune liste de nœuds (04_04) reçue depuis le démarrage")
	}
	if e.SessionsUtilisateurDucky > 0 {
		a = append(a, fmt.Sprintf("%d session(s) Ducky au nom d'un utilisateur", e.SessionsUtilisateurDucky))
	}
	for _, c := range e.GPO.Cycles {
		if len(c.Echecs) > 0 {
			a = append(a, fmt.Sprintf("GPO %s : %d module(s) en échec au dernier cycle", c.Scope, len(c.Echecs)))
		}
	}
	return a
}

// sessionsParWho lit les sessions ouvertes avec `who`.
//
//	alice@acme.lan pts/0        2026-09-22 16:58 (10.0.0.42)
func sessionsParWho() ([]SessionLocale, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "who").Output()
	if err != nil {
		return nil, fmt.Errorf("who : %v", err)
	}
	return AnalyserWho(string(out)), nil
}

// AnalyserWho découpe la sortie de `who`.
func AnalyserWho(sortie string) []SessionLocale {
	var out []SessionLocale
	for _, ligne := range strings.Split(sortie, "\n") {
		champs := strings.Fields(ligne)
		if len(champs) < 2 {
			continue
		}
		s := SessionLocale{Utilisateur: champs[0], Terminal: champs[1]}
		reste := champs[2:]
		if n := len(reste); n > 0 && strings.HasPrefix(reste[n-1], "(") {
			s.Origine = reste[n-1]
			reste = reste[:n-1]
		}
		s.Depuis = strings.Join(reste, " ")
		out = append(out, s)
	}
	return out
}
