package action

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"vaultaire/core/database"
	dbclients "vaultaire/core/database/db_clients"
	dbsettings "vaultaire/core/database/db_settings"
	"vaultaire/core/miseajour"
	"vaultaire/core/paquetagent"
	"vaultaire/core/parcversion"
	keymanagement "vaultaire/ducky-network/key_management"
	miseajourmanager "vaultaire/ducky-network/miseajour_manager"
)

// La version attendue des agents, et la vue « constaté vs attendu » — TO-DO 111.
//
// # Ce que ces actions font, et ce qu'elles ne font pas encore
//
// Elles posent une CONSIGNE et la confrontent à ce que chaque agent déclare.
// Aucun agent ne s'y conforme encore de lui-même : l'ordre de mise à jour
// (point 115) et le basculement (point 116) lisent cette consigne. La
// vue vaut déjà seule — elle dit quelles machines sont en retard.
//
// # Pourquoi read:log / write:server, portée globale
//
// Les mêmes clés que la signature des GPO et le second facteur Ducky, pour la
// même raison : une cible de version engage des machines qui ne sont pas celles
// d'un seul domaine — une machine appartient à des groupes de plusieurs
// domaines, et la plus haute de leurs cibles l'emporte. Un délégué de paris qui
// pose une cible sur son groupe déciderait donc aussi pour les machines que
// lyon partage avec lui.
//
// La dérogation par machine suit la même clé : figer un poste, c'est le
// soustraire à une cible posée par quelqu'un d'autre.

// ActionsVersionAgent liste les actions de ce fichier, pour la commande.
var ActionsVersionAgent = []string{"agent.status", "agent.set_target", "agent.pin",
	"agent.update", "agent.set_repository"}

// LigneAgent est une machine de la vue.
type LigneAgent struct {
	ComputeurID string
	Hostname    string
	OS          string
	// Declaree : la valeur brute ; VersionLisible : ce qu'on en affiche.
	Declaree       string
	VersionLisible string
	Attendue       parcversion.Attendue
	Etat           parcversion.Etat
	Groupes        []string
	// CompteRendu : le dernier 09_04 (TO-DO 115) — ce qui distingue « pas
	// encore tenté » de « tenté et revenu en arrière ».
	CompteRendu dbclients.CompteRendu
	// Configuration : le dernier 09_07 (TO-DO 117) — la configuration système
	// de la machine face à sa version.
	Configuration dbclients.Configuration
	// Retrogradation : la dérogation de la machine autorise une rétrogradation
	// et c'est elle qui décide de la version attendue (TO-DO 204).
	Retrogradation bool
}

// Nom rend le nom d'hôte, ou l'identifiant tant que la machine n'en a pas
// déclaré.
func (l LigneAgent) Nom() string {
	if strings.TrimSpace(l.Hostname) != "" {
		return l.Hostname
	}
	return l.ComputeurID
}

// ConfigurationLisible rend l'état du dernier 09_07 (TO-DO 117) tel que la
// ligne de commande et le portail l'affichent — vide sans compte rendu : un
// agent d'avant le 117, ou face à un core qui n'annonçait pas « confsys ».
func (l LigneAgent) ConfigurationLisible() string {
	switch l.Configuration.Etat {
	case "":
		return ""
	case miseajour.ConfConforme:
		return "conforme"
	case miseajour.ConfEcart:
		return "écart"
	case miseajour.ConfReconciliee:
		return "réconciliée"
	case miseajour.ConfDesactivee:
		return "désactivée"
	case miseajour.ConfNonPrisEnCharge:
		return "non prise en charge"
	}
	return l.Configuration.Etat
}

// ConfigurationEnEcart : un contrôle a refusé, rien n'a été écrit pour le
// fichier en cause — à traiter sur la machine.
func (l LigneAgent) ConfigurationEnEcart() bool {
	return l.Configuration.Etat == miseajour.ConfEcart
}

// Relancable dit si « agent.update » a quelque chose à pousser : une machine
// en retard, ou dont la version déclarée est illisible (TO-DO 205). Une
// machine en échec reste en retard — c'est elle que le bouton du portail
// vise. À jour, en avance ou sans cible, l'action répondrait « rien à
// faire » : le bouton n'est pas proposé.
func (l LigneAgent) Relancable() bool { return l.Etat.AUnEcart() }

// VueAgents est le résultat de agent.status.
type VueAgents struct {
	// Parc : le défaut du parc, normalisé ; vide sans défaut.
	Parc string
	// ParcIllisible porte une valeur trouvée en base et non retenue.
	ParcIllisible string
	// CiblesDesGroupes : les groupes qui portent une cible.
	CiblesDesGroupes []dbclients.CibleGroupe
	// Groupe : le filtre demandé, vide pour tout le parc.
	Groupe    string
	Machines  []LigneAgent
	Compteurs map[parcversion.Etat]int
	// Depot : le dépôt Nexus nommé dans les ordres (TO-DO 115).
	Depot string
	// Rotation : la clé de signature des paquets et le parc (TO-DO 207) ;
	// nil si elle n'a pas pu être lue — la vue reste utile sans elle.
	Rotation *paquetagent.EtatRotation
}

// ParComputeurID indexe les lignes, pour la colonne du portail.
func (v VueAgents) ParComputeurID() map[string]*LigneAgent {
	m := make(map[string]*LigneAgent, len(v.Machines))
	for i := range v.Machines {
		m[v.Machines[i].ComputeurID] = &v.Machines[i]
	}
	return m
}

// Bilan rend « 12 agent(s) : 3 en retard, 1 inconnue, 8 à jour ».
func (v VueAgents) Bilan() string {
	var parties []string
	for _, e := range parcversion.OrdreDesEtats {
		if n := v.Compteurs[e]; n > 0 {
			parties = append(parties, fmt.Sprintf("%d %s", n, e))
		}
	}
	s := fmt.Sprintf("%d agent(s)", len(v.Machines))
	if v.Groupe != "" {
		s += " dans " + v.Groupe
	}
	if len(parties) > 0 {
		s += " : " + strings.Join(parties, ", ")
	}
	return s
}

// sourceDesCibles est ce que la vue lit. Remplaçable par les tests.
type sourceDesCibles struct {
	agents       func() ([]dbclients.AgentEtCibles, error)
	parc         func() (string, bool, error)
	groupes      func() ([]dbclients.CibleGroupe, error)
	groupeExiste func(string) (bool, error)
	depot        func() (string, bool, error)
}

var lireCibles = sourceDesCibles{
	agents: func() ([]dbclients.AgentEtCibles, error) {
		return dbclients.AgentsEtCibles(database.GetDatabase())
	},
	parc: func() (string, bool, error) {
		return dbsettings.GetString(database.GetDatabase(), parcversion.CleReglageParc)
	},
	groupes: func() ([]dbclients.CibleGroupe, error) {
		return dbclients.CiblesDesGroupes(database.GetDatabase())
	},
	groupeExiste: func(g string) (bool, error) {
		return dbclients.GroupeExiste(database.GetDatabase(), g)
	},
	depot: func() (string, bool, error) {
		return dbsettings.GetString(database.GetDatabase(), miseajour.CleReglageDepot)
	},
}

// construireVue lit le parc et résout la cible de chaque agent.
//
// Une erreur de lecture est rendue telle quelle, jamais remplacée par une vue
// vide : « aucune cible » dit qu'aucune machine ne bougera, et l'afficher
// parce que la base a flanché serait faux sur ce qui va se passer.
func construireVue(groupe string) (VueAgents, error) {
	vue := VueAgents{Groupe: groupe, Compteurs: map[parcversion.Etat]int{}, Depot: miseajour.DepotParDefaut}
	if e, err := lireRotation(); err == nil {
		vue.Rotation = &e
	}
	if lireCibles.depot != nil {
		if d, _, err := lireCibles.depot(); err != nil {
			return VueAgents{}, err
		} else if d != "" {
			vue.Depot = d
		}
	}

	if groupe != "" {
		ok, err := lireCibles.groupeExiste(groupe)
		if err != nil {
			return VueAgents{}, err
		}
		if !ok {
			return VueAgents{}, fmt.Errorf("groupe %q introuvable", groupe)
		}
	}

	brut, _, err := lireCibles.parc()
	if err != nil {
		return VueAgents{}, err
	}
	if brut != "" {
		if n, errN := parcversion.NormaliserCible(brut); errN == nil {
			vue.Parc = n
		} else {
			vue.ParcIllisible = brut
		}
	}

	if vue.CiblesDesGroupes, err = lireCibles.groupes(); err != nil {
		return VueAgents{}, err
	}

	agents, err := lireCibles.agents()
	if err != nil {
		return VueAgents{}, err
	}
	for _, a := range agents {
		if groupe != "" {
			if _, dedans := a.Groupes[groupe]; !dedans {
				continue
			}
		}
		attendue := parcversion.Resoudre(parcversion.Cibles{
			Derogation: a.Derogation, Groupes: a.Groupes, Parc: brut,
		})
		ligne := LigneAgent{
			ComputeurID: a.ComputeurID,
			Hostname:    a.Hostname,
			OS:          a.OS,
			Declaree:    a.Declaree,
			VersionLisible: parcversion.Machine{
				ComputeurID: a.ComputeurID, Hostname: a.Hostname, Declaree: a.Declaree,
			}.VersionLisible(),
			Attendue:       attendue,
			Etat:           parcversion.Situer(a.Declaree, attendue),
			CompteRendu:    a.CompteRendu,
			Configuration:  a.Configuration,
			Retrogradation: a.DerogationRetrograder && attendue.Source == parcversion.SourceMachine,
		}
		for g := range a.Groupes {
			ligne.Groupes = append(ligne.Groupes, g)
		}
		sort.Strings(ligne.Groupes)
		vue.Machines = append(vue.Machines, ligne)
		vue.Compteurs[ligne.Etat]++
	}

	// Ce qui demande un regard d'abord, puis par nom : deux appels sur le même
	// parc rendent la même liste.
	rang := map[parcversion.Etat]int{}
	for i, e := range parcversion.OrdreDesEtats {
		rang[e] = i
	}
	sort.SliceStable(vue.Machines, func(i, j int) bool {
		a, b := vue.Machines[i], vue.Machines[j]
		if rang[a.Etat] != rang[b.Etat] {
			return rang[a.Etat] < rang[b.Etat]
		}
		return a.Nom() < b.Nom()
	})
	return vue, nil
}

// EnregistrerActionsVersionAgent ajoute la lecture et les deux écritures.
func EnregistrerActionsVersionAgent(r *Registre) {
	r.MustEnregistrer(Definition{
		Nom:      "agent.status",
		CleRBAC:  "read:log",
		Portee:   PorteeGlobale,
		Resume:   "version déclarée et version attendue de chaque agent du parc",
		Executer: lireVersionsAgents,
	})
	r.MustEnregistrer(Definition{
		Nom:      "agent.set_target",
		CleRBAC:  "write:server",
		Portee:   PorteeGlobale,
		Resume:   "pose ou retire la version attendue du parc, ou d'un groupe",
		Executer: definirCibleAgents,
	})
	r.MustEnregistrer(Definition{
		Nom:      "agent.pin",
		CleRBAC:  "write:server",
		Portee:   PorteeGlobale,
		Resume:   "fige ou libère la version attendue d'une machine",
		Executer: definirDerogationAgent,
	})
	r.MustEnregistrer(Definition{
		Nom:      "agent.update",
		CleRBAC:  "write:server",
		Portee:   PorteeGlobale,
		Resume:   "relance la mise à jour d'une machine, ou la rétrograde explicitement",
		Executer: relancerMiseAJour,
	})
	r.MustEnregistrer(Definition{
		Nom:      "agent.set_repository",
		CleRBAC:  "write:server",
		Portee:   PorteeGlobale,
		Resume:   "nomme le dépôt Nexus où les agents prennent leurs paquets",
		Executer: definirDepot,
	})
}

func lireVersionsAgents(_ Appelant, p Params) (Resultat, error) {
	vue, err := construireVue(p.Get("group"))
	if err != nil {
		return Resultat{}, err
	}
	return Resultat{Message: vue.Bilan(), Donnees: vue}, nil
}

// versionSaisie rend la version normalisée, ou "" pour un effacement.
func versionSaisie(p Params) (string, error) {
	saisie := p.Get("version")
	if saisie == "" {
		return "", fmt.Errorf("version manquante : une version (2.3.1) ou %q pour retirer la cible",
			parcversion.AucuneCible)
	}
	if parcversion.EstEffacement(saisie) {
		return "", nil
	}
	return parcversion.NormaliserCible(saisie)
}

// Les écritures, remplaçables par les tests.
var (
	ecrireCibleGroupe = func(groupe, version string) error {
		return dbclients.DefinirCibleGroupe(database.GetDatabase(), groupe, version)
	}
	ecrireCibleParc = func(version, auteur string) error {
		return dbsettings.SetString(database.GetDatabase(), parcversion.CleReglageParc, version,
			func(v string) error { _, err := parcversion.NormaliserCible(v); return err }, auteur)
	}
	ecrireDerogation = func(computeurID, version string, retrograder bool) error {
		return dbclients.DefinirDerogation(database.GetDatabase(), computeurID, version, retrograder)
	}
)

// lireRotation : remplaçable par les tests.
var lireRotation = func() (paquetagent.EtatRotation, error) {
	return paquetagent.LireEtat(keymanagement.MagasinPaquets{})
}

// noteDeroule est dite à chaque écriture : une cible posée n'est pas une
// version installée. Depuis le 116, chaque agent étale son départ, télécharge,
// vérifie, bascule et passe une porte de santé — quelques minutes — puis
// rapporte ; c'est dans « vlt agent » qu'on lit le résultat.
const noteDeroule = "Chaque agent concerné installera dans les minutes qui viennent (départ étalé, " +
	"porte de santé, retour arrière en cas d'échec) : le résultat se lit dans vlt agent."

// reveillerLaPoussee : après une écriture, le tour de poussée de ce core part
// tout de suite. Remplaçable par les tests.
var reveillerLaPoussee = miseajourmanager.Reveiller

func definirCibleAgents(a Appelant, p Params) (Resultat, error) {
	version, err := versionSaisie(p)
	if err != nil {
		return Resultat{}, err
	}
	groupe := p.Get("group")

	if groupe != "" {
		if err := ecrireCibleGroupe(groupe, version); err != nil {
			if errors.Is(err, dbclients.ErrIntrouvable) {
				return Resultat{}, fmt.Errorf("groupe %q introuvable", groupe)
			}
			return Resultat{}, err
		}
	} else {
		if err := ecrireCibleParc(version, a.Username); err != nil {
			return Resultat{}, err
		}
	}

	quoi := "du parc"
	if groupe != "" {
		quoi = "du groupe " + groupe
	}
	var msg string
	if version == "" {
		msg = "Version attendue " + quoi + " retirée."
	} else {
		msg = "Version attendue " + quoi + " : " + version + "."
	}

	// Le compte rendu relit la vue : il dit ce que la cible change VRAIMENT,
	// une fois les autres niveaux résolus — une cible de groupe plus basse
	// qu'une autre ne décide de rien pour les machines des deux.
	if vue, errV := construireVue(""); errV == nil {
		msg += " " + bilanDeLaSource(vue, groupe)
	}
	if version != "" {
		msg += "\n" + noteDeroule
	}
	reveillerLaPoussee()

	res := Resultat{Message: msg}
	if groupe == "" {
		res.Cible = "version attendue du parc"
	}
	return res, nil
}

// bilanDeLaSource dit combien d'agents suivent la cible qu'on vient de poser.
func bilanDeLaSource(vue VueAgents, groupe string) string {
	suivent, retard, avance, ailleurs := 0, 0, 0, 0
	for _, l := range vue.Machines {
		concernee := false
		if groupe == "" {
			concernee = true
		} else {
			for _, g := range l.Groupes {
				if g == groupe {
					concernee = true
				}
			}
		}
		if !concernee {
			continue
		}
		deCetteSource := (groupe == "" && l.Attendue.Source == parcversion.SourceParc) ||
			(groupe != "" && l.Attendue.Source == parcversion.SourceGroupe && l.Attendue.Groupe == groupe)
		if !deCetteSource {
			ailleurs++
			continue
		}
		suivent++
		switch l.Etat {
		case parcversion.EtatEnRetard, parcversion.EtatInconnue:
			retard++
		case parcversion.EtatEnAvance:
			avance++
		}
	}
	s := fmt.Sprintf("%d agent(s) la suivent, dont %d à mettre à jour", suivent, retard)
	if avance > 0 {
		s += fmt.Sprintf(" et %d en avance (jamais rétrogradés sans ordre explicite)", avance)
	}
	s += "."
	if ailleurs > 0 {
		if groupe == "" {
			s += fmt.Sprintf(" %d autre(s) suivent la cible d'un groupe ou une dérogation.", ailleurs)
		} else {
			s += fmt.Sprintf(" %d autre(s) machine(s) du groupe suivent une cible plus haute "+
				"d'un autre groupe, ou une dérogation.", ailleurs)
		}
	}
	return s
}

func definirDerogationAgent(_ Appelant, p Params) (Resultat, error) {
	machine := p.Get("computeur_id")
	if machine == "" {
		return Resultat{}, fmt.Errorf("machine manquante (computeur_id)")
	}
	version, err := versionSaisie(p)
	if err != nil {
		return Resultat{}, err
	}
	retrograder := strings.EqualFold(p.Get("downgrade"), "yes")
	if retrograder && version == "" {
		return Resultat{}, fmt.Errorf("--downgrade demande une version : il n'y a rien à rétrograder vers « none »")
	}
	if err := ecrireDerogation(machine, version, retrograder); err != nil {
		if errors.Is(err, dbclients.ErrIntrouvable) {
			return Resultat{}, fmt.Errorf("machine %q introuvable", machine)
		}
		return Resultat{}, err
	}

	var msg string
	if version == "" {
		msg = "Dérogation de " + machine + " retirée : elle suit de nouveau ses groupes ou le parc."
	} else {
		msg = "Dérogation posée : " + machine + " attend " + version + "."
		if retrograder {
			// Durable (TO-DO 204) : la machine la recevra à sa prochaine
			// connexion, quel que soit le core qui la tient, jusqu'à ce
			// qu'elle rende « installe » pour cette version.
			msg += " Rétrogradation AUTORISÉE : elle sera ramenée à " + version +
				" à sa prochaine demande, depuis n'importe quel core du cluster."
		}
	}
	if vue, errV := construireVue(""); errV == nil {
		for _, l := range vue.Machines {
			if l.ComputeurID == machine {
				msg += fmt.Sprintf(" Déclarée : %s, attendue : %s — %s.",
					l.VersionLisible, l.Attendue.Lisible(), l.Etat)
			}
		}
	}
	if version != "" {
		msg += "\n" + noteDeroule
	}
	reveillerLaPoussee()
	return Resultat{Message: msg}, nil
}

// relancer : remplaçable par les tests.
var relancer = miseajourmanager.Relancer

// relancerMiseAJour — « vlt agent update <machine> [--downgrade] ».
//
// Efface le dernier compte rendu, puis pousse l'ordre si la machine est
// connectée à ce core. Une machine en échec le reste tant qu'on ne le fait
// pas : c'est le geste qui dit « j'ai corrigé, réessaie ».
//
// --downgrade est le SEUL chemin d'une rétrogradation : l'agent refuse toute
// version inférieure à la sienne sans ce drapeau. Il n'est pas durable — il
// ne vaut que poussé maintenant, à une machine connectée à ce core.
func relancerMiseAJour(_ Appelant, p Params) (Resultat, error) {
	machine := p.Get("computeur_id")
	if machine == "" {
		return Resultat{}, fmt.Errorf("machine manquante (computeur_id)")
	}
	retrograder := strings.EqualFold(p.Get("downgrade"), "yes")
	r, err := relancer(machine, retrograder)
	if err != nil {
		if errors.Is(err, dbclients.ErrIntrouvable) {
			return Resultat{}, fmt.Errorf("agent %q introuvable", machine)
		}
		return Resultat{}, err
	}
	switch {
	case r.Ordre == nil:
		return Resultat{Message: machine + " : rien à faire — " + r.Motif + "."}, nil
	case r.Envoyee:
		msg := fmt.Sprintf("Ordre %s (dépôt %s) poussé à %s.", r.Ordre.Version, r.Ordre.Depot, machine)
		if r.Ordre.Retrograder {
			msg += " Rétrogradation explicite : l'agent l'acceptera."
		}
		return Resultat{Message: msg + "\n" + noteDeroule}, nil
	case r.Ordre.Retrograder:
		return Resultat{}, fmt.Errorf("%s n'est pas connectée à ce core : une rétrogradation ne vaut que "+
			"poussée, relancez-la depuis le core qui la tient (vlt status -c)", machine)
	}
	return Resultat{Message: fmt.Sprintf("%s n'est pas connectée à ce core : compte rendu effacé, elle aura "+
		"l'ordre %s à sa prochaine connexion, ou au prochain tour du core qui la tient.", machine, r.Ordre.Version)}, nil
}

// ecrireDepot : remplaçable par les tests.
var ecrireDepot = func(depot, auteur string) error {
	return dbsettings.SetString(database.GetDatabase(), miseajour.CleReglageDepot, depot,
		func(v string) error { _, err := miseajour.NormaliserDepot(v); return err }, auteur)
}

// definirDepot — « vlt agent depot <nom|none> ».
func definirDepot(a Appelant, p Params) (Resultat, error) {
	saisie := p.Get("depot")
	depot := ""
	if !parcversion.EstEffacement(saisie) {
		d, err := miseajour.NormaliserDepot(saisie)
		if err != nil {
			return Resultat{}, err
		}
		depot = d
	}
	if err := ecrireDepot(depot, a.Username); err != nil {
		return Resultat{}, err
	}
	res := Resultat{Cible: "dépôt des mises à jour"}
	if depot == "" {
		res.Message = "Dépôt des mises à jour : « " + miseajour.DepotParDefaut + " » (défaut)."
	} else {
		res.Message = "Dépôt des mises à jour : « " + depot + " ». Les ordres suivants le nommeront ; " +
			"il doit exister, de type vaultaire et public, sur chaque Nexus du cluster."
	}
	return res, nil
}
