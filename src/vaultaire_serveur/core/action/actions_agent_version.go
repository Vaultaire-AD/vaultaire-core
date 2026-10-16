package action

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"vaultaire/core/database"
	dbclients "vaultaire/core/database/db_clients"
	dbsettings "vaultaire/core/database/db_settings"
	"vaultaire/core/parcversion"
)

// La version attendue des agents, et la vue « constaté vs attendu » — TO-DO 111.
//
// # Ce que ces actions font, et ce qu'elles ne font pas encore
//
// Elles posent une CONSIGNE et la confrontent à ce que chaque agent déclare.
// Aucun agent ne s'y conforme encore de lui-même : l'ordre de mise à jour
// (point 115) et le basculement (point 116) viendront lire cette consigne. La
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
var ActionsVersionAgent = []string{"agent.status", "agent.set_target", "agent.pin"}

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
}

// Nom rend le nom d'hôte, ou l'identifiant tant que la machine n'en a pas
// déclaré.
func (l LigneAgent) Nom() string {
	if strings.TrimSpace(l.Hostname) != "" {
		return l.Hostname
	}
	return l.ComputeurID
}

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
}

// construireVue lit le parc et résout la cible de chaque agent.
//
// Une erreur de lecture est rendue telle quelle, jamais remplacée par une vue
// vide : « aucune cible » dit qu'aucune machine ne bougera, et l'afficher
// parce que la base a flanché serait faux sur ce qui va se passer.
func construireVue(groupe string) (VueAgents, error) {
	vue := VueAgents{Groupe: groupe, Compteurs: map[parcversion.Etat]int{}}

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
			Attendue: attendue,
			Etat:     parcversion.Situer(a.Declaree, attendue),
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
	ecrireDerogation = func(computeurID, version string) error {
		return dbclients.DefinirDerogation(database.GetDatabase(), computeurID, version)
	}
)

// noteProvisoire est dite à chaque écriture tant que les points 115 et 116 ne
// sont pas faits : sans elle, on croirait avoir lancé une mise à jour.
const noteProvisoire = "Aucun agent ne se met encore à jour de lui-même : " +
	"la cible sert pour l'instant à la vue « vlt agent »."

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
		msg += "\n" + noteProvisoire
	}

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
	if err := ecrireDerogation(machine, version); err != nil {
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
		msg += "\n" + noteProvisoire
	}
	return Resultat{Message: msg}, nil
}
