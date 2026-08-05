// Package clienttype déclare les types de programmes qui peuvent se connecter au
// core, et ce que chacun a le droit d'émettre sur le réseau Ducky.
//
// # Deux familles
//
// Un client BASIC est un agent : il représente une machine du parc. Il est créé
// d'abord sur le core (`vlt create`), qui génère sa paire de clés, puis installé
// sur la machine avec sa configuration.
//
// Un client SERVICE est une extension : il ajoute une fonction au cluster. Il
// s'enrôle seul à sa première connexion, avec une clé d'enrôlement, et génère sa
// propre paire — la clé privée ne quitte jamais son hôte.
//
// # Pourquoi ce catalogue est du code et pas de la donnée
//
// Un type détermine quelles trames un programme peut émettre : c'est une
// frontière de privilège. Éditable depuis une interface d'administration, elle
// permettrait à un administrateur d'accorder à un type des catégories que le
// code n'a jamais prévu de lui voir utiliser.
//
// C'est le même partage que pour les GPO : la structure est du code, les valeurs
// sont en base.
//
// # Granularité à la sous-trame
//
// Les droits ne portent pas sur la catégorie mais sur la trame complète, en
// « CC_SS ». L'interface web utilise la catégorie 02 pour s'authentifier, mais
// n'a rien à faire de 02_11, 02_12 et 02_13, qui sont l'inventaire matériel
// d'une machine — elle n'a ni processeur ni mémoire à déclarer.
//
// La liste est donc exhaustive, et c'est volontaire : une sous-trame ajoutée au
// protocole n'est émissible par personne tant qu'elle n'a pas été déclarée ici.
// Un oubli de mise à jour produit un refus visible, jamais une ouverture
// silencieuse.
package clienttype

import (
	"fmt"
	"sort"
	"strings"
)

// Family distingue un agent de machine d'un service du cluster.
type Family string

const (
	// FamilyAgent : créé sur le core, représente une machine du parc.
	FamilyAgent Family = "agent"
	// FamilyService : s'enrôle seul, ajoute une fonction au cluster.
	FamilyService Family = "service"
)

// Definition décrit un type de programme.
type Definition struct {
	Name        string
	Label       string
	Description string
	Family      Family

	// Frames énumère les trames que ce type peut ÉMETTRE, en « CC_SS ».
	Frames []string

	// AssertsUser autorise le programme à déclarer agir au nom d'un utilisateur
	// qu'il a lui-même authentifié.
	//
	// C'est le privilège le plus lourd du catalogue. Un programme qui le porte
	// peut agir au nom de n'importe quel compte : le RBAC est évalué sur
	// l'identité déclarée, donc il ne peut rien faire qu'aucun utilisateur ne
	// pourrait faire, mais il choisit lequel. Sa compromission est de la même
	// gravité que celle d'un portail d'authentification.
	AssertsUser bool
}

// Noms des types. Ils sont écrits tels quels dans id_logiciels.logiciel_type.
//
// LE CORE N'EST PAS DANS CE CATALOGUE, et ne peut pas y être. C'est lui qui juge
// la légitimité des trames qu'il reçoit en fonction du type de leur émetteur :
// il ne peut pas se juger lui-même. Il n'est d'ailleurs jamais enregistré comme
// client — GenerateClientSoftware n'est appelé que pour créer un agent, et
// l'enrôlement que pour créer un service.
const (
	Client = "vaultaire_client"
	Proxy  = "vaultaire_proxy"
	Web    = "vaultaire_web"
)

var catalogue = []Definition{
	{
		Name:   Client,
		Label:  "Agent Vaultaire",
		Family: FamilyAgent,
		Description: "Agent installé sur une machine du parc. Authentifie les " +
			"utilisateurs, tire ses GPO et applique les révocations.",

		// Liste relevée sur ce que l'agent ÉMET RÉELLEMENT
		// (src/vaultaire_client), et non sur la table du protocole, qui décrit
		// aussi des trames restées à l'état d'intention.
		//
		// Le drapeau `isServeur` d'un client ne change rien ici : c'est le même
		// binaire, qui émet les mêmes trames et se contente d'ouvrir en plus un
		// tunnel machine. Une machine serveur n'est pas plus digne de confiance
		// qu'un poste, elle a seulement plus de tâches — ce n'est donc pas une
		// frontière de privilège et ça n'a rien à faire dans ce catalogue.
		Frames: []string{
			"01_01",
			"02_01", "02_03", "02_05", "02_12",
			"03_01", "03_04", "03_06",
			"05_01", "05_05", "05_09", "05_12",
			"06_02", "06_03", "06_04",
		},
	},
	{
		Name:   Proxy,
		Label:  "Proxy",
		Family: FamilyService,
		Description: "Répartition de charge et découverte de service. " +
			"N'authentifie personne et ne reçoit aucune politique.",

		// Relevé sur src/vaultaire_proxy. Il n'émet PAS 04_05 (métriques),
		// contrairement à ce que la table du protocole laisse entendre : la
		// trame est spécifiée, elle n'est pas encore envoyée. Elle sera ajoutée
		// ici le jour où elle le sera là-bas, pas avant.
		Frames: []string{
			"01_01", "01_03",
			"04_01", "04_03", "04_07",
		},
	},
	{
		Name:   Web,
		Label:  "Interface web",
		Family: FamilyService,
		Description: "Interface d'administration. Authentifie les " +
			"administrateurs et relaie leurs commandes au core.",
		Frames: []string{
			"01_01", "01_03",
			"02_01", "02_03", "02_05",
			"04_09", "04_12", "04_14",
			"07_01", "07_04",
		},
		AssertsUser: true,
	},
}

// index accélère les recherches et fige la forme d'ensemble au démarrage.
var index = func() map[string]definitionIndex {
	m := make(map[string]definitionIndex, len(catalogue))
	for _, d := range catalogue {
		frames := make(map[string]struct{}, len(d.Frames))
		for _, f := range d.Frames {
			frames[f] = struct{}{}
		}
		m[d.Name] = definitionIndex{Definition: d, frames: frames}
	}
	return m
}()

type definitionIndex struct {
	Definition
	frames map[string]struct{}
}

// Lookup retourne la définition d'un type.
func Lookup(name string) (Definition, bool) {
	d, ok := index[strings.TrimSpace(name)]
	return d.Definition, ok
}

// Validate refuse un type absent du catalogue.
//
// Appelée à la création d'un client. Sans elle, logiciel_type reste le
// VARCHAR libre qu'il a toujours été, et une faute de frappe crée un client qui
// ne pourra plus jamais rien émettre une fois MayEmit en service.
func Validate(name string) error {
	if _, ok := Lookup(name); !ok {
		return fmt.Errorf("type de client inconnu : %q (types connus : %s)",
			name, strings.Join(Names(), ", "))
	}
	return nil
}

// MayEmit indique si un type a le droit d'émettre une trame donnée.
//
// FAIL-CLOSED : un type inconnu n'émet rien, et une trame non déclarée n'est
// émise par personne.
//
// Les trames d'enrôlement 01_03 et 01_04 ne passent pas par ici : elles
// précèdent l'existence du client, donc de son type. C'est la clé d'enrôlement
// qui les autorise, et le type qu'elle porte qui décide de la suite. Elles
// figurent tout de même dans les listes ci-dessus, pour que le catalogue se lise
// comme la description complète de ce qu'un programme fait sur le réseau.
func MayEmit(clientType, frame string) bool {
	d, ok := index[strings.TrimSpace(clientType)]
	if !ok {
		return false
	}
	_, allowed := d.frames[strings.TrimSpace(frame)]
	return allowed
}

// MayAssertUser indique si un type peut déclarer agir au nom d'un utilisateur.
func MayAssertUser(clientType string) bool {
	d, ok := Lookup(clientType)
	return ok && d.AssertsUser
}

// IsService indique si un type s'enrôle seul plutôt que d'être créé sur le core.
func IsService(clientType string) bool {
	d, ok := Lookup(clientType)
	return ok && d.Family == FamilyService
}

// Names retourne les types connus, triés.
func Names() []string {
	out := make([]string, 0, len(catalogue))
	for _, d := range catalogue {
		out = append(out, d.Name)
	}
	sort.Strings(out)
	return out
}

// ServiceNames retourne les seuls types de la famille service, triés.
//
// Utilisé à l'émission d'une clé d'enrôlement : une clé ne peut viser qu'un
// service. Un agent se crée sur le core, il n'a rien à enrôler.
func ServiceNames() []string {
	var out []string
	for _, d := range catalogue {
		if d.Family == FamilyService {
			out = append(out, d.Name)
		}
	}
	sort.Strings(out)
	return out
}

// All retourne le catalogue complet, pour l'affichage.
func All() []Definition {
	out := make([]Definition, len(catalogue))
	copy(out, catalogue)
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}
