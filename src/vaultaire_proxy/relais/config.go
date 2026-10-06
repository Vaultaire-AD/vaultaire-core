// Package relais transporte des connexions TCP d'un client vers un nœud du
// cluster, SANS LES LIRE (TO-DO 38).
//
// # Ce qu'un relais est, et ce qu'il n'est pas
//
// Un relais écoute un port, accepte une connexion, en ouvre une vers une cible,
// et recopie les octets dans les deux sens. Il ne termine rien : ni la session
// Ducky, ni TLS. C'est l'arbitrage 2 : depuis le point 29, le mot de passe
// transite dans le tunnel ; un proxy qui déchiffrerait deviendrait un point de
// collecte des mots de passe du parc.
//
// Conséquence : le relais est le même code quel que soit le protocole. Ce qui
// change d'un type à l'autre, c'est seulement VERS QUI il relaie et sur quel
// port il écoute par défaut :
//
//	ducky   agents → cores (Ducky, 6666)                         ACTIF
//	https   navigateurs, dnf, docker → services HTTPS (Nexus…)   ACTIF (TO-DO 72)
//	ldaps   applications → cores (LDAPS, 636)                    ACTIF (TO-DO 72)
//	ldap    applications → cores (LDAP, 389)                     REFUSÉ
//
// HTTPS apprend ses cibles du core par la 04_15 (services d'un type, réservée
// aux proxies). LDAPS place devant chaque connexion un en-tête PROXY v2 qui
// porte l'adresse du client : le core ne le croit que d'un proxy enregistré,
// et la limitation des échecs de bind compte ainsi par client, pas par site.
//
// LDAP en clair reste REFUSÉ : relayé, il ferait voyager des mots de passe en
// clair du site jusqu'au core — c'est-à-dire sur le lien le plus long, celui
// qu'on protège le moins bien —, et le core n'implémente pas StartTLS.
package relais

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Type est le protocole relayé.
type Type string

const (
	TypeDucky Type = "ducky"
	TypeHTTPS Type = "https"
	TypeLDAP  Type = "ldap"
	TypeLDAPS Type = "ldaps"
)

// actif dit quels types peuvent être démarrés aujourd'hui.
var actif = map[Type]bool{TypeDucky: true, TypeHTTPS: true, TypeLDAPS: true}

// raisonRefus dit pourquoi un type reconnu n'est pas activable.
var raisonRefus = map[Type]string{
	TypeLDAP: "relayé, LDAP en clair ferait voyager les mots de passe en clair du " +
		"site jusqu'au core, et le core n'implémente pas StartTLS — employez « ldaps »",
}

// portParDefaut est le port d'écoute si la configuration n'en donne pas.
var portParDefaut = map[Type]int{TypeDucky: 6666, TypeHTTPS: 443, TypeLDAP: 389, TypeLDAPS: 636}

// Sources de cibles.
const (
	// SourceCores : les cores du cluster, appris par la découverte (04_04),
	// puis les serveurs du fichier de configuration du proxy en dernier
	// recours.
	SourceCores = "cores"
	// SourceListe : les adresses écrites dans la configuration, dans l'ordre.
	SourceListe = "liste"
	// SourceService : un TYPE de service du cluster (« service:vaultaire_nexus »),
	// appris du core par la 04_15. Pour le relais HTTPS.
	SourceService = "service:"
)

// Cibles dit vers qui relayer.
//
// Les étiquettes JSON sont celles du protocole (04_18 et 04_19, TO-DO 141) :
// le core écrit et lit le même document sans partager ce code. Elles suivent
// les étiquettes YAML à dessein — un relais se décrit de la même façon dans le
// fichier du proxy, dans la trame et dans la base du core.
type Cibles struct {
	Source   string   `yaml:"source" json:"source"`
	Adresses []string `yaml:"adresses,omitempty" json:"adresses,omitempty"`

	// Port : pour la source « cores », le port à joindre sur chaque core.
	//
	// La découverte (04_04) n'annonce que le port DUCKY des cores. Un relais
	// LDAPS qui reprendrait ces adresses telles quelles enverrait LDAPS sur le
	// port 6666 — défaut trouvé en éprouvant le TO-DO 72. Zéro : 636 pour un
	// relais ldaps, le port annoncé pour un relais ducky.
	Port int `yaml:"port,omitempty" json:"port,omitempty"`
}

// PortLDAPSParDefaut est le port LDAPS des cores quand la configuration du
// relais n'en donne pas.
const PortLDAPSParDefaut = 636

// PortCible rend le port à substituer aux adresses des cores, ou 0 pour les
// garder telles qu'annoncées.
func (r Relais) PortCible() int {
	if r.Cibles.Port > 0 {
		return r.Cibles.Port
	}
	if r.Type == TypeLDAPS && r.Cibles.Source == SourceCores {
		return PortLDAPSParDefaut
	}
	return 0
}

// Relais est la configuration d'un relais.
type Relais struct {
	Nom    string `yaml:"nom" json:"nom"`
	Type   Type   `yaml:"type" json:"type"`
	Ecoute string `yaml:"ecoute" json:"ecoute"`
	Cibles Cibles `yaml:"cibles" json:"cibles"`

	// Délai pour joindre UNE cible. Court à dessein : un client qui attend ne
	// fait rien, et le relais essaie la suivante.
	DelaiConnexionSecondes int `yaml:"delai_connexion_secondes,omitempty" json:"delai_connexion_secondes,omitempty"`
	// Inactivité au-delà de laquelle une connexion relayée est fermée. Doit
	// dépasser le battement du protocole (Ducky : 02_11 toutes les 2 min).
	InactiviteSecondes int `yaml:"inactivite_secondes,omitempty" json:"inactivite_secondes,omitempty"`
	// Plafonds : total et par adresse source.
	MaxConnexions int `yaml:"max_connexions,omitempty" json:"max_connexions,omitempty"`
	MaxParSource  int `yaml:"max_par_source,omitempty" json:"max_par_source,omitempty"`
}

// Effectif rend le relais avec ses défauts RÉSOLUS : les quatre réglages
// facultatifs portent la valeur réellement appliquée, et non zéro.
//
// Pour le compte rendu au core. Afficher « 0 » pour un plafond laisserait
// croire qu'il n'y en a pas ; afficher « défaut » obligerait la page à
// connaître des constantes qui vivent ici.
func (r Relais) Effectif() Relais {
	r.DelaiConnexionSecondes = int(r.DelaiConnexion() / time.Second)
	r.InactiviteSecondes = int(r.Inactivite() / time.Second)
	r.MaxConnexions = r.maxConnexions()
	r.MaxParSource = r.maxParSource()
	return r
}

// Défauts.
const (
	DelaiConnexionParDefaut = 3 * time.Second
	InactiviteParDefaut     = 15 * time.Minute
	MaxConnexionsParDefaut  = 4000
	MaxParSourceParDefaut   = 20
)

// DelaiConnexion rend le délai effectif.
func (r Relais) DelaiConnexion() time.Duration {
	if r.DelaiConnexionSecondes > 0 {
		return time.Duration(r.DelaiConnexionSecondes) * time.Second
	}
	return DelaiConnexionParDefaut
}

// Inactivite rend la durée effective.
func (r Relais) Inactivite() time.Duration {
	if r.InactiviteSecondes > 0 {
		return time.Duration(r.InactiviteSecondes) * time.Second
	}
	return InactiviteParDefaut
}

func (r Relais) maxConnexions() int {
	if r.MaxConnexions > 0 {
		return r.MaxConnexions
	}
	return MaxConnexionsParDefaut
}

func (r Relais) maxParSource() int {
	if r.MaxParSource > 0 {
		return r.MaxParSource
	}
	return MaxParSourceParDefaut
}

// ErrTypePrevu signale un type reconnu mais pas encore activable.
type ErrTypePrevu struct{ Type Type }

func (e ErrTypePrevu) Error() string {
	return fmt.Sprintf("relais de type %q refusé : %s", e.Type, raisonRefus[e.Type])
}

// EnvoieEnteteProxy dit si le relais place un en-tête PROXY v2 devant chaque
// connexion.
//
// LDAPS seulement, et sans réglage : le core ne lit l'en-tête que sur ses
// écoutes LDAP. Envoyé à l'écoute Ducky ou à un Nexus, il serait pris pour le
// début du protocole et la connexion échouerait. Un réglage de plus ne
// permettrait que cette erreur-là.
func (r Relais) EnvoieEnteteProxy() bool {
	return r.Type == TypeLDAPS
}

// TypeDeService rend le type de service d'une source « service:… », ou "".
func (r Relais) TypeDeService() string {
	if strings.HasPrefix(r.Cibles.Source, SourceService) {
		return strings.TrimSpace(strings.TrimPrefix(r.Cibles.Source, SourceService))
	}
	return ""
}

// ServicesSuivis rend les types de services dont les relais ont besoin, sans
// doublon — ce que le proxy demandera au core.
func ServicesSuivis(liste []Relais) []string {
	vus := map[string]bool{}
	var out []string
	for _, r := range liste {
		if t := r.TypeDeService(); t != "" && !vus[t] {
			vus[t] = true
			out = append(out, t)
		}
	}
	return out
}

// Valider contrôle une configuration de relais.
func (r *Relais) Valider() error {
	if r.Type == "" {
		r.Type = TypeDucky
	}
	if _, connu := portParDefaut[r.Type]; !connu {
		return fmt.Errorf("relais %q : type %q inconnu (ducky, https, ldap, ldaps)", r.Nom, r.Type)
	}
	if !actif[r.Type] {
		return ErrTypePrevu{Type: r.Type}
	}
	if r.Nom == "" {
		r.Nom = string(r.Type)
	}
	if r.Ecoute == "" {
		r.Ecoute = ":" + strconv.Itoa(portParDefaut[r.Type])
	}
	if _, p, err := net.SplitHostPort(r.Ecoute); err != nil || p == "" {
		return fmt.Errorf("relais %q : écoute %q invalide (attendu « [adresse]:port »)", r.Nom, r.Ecoute)
	}
	if r.Cibles.Source == "" {
		if r.Type == TypeHTTPS {
			// Pas de défaut pour HTTPS : « cores » y serait faux (voir plus bas),
			// et deviner un type de service serait pire que le demander.
			return fmt.Errorf("relais %q : un relais https doit nommer ses cibles — "+
				"source « service:vaultaire_nexus » ou « liste »", r.Nom)
		}
		r.Cibles.Source = SourceCores
	}
	if r.Cibles.Port != 0 {
		if r.Cibles.Source != SourceCores {
			return fmt.Errorf("relais %q : « port » ne vaut que pour la source « cores » — "+
				"une liste porte déjà le port de chaque adresse", r.Nom)
		}
		if r.Cibles.Port < 1 || r.Cibles.Port > 65535 {
			return fmt.Errorf("relais %q : port cible %d invalide", r.Nom, r.Cibles.Port)
		}
	}
	switch {
	case r.Cibles.Source == SourceCores:
		if r.Type == TypeHTTPS {
			// Les cores appris sont leurs adresses DUCKY : relayer du HTTPS vers
			// le port 6666 d'un core ne mènerait nulle part.
			return fmt.Errorf("relais %q : la source « cores » donne les adresses Ducky des cores, "+
				"pas un service HTTPS — employez « service:<type> » ou « liste »", r.Nom)
		}
	case r.Cibles.Source == SourceListe:
		if len(r.Cibles.Adresses) == 0 {
			return fmt.Errorf("relais %q : source « liste » sans adresse", r.Nom)
		}
		for _, a := range r.Cibles.Adresses {
			if _, _, err := net.SplitHostPort(a); err != nil {
				return fmt.Errorf("relais %q : cible %q invalide (attendu « hôte:port »)", r.Nom, a)
			}
		}
	case strings.HasPrefix(r.Cibles.Source, SourceService):
		if r.Type != TypeHTTPS {
			return fmt.Errorf("relais %q : la source %q ne sert qu'au relais https — un %s relaie vers les cores",
				r.Nom, r.Cibles.Source, r.Type)
		}
		if r.TypeDeService() == "" {
			return fmt.Errorf("relais %q : source « service: » sans type (ex. « service:vaultaire_nexus »)", r.Nom)
		}
	default:
		return fmt.Errorf("relais %q : source de cibles %q inconnue (cores, liste, service:<type>)", r.Nom, r.Cibles.Source)
	}
	return nil
}

// fichier est la partie du fichier de configuration du proxy propre aux relais.
// Le reste (servers, enrollment) est lu par le SDK.
type fichier struct {
	Relais []Relais `yaml:"relais"`

	// Pilotage dit si ce proxy accepte que le core pilote ses relais
	// (TO-DO 141). Un POINTEUR : absent vaut « oui », et seul un « false »
	// écrit le refuse.
	Pilotage *bool `yaml:"pilotage_par_le_core"`
}

// Refus est un relais écarté d'une liste, et pourquoi.
type Refus struct {
	Relais Relais
	Motif  string
	// err garde l'erreur d'origine : Charger la rend telle quelle, et un
	// appelant peut y reconnaître ErrTypePrevu.
	err error
}

func refuser(r Relais, err error) Refus { return Refus{Relais: r, Motif: err.Error(), err: err} }

// Trier contrôle une liste de relais et sépare ceux qui peuvent tourner de
// ceux qui ne le peuvent pas (TO-DO 141).
//
// # Pourquoi les deux listes
//
// Charger arrêtait à la première faute : c'est juste pour un fichier, que
// quelqu'un vient d'écrire et peut corriger avant de démarrer. Ce ne l'est
// plus pour une liste poussée par le core : refuser dix relais parce que le
// onzième demande un port mal écrit couperait un site pour une faute de frappe
// faite ailleurs. Ici chaque relais est jugé seul, et les autres vivent.
//
// # Les règles de LISTE
//
// Deux relais ne portent pas le même nom, ni la même écoute. Le relais Ducky
// écoute sur le port ANNONCÉ au cluster — sinon les agents se présenteraient
// là où rien ne répond — et il n'y en a qu'un, puisqu'un seul port est
// annoncé. Quand deux relais sont en conflit, c'est le SECOND qui est écarté :
// l'ordre de la liste tranche, et il est stable.
//
// Les relais retenus sortent normalisés : Valider a posé leurs défauts.
func Trier(liste []Relais, portAnnonce int) (retenus []Relais, refus []Refus) {
	noms := map[string]bool{}
	ecoutes := map[string]bool{}
	ducky := 0
	for _, r := range liste {
		if err := r.Valider(); err != nil {
			refus = append(refus, refuser(r, err))
			continue
		}
		if noms[r.Nom] {
			refus = append(refus, refuser(r, fmt.Errorf("relais %q déclaré deux fois", r.Nom)))
			continue
		}
		_, port, _ := net.SplitHostPort(r.Ecoute)
		// Le port 0 demande un port libre au système : deux relais qui le
		// demandent n'écoutent pas au même endroit.
		if port != "0" && ecoutes[r.Ecoute] {
			refus = append(refus, refuser(r, fmt.Errorf("deux relais écoutent sur %s", r.Ecoute)))
			continue
		}
		if r.Type == TypeDucky {
			if port != strconv.Itoa(portAnnonce) {
				refus = append(refus, refuser(r, fmt.Errorf(
					"relais Ducky %q sur le port %s, alors que le port annoncé aux agents est %d (-listen-port) : "+
						"les agents se présenteraient là où rien ne répond", r.Nom, port, portAnnonce)))
				continue
			}
			if ducky++; ducky > 1 {
				refus = append(refus, refuser(r, fmt.Errorf(
					"%d relais Ducky déclarés : un seul port est annoncé aux agents", ducky)))
				continue
			}
		}
		noms[r.Nom] = true
		ecoutes[r.Ecoute] = true
		retenus = append(retenus, r)
	}
	return retenus, refus
}

// PorteUnRelaisDucky dit si une liste retenue porte le relais Ducky.
func PorteUnRelaisDucky(retenus []Relais) bool {
	for _, r := range retenus {
		if r.Type == TypeDucky {
			return true
		}
	}
	return false
}

// ParDefaut rend la liste d'un proxy sans section « relais » : un seul relais
// Ducky vers les cores, sur le port annoncé au cluster.
func ParDefaut(portAnnonce int) []Relais {
	return []Relais{{Nom: "ducky", Type: TypeDucky, Ecoute: ":" + strconv.Itoa(portAnnonce),
		Cibles: Cibles{Source: SourceCores}}}
}

func lire(chemin string) (fichier, error) {
	var f fichier
	data, err := os.ReadFile(chemin)
	switch {
	case err == nil:
		if err := yaml.Unmarshal(data, &f); err != nil {
			return f, fmt.Errorf("configuration %s illisible : %w", chemin, err)
		}
	case !os.IsNotExist(err):
		return f, fmt.Errorf("lecture de %s : %w", chemin, err)
	}
	return f, nil
}

// Charger lit la section « relais » du fichier de configuration.
//
// Sans section — les fichiers d'avant la 2.2 —, un seul relais Ducky vers les
// cores, sur le port annoncé au cluster (-listen-port). C'est ce que
// l'annonce promettait déjà aux agents.
//
// Le relais Ducky doit écouter sur le port ANNONCÉ : sinon les agents se
// présenteraient là où rien ne répond. Un relais Ducky configuré sur un autre
// port est refusé.
//
// Un fichier est STRICT : la première faute arrête tout, et c'est l'erreur
// qu'on rend. Voir Trier pour le cas d'une liste poussée par le core.
func Charger(chemin string, portAnnonce int) ([]Relais, error) {
	f, err := lire(chemin)
	if err != nil {
		return nil, err
	}
	if len(f.Relais) == 0 {
		f.Relais = ParDefaut(portAnnonce)
	}
	retenus, refus := Trier(f.Relais, portAnnonce)
	if len(refus) > 0 {
		return nil, refus[0].err
	}
	return retenus, nil
}

// PilotageAutorise dit si le fichier laisse le core piloter les relais de ce
// proxy. Vrai sans la clé, et vrai si le fichier est illisible — Charger, lu
// juste avant, aura déjà arrêté le proxy sur cette erreur.
//
// # Pourquoi un proxy peut refuser
//
// Piloter les relais, c'est décider des ports qu'une machine ouvre et vers
// quoi elle redirige. Par défaut le proxy fait confiance à son core, comme il
// le fait déjà pour la liste des cibles. Un site qui veut que ce pouvoir reste
// à qui administre la machine écrit « pilotage_par_le_core: false » : le proxy
// continue de rendre compte, le core voit tout, et ne change rien.
func PilotageAutorise(chemin string) bool {
	f, err := lire(chemin)
	if err != nil || f.Pilotage == nil {
		return true
	}
	return *f.Pilotage
}
