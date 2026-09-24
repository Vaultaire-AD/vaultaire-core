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
//	https   navigateurs, dnf, docker → services HTTPS (Nexus…)   PRÉVU
//	ldap    applications → cores (LDAP, 389)                     PRÉVU
//	ldaps   applications → cores (LDAPS, 636)                    PRÉVU
//
// Les types prévus sont reconnus par la configuration, mais refusés à
// l'activation tant que ce qui les rend sûrs n'existe pas : pour LDAP/S, le SAN
// du certificat du core qui couvre les proxies et la limitation par source
// côté core ; pour HTTPS, la découverte des services (le core n'annonce que
// les cores et les proxies en 04_04). Voir TO-DO 72.
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
var actif = map[Type]bool{TypeDucky: true}

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
	// SourceService : un TYPE de service du cluster (« service:vaultaire_nexus »).
	// Prévu pour le relais HTTPS : demande que le core annonce les services.
	SourceService = "service:"
)

// Cibles dit vers qui relayer.
type Cibles struct {
	Source   string   `yaml:"source"`
	Adresses []string `yaml:"adresses,omitempty"`
}

// Relais est la configuration d'un relais.
type Relais struct {
	Nom    string `yaml:"nom"`
	Type   Type   `yaml:"type"`
	Ecoute string `yaml:"ecoute"`
	Cibles Cibles `yaml:"cibles"`

	// Délai pour joindre UNE cible. Court à dessein : un client qui attend ne
	// fait rien, et le relais essaie la suivante.
	DelaiConnexionSecondes int `yaml:"delai_connexion_secondes,omitempty"`
	// Inactivité au-delà de laquelle une connexion relayée est fermée. Doit
	// dépasser le battement du protocole (Ducky : 02_11 toutes les 2 min).
	InactiviteSecondes int `yaml:"inactivite_secondes,omitempty"`
	// Plafonds : total et par adresse source.
	MaxConnexions int `yaml:"max_connexions,omitempty"`
	MaxParSource  int `yaml:"max_par_source,omitempty"`
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
	return fmt.Sprintf("relais de type %q prévu mais pas encore activé (TO-DO 72) : "+
		"seul « ducky » est disponible aujourd'hui", e.Type)
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
		r.Cibles.Source = SourceCores
	}
	switch {
	case r.Cibles.Source == SourceCores:
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
		return fmt.Errorf("relais %q : la source %q (services du cluster) est prévue avec le relais HTTPS, pas encore disponible (TO-DO 72)",
			r.Nom, r.Cibles.Source)
	default:
		return fmt.Errorf("relais %q : source de cibles %q inconnue (cores, liste)", r.Nom, r.Cibles.Source)
	}
	return nil
}

// fichier est la partie du fichier de configuration du proxy propre aux relais.
// Le reste (servers, enrollment) est lu par le SDK.
type fichier struct {
	Relais []Relais `yaml:"relais"`
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
func Charger(chemin string, portAnnonce int) ([]Relais, error) {
	var f fichier
	data, err := os.ReadFile(chemin)
	switch {
	case err == nil:
		if err := yaml.Unmarshal(data, &f); err != nil {
			return nil, fmt.Errorf("configuration %s illisible : %w", chemin, err)
		}
	case !os.IsNotExist(err):
		return nil, fmt.Errorf("lecture de %s : %w", chemin, err)
	}
	if len(f.Relais) == 0 {
		f.Relais = []Relais{{Nom: "ducky", Type: TypeDucky, Ecoute: ":" + strconv.Itoa(portAnnonce),
			Cibles: Cibles{Source: SourceCores}}}
	}
	noms := map[string]bool{}
	ecoutes := map[string]bool{}
	ducky := 0
	for i := range f.Relais {
		r := &f.Relais[i]
		if err := r.Valider(); err != nil {
			return nil, err
		}
		if noms[r.Nom] {
			return nil, fmt.Errorf("relais %q déclaré deux fois", r.Nom)
		}
		noms[r.Nom] = true
		if ecoutes[r.Ecoute] {
			return nil, fmt.Errorf("deux relais écoutent sur %s", r.Ecoute)
		}
		ecoutes[r.Ecoute] = true
		if r.Type == TypeDucky {
			ducky++
			_, p, _ := net.SplitHostPort(r.Ecoute)
			if p != strconv.Itoa(portAnnonce) {
				return nil, fmt.Errorf("relais Ducky %q sur le port %s, alors que le port annoncé aux agents est %d (-listen-port) : "+
					"les agents se présenteraient là où rien ne répond", r.Nom, p, portAnnonce)
			}
		}
	}
	if ducky > 1 {
		return nil, fmt.Errorf("%d relais Ducky déclarés : un seul port est annoncé aux agents", ducky)
	}
	return f.Relais, nil
}
