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
type Cibles struct {
	Source   string   `yaml:"source"`
	Adresses []string `yaml:"adresses,omitempty"`

	// Port : pour la source « cores », le port à joindre sur chaque core.
	//
	// La découverte (04_04) n'annonce que le port DUCKY des cores. Un relais
	// LDAPS qui reprendrait ces adresses telles quelles enverrait LDAPS sur le
	// port 6666 — défaut trouvé en éprouvant le TO-DO 72. Zéro : 636 pour un
	// relais ldaps, le port annoncé pour un relais ducky.
	Port int `yaml:"port,omitempty"`
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
