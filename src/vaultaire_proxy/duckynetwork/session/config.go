package session

import (
	"fmt"
	"strings"
	"time"

	"vaultaire_proxy/duckynetwork/storage"
	tramesmanager "vaultaire_proxy/duckynetwork/trames_manager"
)

// Config décrit ce qu'un programme hôte doit fournir pour se connecter.
type Config struct {
	// ServerAddress est l'adresse du core, « hôte:port ».
	ServerAddress string

	// KeyDir contient la paire du client, la clé publique du core et
	// l'identité. Doit survivre aux redémarrages : sinon le programme se
	// réenrôle à chaque lancement et consomme une place de clé d'enrôlement.
	KeyDir string

	// EnrollmentKey n'est utilisée qu'au premier démarrage, ou après un
	// réenrôlement forcé. Elle porte le TYPE du client : c'est elle qui décide
	// de ce que le core nous laissera émettre.
	EnrollmentKey string

	// Label est le nom lisible affiché côté core. Purement descriptif.
	Label string

	// Username et Password servent à l'étape 02.
	//
	// Laissés vides, le programme s'authentifie sous le compte de service
	// « vaultaire » — ce que fait tout programme qui se présente LUI-MÊME :
	// agent au démarrage, proxy, interface web.
	//
	// Les renseigner n'a de sens que pour ouvrir une session au nom d'une
	// PERSONNE. Authentifier un utilisateur tiers ne passe pas par là mais par
	// la catégorie 03, qui ne transporte jamais son mot de passe.
	Username string
	Password string

	// MachineInfo fournit le contenu de la trame 02_12 : hostname, système,
	// mémoire, processeurs — une ligne chacun, dans cet ordre.
	//
	// Laissé nil, une version portable est utilisée. Un agent, qui sait lire
	// l'inventaire réel de sa machine, remplace ce champ.
	MachineInfo func() string

	// AuthTimeout borne l'attente de l'issue de l'étape 02.
	//
	// Sans elle, un core qui accepterait la connexion TCP puis se tairait
	// laisserait le programme bloqué à la connexion, sans jamais tenter de se
	// reconnecter — la panne la plus difficile à diagnostiquer, parce que rien
	// n'échoue.
	AuthTimeout time.Duration

	// OnReady est appelé une fois la session chiffrée établie, à chaque
	// connexion — reconnexions comprises. C'est l'endroit où rejouer ce qui ne
	// survit pas à une coupure : enregistrement dans le cluster, souscriptions.
	//
	// Une erreur renvoyée ici fait retomber la connexion et déclenche une
	// nouvelle tentative : un programme qui ne peut pas s'annoncer n'a rien à
	// faire dans la boucle de réception.
	OnReady func(session *storage.DuckySession) error

	// AllowReEnroll autorise le réenrôlement automatique quand le core refuse
	// notre identité.
	//
	// Laissé à faux, une identité révoquée arrête le programme au lieu de le
	// laisser reprendre une place dans le parc — ce qui est le comportement
	// voulu si la révocation était délibérée. Un service qu'on veut autonome
	// (un proxy) le met à vrai.
	AllowReEnroll bool

	// ReconnectDelay est le délai initial entre deux tentatives ; il double à
	// chaque échec jusqu'à MaxReconnectDelay.
	ReconnectDelay    time.Duration
	MaxReconnectDelay time.Duration

	// Spliter aiguille les trames reçues. Laissé nil, un Spliter est créé avec
	// les gestionnaires 01 et 02 par défaut.
	Spliter *tramesmanager.Spliter
}

// Valeurs par défaut de la temporisation de reconnexion.
const (
	DefaultReconnectDelay    = 5 * time.Second
	DefaultMaxReconnectDelay = 5 * time.Minute
	DefaultAuthTimeout       = 30 * time.Second
)

// normalize valide la configuration et applique les valeurs par défaut.
func (c *Config) normalize() error {
	if strings.TrimSpace(c.ServerAddress) == "" {
		return fmt.Errorf("ServerAddress est requis")
	}
	if strings.TrimSpace(c.KeyDir) == "" {
		return fmt.Errorf("KeyDir est requis")
	}
	if c.AuthTimeout <= 0 {
		c.AuthTimeout = DefaultAuthTimeout
	}
	if c.ReconnectDelay <= 0 {
		c.ReconnectDelay = DefaultReconnectDelay
	}
	if c.MaxReconnectDelay < c.ReconnectDelay {
		c.MaxReconnectDelay = DefaultMaxReconnectDelay
	}
	if c.MaxReconnectDelay < c.ReconnectDelay {
		c.MaxReconnectDelay = c.ReconnectDelay
	}
	return nil
}
