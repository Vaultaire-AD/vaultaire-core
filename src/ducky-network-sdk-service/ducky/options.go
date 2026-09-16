package ducky

import (
	"fmt"
	"os"
	"time"

	"duckynetworkclient/V1/config"
	"duckynetworkclient/V1/duckynetwork/storage"
)

// ServiceAccount est le compte sous lequel un PROGRAMME s'authentifie.
//
// Ce n'est pas un compte de secours : c'est celui que le core reconnaît comme
// « ce n'est pas une personne, c'est un logiciel ». Un service qui s'annoncerait
// sous un autre nom serait traité comme un utilisateur et se verrait réclamer un
// vrai mot de passe.
const ServiceAccount = "vaultaire"

// Options décrit ce dont le paquet a besoin.
type Options struct {
	// ConfigPath : fichier YAML du service.
	//
	//	servers:
	//	  - ip: 10.0.0.1
	//	    port: 6666
	//	enrollment:
	//	  key: "..."
	//	  label: "proxy-preprod-01"
	//
	// FACULTATIF : son absence n'est pas une erreur si l'environnement porte le
	// nécessaire (VAULTAIRE_IP_CORE et VAULTAIRE_ENROLL_KEY). C'est le mode de
	// déploiement en conteneur, où deux variables suffisent.
	//
	// L'environnement l'emporte sur le fichier quand les deux sont présents.
	ConfigPath string

	// KeyPath : répertoire des clés et de l'identité. Contient, après
	// enrôlement, private_key.pem, public.pem, serveurpublickey.pem et
	// client_software.yaml.
	//
	// DOIT survivre aux redémarrages. Sans persistance, le service se réenrôle
	// à chaque lancement et consomme une utilisation de la clé d'enrôlement à
	// chaque fois — jusqu'à épuiser le quota et rester dehors.
	KeyPath string

	// Enroll autorise l'enrôlement automatique quand aucune identité n'existe.
	//
	// Laissé à faux, un service sans identité s'arrête avec un message clair au
	// lieu d'aller en créer une. C'est ce qu'on veut d'un déploiement où
	// l'enrôlement est un geste d'administration délibéré.
	Enroll bool

	// Username et Password ne servent qu'à ouvrir une session au nom d'une
	// PERSONNE. Laissés vides, le programme s'authentifie comme service.
	Username string
	Password string

	// Persistent maintient la connexion : à la perte du lien, le paquet
	// reconnecte au lieu de rendre la main.
	Persistent bool

	// LogPath, Debug, SilentConsole pilotent la journalisation.
	//
	// LogPath n'est qu'un défaut : VAULTAIRE_LOG_PATH l'emporte.
	LogPath       string
	Debug         bool
	SilentConsole bool

	// Timeout borne l'attente d'une session authentifiée.
	Timeout time.Duration
}

// DefaultTimeout laisse le temps aux deux allers-retours 01 puis 02.
const DefaultTimeout = 30 * time.Second

// prepare valide les prérequis et applique la configuration aux globales.
//
// # Pourquoi valider ici plutôt que laisser échouer plus loin
//
// Les fonctions de bas niveau renvoient « err » ou nil sur un fichier manquant,
// et l'échec ne se manifeste qu'au déchiffrement, sous la forme d'un « bourrage
// invalide » qui ne désigne pas le fichier absent. Un contrôle en amont coûte
// deux appels système et remplace une heure de recherche.
func (o *Options) prepare() error {
	// KeyPath devient facultatif quand VAULTAIRE_KEY_PATH est posée : la
	// variable l'emporterait de toute façon, exiger l'option en plus reviendrait
	// à demander deux fois la même chose et à refuser un déploiement
	// parfaitement configuré.
	if o.KeyPath == "" && os.Getenv(storage.EnvKeyPath) == "" {
		return fmt.Errorf("KeyPath est requis, ou la variable %s", storage.EnvKeyPath)
	}
	if o.ConfigPath == "" {
		return fmt.Errorf("ConfigPath est requis : fichier YAML du service")
	}
	if o.Timeout <= 0 {
		o.Timeout = DefaultTimeout
	}
	if o.Username == "" {
		o.Username = ServiceAccount
		o.Password = ServiceAccount
	}

	// KeyPath est posé AVANT toute lecture : les chemins de l'identité et des
	// clés en dérivent.
	//
	// C'est un DÉFAUT, pas une valeur définitive : storage.KeyPathResolu donne
	// la priorité à VAULTAIRE_KEY_PATH. L'ordre est le même partout dans le
	// socle — environnement d'abord, puis ce que le programme a posé, puis le
	// défaut du paquet.
	if o.KeyPath != "" {
		storage.KeyPath = o.KeyPath
	}
	storage.DEBUG = o.Debug
	storage.SilentConsole = o.SilentConsole
	// Persistent, et PAS IsServeur : ce dernier décrit la machine et sera
	// renseigné par client_software.yaml, qui écraserait la valeur posée ici.
	storage.Persistent = o.Persistent
	if o.LogPath != "" {
		storage.LogPath = o.LogPath
	}

	if err := config.LoadConfig(o.ConfigPath); err != nil {
		return err
	}
	if len(config.GetServers()) == 0 {
		return fmt.Errorf(
			"aucun serveur déclaré : renseignez la variable %s (« ip:port »), "+
				"ou la section servers de %s",
			config.EnvCore, o.ConfigPath)
	}
	return nil
}
