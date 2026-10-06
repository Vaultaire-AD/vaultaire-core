package decouverte

import (
	"fmt"
	"strconv"
	"strings"
	"sync"

	"duckynetworkclient/V1/duckynetwork/enligne"
	"duckynetworkclient/V1/duckynetwork/logs"
)

// Les relais d'un proxy, pilotés par le core — 04_18 → 04_19 (TO-DO 141).
//
// # Les deux trames
//
//	04_18  proxy → core   « voici mes relais, tels qu'ils tournent »
//	04_19  core → proxy   « voici ceux que je veux », ou « garde les tiens »
//
// La 04_18 est à la fois un COMPTE RENDU et une DEMANDE : le core y lit la
// configuration complète du proxy — c'est ce qu'affiche la page Cluster — et y
// répond par ce qu'il veut voir tourner. Une seule trame pour les deux, parce
// que la réponse dépend du compte rendu : le core ne renvoie sa configuration
// que si celle du proxy en diffère.
//
// Le core peut aussi émettre une 04_19 de lui-même, quand un administrateur
// vient de changer quelque chose : le proxy l'applique sans attendre son tour.
//
// # Ce paquet ne connaît pas les relais
//
// Il transporte un document JSON qu'il ne lit pas. Les relais vivent dans le
// proxy ; le SDK est partagé avec l'agent et le Nexus, qui n'en ont pas.
// Réservée au PROXY côté core : tout autre type de client qui émettrait une
// 04_18 se ferait fermer sa connexion.
//
// # Jamais vers un core qui ne l'annonce pas
//
// Voir enligne.PrefixeCapacites : un core antérieur à la 2.2 fermerait la
// connexion sur une trame qu'il ne connaît pas.

// Modes d'une 04_19.
const (
	// ModeCore : le core pilote. La trame porte la révision et les relais.
	ModeCore = "core"
	// ModeFichier : le core ne pilote pas ce proxy, ou vient de rendre la
	// main. Le proxy applique son fichier de configuration.
	ModeFichier = "fichier"
	// ModeInchange : rien à faire, le compte rendu correspond à la demande.
	ModeInchange = "inchange"
)

// ConfigurationRelais est une 04_19 lue.
type ConfigurationRelais struct {
	Mode     string
	Revision int
	// Document est le JSON des relais demandés, tel que le core l'a écrit.
	// Vide hors du mode « core ».
	Document string
}

var (
	relaisMu        sync.RWMutex
	surConfigRelais func(ConfigurationRelais)
)

// SurConfigurationRelais branche ce qui applique une 04_19. Un seul
// destinataire : le proxy. Sans lui, la trame est ignorée et le dit.
func SurConfigurationRelais(f func(ConfigurationRelais)) {
	relaisMu.Lock()
	surConfigRelais = f
	relaisMu.Unlock()
}

// ConstruireEtatRelais compose la 04_18. Le document tient sur UNE ligne : la
// trame est découpée par lignes, et un JSON indenté décalerait ses champs.
func ConstruireEtatRelais(sessionKey, clientID, document string) string {
	document = strings.ReplaceAll(strings.ReplaceAll(document, "\r", " "), "\n", " ")
	return strings.Join([]string{
		"04_18", "serveur_central", sessionKey, "vaultaire", clientID, document,
	}, "\n")
}

// EmettreEtatRelais envoie le compte rendu des relais au core. Rend faux, sans
// rien émettre, si le core de la connexion courante n'a pas annoncé qu'il
// sait le lire.
func EmettreEtatRelais(sessionKey func() string, document string) bool {
	if !enligne.CoreSait(enligne.CapaciteRelais) {
		return false
	}
	if envoyer == nil {
		logs.Write_log("WARNING", "relais pilotés : aucun émetteur branché, compte rendu abandonné")
		return false
	}
	cle := sessionKey()
	if strings.TrimSpace(cle) == "" {
		logs.Write_log("WARNING", "relais pilotés : aucune session établie, compte rendu abandonné")
		return false
	}
	envoyer(ConstruireEtatRelais(cle, clientID, document))
	return true
}

// AnalyserConfigurationRelais lit le contenu d'une 04_19 :
//
//	<mode>\n<révision>\n<document JSON>
//
// Le document est tout ce qui suit la révision, recollé : il ne devrait tenir
// que sur une ligne, mais le lire ainsi évite qu'un core qui l'écrirait sur
// plusieurs ne soit compris de travers.
func AnalyserConfigurationRelais(contenu string) (ConfigurationRelais, error) {
	lignes := strings.Split(strings.TrimSpace(contenu), "\n")
	mode := strings.ToLower(strings.TrimSpace(lignes[0]))
	switch mode {
	case ModeInchange:
		return ConfigurationRelais{Mode: ModeInchange}, nil
	case ModeFichier:
		return ConfigurationRelais{Mode: ModeFichier}, nil
	case ModeCore:
	default:
		return ConfigurationRelais{}, fmt.Errorf("04_19 : mode %q inconnu", lignes[0])
	}
	if len(lignes) < 3 {
		return ConfigurationRelais{}, fmt.Errorf("04_19 incomplète : mode « core » sans révision ou sans relais")
	}
	revision, err := strconv.Atoi(strings.TrimSpace(lignes[1]))
	if err != nil || revision < 1 {
		return ConfigurationRelais{}, fmt.Errorf("04_19 : révision illisible (%q)", lignes[1])
	}
	document := strings.TrimSpace(strings.Join(lignes[2:], "\n"))
	if document == "" {
		return ConfigurationRelais{}, fmt.Errorf("04_19 : révision %d sans relais", revision)
	}
	return ConfigurationRelais{Mode: ModeCore, Revision: revision, Document: document}, nil
}

// traiterConfigurationRelais remet une 04_19 à qui l'applique.
//
// Dans une goroutine : appliquer ouvre et ferme des ports, et cette fonction
// tourne sur le fil de LECTURE du tunnel — qui ne doit attendre personne.
func traiterConfigurationRelais(contenu string) {
	cfg, err := AnalyserConfigurationRelais(contenu)
	if err != nil {
		logs.Write_log("WARNING", "relais pilotés : "+err.Error())
		return
	}
	relaisMu.RLock()
	f := surConfigRelais
	relaisMu.RUnlock()
	if f == nil {
		logs.Write_log("WARNING", "relais pilotés : 04_19 reçue, mais ce programme ne porte pas de relais — ignorée")
		return
	}
	if cfg.Mode == ModeInchange {
		return
	}
	go func() {
		defer logs.Recover("application des relais du core")
		f(cfg)
	}()
}
