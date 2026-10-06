package decouverte

import (
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"duckynetworkclient/V1/duckynetwork/logs"
)

// Les services d'un type — 04_15 → 04_16 (TO-DO 72).
//
// Réservé au PROXY : c'est la liste des Nexus vers qui son relais HTTPS
// transporte les connexions d'un site. Le core refuse la 04_15 à tout autre
// type de client.
//
// # Pourquoi une cadence plus courte que la découverte des cores
//
// La liste des cores sert à se reconnecter : un agent qui la reçoit tard
// bascule de toute façon sur l'adresse suivante qu'il a déjà. Ici, un Nexus
// ajouté n'est joignable par le site qu'une fois la liste reçue, et un Nexus
// retiré de la rotation continue d'être tenté en premier jusque-là. Cinq
// minutes : le délai qu'un exploitant attend sans aller relire la doc.

// CadenceServices espace deux demandes pour un même type.
const CadenceServices = 5 * time.Minute

var (
	servicesMu sync.RWMutex
	services   = map[string][]string{}

	// typesSuivis est l'ensemble des types demandés au core. Il GRANDIT en
	// cours de route : un relais HTTPS posé par le core (TO-DO 141) peut
	// nommer un type de service qu'aucun relais du fichier ne suivait.
	typesSuivis  = map[string]bool{}
	boucleSuivi  sync.Once
	cleDesSuivis func() string
	reveilSuivi  = make(chan struct{}, 1)
)

// SuivreServices demande, tout de suite puis à chaque CadenceServices, les
// services de chacun des types.
//
// Peut être appelée plusieurs fois : les types s'AJOUTENT, et un type nouveau
// est demandé sans attendre le tour suivant. Aucun n'est jamais retiré — une
// demande de trop toutes les cinq minutes coûte moins qu'un relais dont les
// cibles cessent d'être rafraîchies parce qu'on a mal compté ses voisins.
func SuivreServices(types []string, sessionKey func() string) {
	nouveaux := ajouterTypesSuivis(types)

	// Le fournisseur de clé est retenu MÊME sans type à suivre : un proxy sans
	// relais HTTPS dans son fichier peut en recevoir un du core plus tard, et
	// il lui faudra de quoi émettre la demande.
	servicesMu.Lock()
	premierFournisseur := cleDesSuivis == nil && sessionKey != nil
	if cleDesSuivis == nil {
		cleDesSuivis = sessionKey
	}
	cle := cleDesSuivis
	servicesMu.Unlock()
	if cle == nil {
		return
	}
	if premierFournisseur {
		// Ceux qui avaient été retenus avant qu'on sache émettre partent aussi.
		nouveaux = TypesSuivis()
	}
	if len(nouveaux) == 0 {
		return
	}

	logs.Write_log("INFO", fmt.Sprintf("services du cluster : suivi de %s (cadence %s)",
		strings.Join(nouveaux, ", "), CadenceServices))

	boucleSuivi.Do(func() {
		go func() {
			defer logs.Recover("services du cluster")
			for {
				for _, t := range TypesSuivis() {
					emettreDemandeServices(cle, t)
				}
				select {
				case <-time.After(CadenceServices):
				case <-reveilSuivi:
				}
			}
		}()
	})
	// La boucle tourne déjà : un type ajouté est demandé maintenant.
	select {
	case reveilSuivi <- struct{}{}:
	default:
	}
}

// SuivreServicesEnPlus ajoute des types au suivi déjà démarré, avec le
// fournisseur de clé donné au premier appel. Sans effet tant que
// SuivreServices n'a jamais reçu de fournisseur.
func SuivreServicesEnPlus(types []string) {
	servicesMu.RLock()
	cle := cleDesSuivis
	servicesMu.RUnlock()
	if cle == nil {
		// Retenus quand même : ils partiront au premier SuivreServices.
		ajouterTypesSuivis(types)
		return
	}
	SuivreServices(types, cle)
}

// ajouterTypesSuivis rend ceux qui n'étaient pas encore suivis.
func ajouterTypesSuivis(types []string) []string {
	servicesMu.Lock()
	defer servicesMu.Unlock()
	var nouveaux []string
	for _, t := range types {
		t = strings.TrimSpace(t)
		if t == "" || typesSuivis[t] {
			continue
		}
		typesSuivis[t] = true
		nouveaux = append(nouveaux, t)
	}
	return nouveaux
}

// TypesSuivis rend les types demandés au core, triés.
func TypesSuivis() []string {
	servicesMu.RLock()
	defer servicesMu.RUnlock()
	out := make([]string, 0, len(typesSuivis))
	for t := range typesSuivis {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

func emettreDemandeServices(sessionKey func() string, typ string) {
	if envoyer == nil {
		logs.Write_log("WARNING", "services du cluster : aucun émetteur branché, demande abandonnée")
		return
	}
	cle := sessionKey()
	if strings.TrimSpace(cle) == "" {
		logs.Write_log("WARNING", "services du cluster : aucune session établie, demande abandonnée")
		return
	}
	envoyer(ConstruireDemandeServices(cle, clientID, typ))
}

// ConstruireDemandeServices compose la 04_15.
func ConstruireDemandeServices(sessionKey, clientID, typ string) string {
	return strings.Join([]string{
		"04_15", "serveur_central", sessionKey, "vaultaire", clientID, typ,
	}, "\n")
}

// AnalyserServices lit une 04_16 : <type>\n<nombre>\n<hôte:port>…
//
// Une ligne qui n'est pas une adresse composable est écartée et comptée : un
// relais qui tenterait « nexus » sans port attendrait son délai pour rien à
// chaque connexion.
func AnalyserServices(contenu string) (string, []string, error) {
	lignes := strings.Split(strings.TrimSpace(contenu), "\n")
	if len(lignes) < 2 {
		return "", nil, fmt.Errorf("04_16 incomplète")
	}
	typ := strings.TrimSpace(lignes[0])
	if typ == "" {
		return "", nil, fmt.Errorf("04_16 sans type")
	}
	annonce, err := strconv.Atoi(strings.TrimSpace(lignes[1]))
	if err != nil {
		return typ, nil, fmt.Errorf("04_16 : nombre illisible (%q)", lignes[1])
	}
	var out []string
	for _, l := range lignes[2:] {
		l = strings.TrimSpace(l)
		if l == "" {
			continue
		}
		if h, p, err := net.SplitHostPort(l); err != nil || h == "" || p == "" {
			logs.Write_log("WARNING", "04_16 : adresse rejetée : "+l)
			continue
		}
		out = append(out, l)
	}
	if len(out) != annonce {
		logs.Write_log("WARNING", fmt.Sprintf(
			"04_16 : %d service(s) %s annoncé(s), %d lu(s)", annonce, typ, len(out)))
	}
	return typ, out, nil
}

// traiterServices applique une 04_16.
//
// Une liste VIDE remplace la précédente : si le core dit qu'il n'y a plus
// aucun Nexus en ligne, garder l'ancienne liste ferait tenter des adresses
// mortes avec un délai à chaque connexion. Le relais refuse alors franchement.
func traiterServices(contenu string) {
	typ, adresses, err := AnalyserServices(contenu)
	if err != nil {
		logs.Write_log("WARNING", "services du cluster : "+err.Error())
		return
	}
	servicesMu.Lock()
	services[typ] = adresses
	servicesMu.Unlock()
	logs.Write_log("INFO", fmt.Sprintf("services du cluster : %d %s joignable(s) %v",
		len(adresses), typ, adresses))
}

// AdressesService rend les adresses connues d'un type, dans l'ordre du core.
func AdressesService(typ string) []string {
	servicesMu.RLock()
	defer servicesMu.RUnlock()
	return append([]string(nil), services[typ]...)
}
