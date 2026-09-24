package decouverte

import (
	"fmt"
	"net"
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
	suivis     sync.Once
)

// SuivreServices demande, tout de suite puis à chaque CadenceServices, les
// services de chacun des types. Un seul appel par processus : les suivants
// sont ignorés.
func SuivreServices(types []string, sessionKey func() string) {
	if len(types) == 0 {
		return
	}
	suivis.Do(func() {
		go func() {
			defer logs.Recover("services du cluster")
			for {
				for _, t := range types {
					emettreDemandeServices(sessionKey, t)
				}
				time.Sleep(CadenceServices)
			}
		}()
		logs.Write_log("INFO", fmt.Sprintf("services du cluster : suivi de %s (cadence %s)",
			strings.Join(types, ", "), CadenceServices))
	})
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
