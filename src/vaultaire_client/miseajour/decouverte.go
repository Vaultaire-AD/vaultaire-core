package miseajour

import (
	"strings"
	"time"

	"duckynetworkclient/V1/duckynetwork/decouverte"
	"duckynetworkclient/V1/duckynetwork/logs"

	"vaultaire_client/config"
)

// demanderNexus : la 04_15, remplaçable par les tests.
var demanderNexus = func(sessionKey func() string) ([]string, error) {
	return decouverte.DemanderServices(TypeNexus, sessionKey, DelaiDecouverte)
}

// Depots demande au cluster où sont les Nexus, et retombe sur le repli.
//
// Un core qui ne répond pas n'empêche pas le repli : la dernière liste connue
// sert si elle existe, sinon update_repository.
func Depots(sessionKey func() string) ([]Base, error) {
	// La 04_15 n'est émise que vers un core qui annonce la capacité : un core
	// plus ancien fermerait la connexion de l'agent (voir enligne.PrefixeCapacites).
	if !coreSait() {
		logs.Write_log("INFO", "mise à jour : le core de cette connexion n'annonce pas la mise à jour "+
			"— dépôts non demandés, repli")
		return Bases(decouverte.AdressesService(TypeNexus), config.GetUpdateRepository())
	}
	annoncees, err := demanderNexus(sessionKey)
	if err != nil {
		logs.Write_log("WARNING", "mise à jour : dépôts non demandés au cluster ("+err.Error()+
			") — dernière liste connue, ou repli")
	}
	return Bases(annoncees, config.GetUpdateRepository())
}

// Journaliser dit, une fois, où l'agent prendrait ses mises à jour.
//
// Appelée au démarrage, une fois la session ouverte. Ce n'est pas un
// préalable : c'est ce qui permet de vérifier, en recette et sur un parc, que
// la découverte aboutit, sans attendre qu'un ordre arrive. Une seule 04_15
// par démarrage de l'agent ; un ordre redemande les dépôts (Depots).
func Journaliser(sessionKey func() string) {
	// Les capacités du core arrivent avec sa 02_11 : on leur laisse le temps,
	// une fois la session ouverte, avant de conclure qu'il ne les a pas.
	if sessionKey() != "" {
		for i := 0; i < 30 && !coreSait(); i++ {
			time.Sleep(time.Second)
		}
	}
	bases, err := Depots(sessionKey)
	if err != nil {
		logs.Write_log("WARNING", "mise à jour : "+err.Error())
		return
	}
	var l []string
	for _, b := range bases {
		l = append(l, b.URL+" ("+string(b.Source)+")")
	}
	logs.Write_log("INFO", "mise à jour : dépôt(s) "+strings.Join(l, ", "))
}
