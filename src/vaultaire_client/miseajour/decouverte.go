package miseajour

import (
	"strings"

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
// la découverte aboutit — bien avant que le point 116 ne télécharge quoi que
// ce soit. Une seule 04_15 par démarrage de l'agent.
func Journaliser(sessionKey func() string) {
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
