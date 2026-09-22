package main

import (
	"fmt"
	"time"

	"duckynetworkclient/V1/duckynetwork/logs"

	"vaultaire_proxy/relais"
)

// PeriodeBilan est l'intervalle du bilan des relais dans le journal.
const PeriodeBilan = 5 * time.Minute

// demarrerRelais lit la section « relais » de la configuration, ouvre les
// ports, et lance les boucles. Rend une erreur si un relais ne peut pas
// écouter : c'est à l'appelant d'arrêter le proxy.
func demarrerRelais(configPath string, portAnnonce int) ([]*relais.Serveur, error) {
	liste, err := relais.Charger(configPath, portAnnonce)
	if err != nil {
		return nil, err
	}
	journal := func(niveau, message string) { logs.Write_log(niveau, message) }

	var serveurs []*relais.Serveur
	for _, r := range liste {
		srv := relais.Nouveau(r, resolveurPour(r), journal)
		if err := srv.Ecouter(); err != nil {
			for _, s := range serveurs {
				_ = s.Fermer()
			}
			return nil, err
		}
		serveurs = append(serveurs, srv)
	}
	for _, srv := range serveurs {
		srv := srv
		logs.Go("relais "+srv.Stats().Nom, func() {
			if err := srv.Servir(); err != nil {
				logs.Write_log("ERROR", fmt.Sprintf("relais arrêté : %v", err))
			}
		})
	}
	// Bilan périodique : sans lui, un relais qui refuse tout (aucun core
	// joignable) ne se voit qu'en lisant une ligne par connexion.
	logs.Go("bilan des relais", func() {
		for {
			time.Sleep(PeriodeBilan)
			for _, srv := range serveurs {
				logs.Write_log("INFO", srv.Stats().Resume())
			}
		}
	})
	return serveurs, nil
}
