package main

import (
	"strconv"

	"duckynetworkclient/V1/config"
	"duckynetworkclient/V1/duckynetwork/decouverte"

	"vaultaire_proxy/relais"
)

// resolveurPour rend la fonction qui donne les cibles d'un relais.
//
// Source « cores » : les cores appris du cluster (04_04), dans l'ordre servi,
// puis les serveurs du fichier de configuration du proxy — le dernier recours,
// comme pour un agent. Les proxies de la liste sont ÉCARTÉS : un proxy qui
// relaierait vers un proxy pourrait boucler, et n'apporterait rien.
func resolveurPour(r relais.Relais) relais.Resolveur {
	switch r.Cibles.Source {
	case relais.SourceListe:
		liste := append([]string(nil), r.Cibles.Adresses...)
		return func() []string { return liste }
	default:
		return ciblesCores
	}
}

func ciblesCores() []string {
	vues := map[string]bool{}
	var out []string
	ajouter := func(a string) {
		if a != "" && !vues[a] {
			vues[a] = true
			out = append(out, a)
		}
	}
	for _, n := range decouverte.Appris() {
		if n.Role == "core" {
			ajouter(n.Adresse())
		}
	}
	for _, s := range config.GetServers() {
		ajouter(s.IP + ":" + strconv.Itoa(s.Port))
	}
	return out
}
