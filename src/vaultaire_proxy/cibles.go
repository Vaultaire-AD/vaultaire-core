package main

import (
	"net"
	"strconv"

	"duckynetworkclient/V1/config"
	"duckynetworkclient/V1/duckynetwork/decouverte"

	"vaultaire_proxy/relais"
)

// resolveurPour rend la fonction qui donne les cibles d'un relais.
//
// Source « service:<type> » : les services de ce type (04_15 / 04_16).
//
// Source « cores » : les cores appris du cluster (04_04), dans l'ordre servi,
// puis les serveurs du fichier de configuration du proxy — le dernier recours,
// comme pour un agent. Les proxies de la liste sont ÉCARTÉS : un proxy qui
// relaierait vers un proxy pourrait boucler, et n'apporterait rien.
func resolveurPour(r relais.Relais) relais.Resolveur {
	if typ := r.TypeDeService(); typ != "" {
		// Les services d'un type, appris du core par la 04_15 et relus à
		// CHAQUE connexion : un Nexus retiré de la rotation cesse d'être
		// tenté dès la réponse suivante, sans redémarrer le proxy.
		return func() []string { return decouverte.AdressesService(typ) }
	}
	switch r.Cibles.Source {
	case relais.SourceListe:
		liste := append([]string(nil), r.Cibles.Adresses...)
		return func() []string { return liste }
	default:
		if port := r.PortCible(); port > 0 {
			return func() []string { return avecPort(ciblesCores(), port) }
		}
		return ciblesCores
	}
}

// avecPort remplace le port de chaque adresse : les cores sont appris par leur
// adresse Ducky, et un relais LDAPS doit joindre leur port LDAPS. Deux cores
// annoncés sur deux ports Ducky différents mais la même IP ne font plus qu'une
// cible : c'est la même machine.
func avecPort(adresses []string, port int) []string {
	vues := map[string]bool{}
	var out []string
	for _, a := range adresses {
		h, _, err := net.SplitHostPort(a)
		if err != nil {
			continue
		}
		c := net.JoinHostPort(h, strconv.Itoa(port))
		if !vues[c] {
			vues[c] = true
			out = append(out, c)
		}
	}
	return out
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
