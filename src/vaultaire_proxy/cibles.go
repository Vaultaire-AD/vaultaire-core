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
// Source « cores » : le core de la session du proxy (TO-DO 225), puis les
// cores appris du cluster (04_04), dans l'ordre servi, puis les serveurs du
// fichier de configuration du proxy — le dernier recours,
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
	return ordonnerCibles(config.ServeurCourant(), decouverte.Appris(), config.GetServers())
}

// ordonnerCibles : le core de la session du proxy d'abord, puis les cores
// appris (04_04) dans l'ordre servi, puis les serveurs du fichier.
//
// Le premier rang est le correctif du TO-DO 225. Les cores appris le sont par
// leur adresse EXPOSÉE, celle que reçoivent les agents. Un proxy qui la prend
// peut arriver au core par un autre chemin que sa propre session — recette du
// 27/10 : core et proxy sur le même hôte, l'adresse exposée repasse par le NAT
// de l'hôte, et le core voit la passerelle docker au lieu du proxy. Il refuse
// alors l'en-tête PROXY du relais LDAPS (« pas un proxy enregistré ») et ne
// reconnaît pas les postes relayés à la purge. Par le chemin de la session, le
// core voit le proxy sous l'adresse qu'il lui connaît (adresse_vue).
//
// Le core de la session est forcément joignable et dans le cluster ; s'il
// passe en maintenance, la purge déplace la session, et les relais suivent.
func ordonnerCibles(courant string, appris []decouverte.Noeud, serveurs []config.ServerConfig) []string {
	vues := map[string]bool{}
	var out []string
	ajouter := func(a string) {
		if a != "" && !vues[a] {
			vues[a] = true
			out = append(out, a)
		}
	}
	ajouter(courant)
	for _, n := range appris {
		if n.Role == "core" {
			ajouter(n.Adresse())
		}
	}
	for _, s := range serveurs {
		ajouter(s.IP + ":" + strconv.Itoa(s.Port))
	}
	return out
}
