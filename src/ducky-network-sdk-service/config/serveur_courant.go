package config

import "sync/atomic"

// L'adresse du core sur lequel la session Ducky de ce processus est ouverte.
//
// Un proxy en a besoin pour ses relais (TO-DO 225) : il doit joindre les cores
// par le MÊME chemin que sa propre session. Le core reconnaît un proxy à
// l'adresse sous laquelle il voit sa session (adresse_vue) ; une connexion
// relayée qui prend un autre chemin — l'adresse exposée aux agents, repassée
// par le NAT de l'hôte — arrive sous une autre adresse : son en-tête PROXY est
// refusé, et la purge ne reconnaît pas les postes relayés.
var serveurCourant atomic.Value // string

// NoterServeurCourant retient l'adresse « hôte:port » de la session ouverte.
func NoterServeurCourant(adresse string) { serveurCourant.Store(adresse) }

// ServeurCourant rend l'adresse de la session ouverte, ou "" avant la première.
func ServeurCourant() string {
	v, _ := serveurCourant.Load().(string)
	return v
}
