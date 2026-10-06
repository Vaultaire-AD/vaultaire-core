// Package gpo accuse réception des trames de politique SANS les appliquer.
//
// # Pourquoi les recevoir sans les traiter
//
// La V1 Windows ne fait qu'une chose : l'authentification par mot de passe. Les
// GPO supposent un système de fichiers, des unités systemd, des modules PAM —
// rien de tout cela n'existe ici, et un équivalent Windows (stratégies locales,
// registre) est un chantier à part entière.
//
// Mais le core envoie ces trames à tout agent raccordé. Deux choix : les
// laisser tomber dans le « non géré » du socle, qui n'écrit qu'en DEBUG, ou les
// NOMMER. La seconde option est la bonne : un administrateur qui se demande
// pourquoi sa GPO n'a pas d'effet sur un poste Windows doit lire dans le
// journal que la trame est bien arrivée et volontairement ignorée — et non
// chercher du côté du réseau.
package gpo

import (
	"fmt"
	"sync/atomic"

	"duckynetworkclient/V1/duckynetwork/logs"
	"duckynetworkclient/V1/duckynetwork/storage"
)

var recues atomic.Int64

// HandleTrameGPO journalise et ne fait rien d'autre.
func HandleTrameGPO(trames storage.Trames_struct_client, _ *storage.DuckySession) string {
	sous := "??"
	if len(trames.Message_Order) > 1 {
		sous = trames.Message_Order[1]
	}
	n := recues.Add(1)
	// INFO pour les premières, DEBUG ensuite : la première dit que le transport
	// marche, les suivantes ne feraient que remplir le journal d'un poste qui
	// reçoit un cycle par heure.
	niveau := "DEBUG"
	if n <= 3 {
		niveau = "INFO"
	}
	logs.Write_log(niveau, fmt.Sprintf(
		"GPO : trame 05_%s reçue et ignorée (l'agent Windows V1 n'applique aucune politique)", sous))
	return ""
}

// Recues rend le nombre de trames GPO reçues depuis le démarrage. Sert au
// journal de fin et au diagnostic.
func Recues() int64 { return recues.Load() }

// HandleTrameRevocation : même décision que pour les GPO, autre sujet.
//
// Une révocation coupe l'accès d'un compte. Sur Linux, l'agent verrouille le
// compte local et tue les sessions ouvertes ; sur Windows, cela demande de
// toucher à la base des comptes et aux sessions interactives, et de savoir ce
// qu'on fait d'un utilisateur en train de travailler. La V1 ne le fait pas, et
// le DIT — parce que quelqu'un finira par révoquer un compte et par vérifier
// qu'il ne peut plus entrer.
//
// Ce qui est vrai dès la V1 : un compte révoqué ne passera plus
// l'authentification suivante, le core la refusant. Ce qui ne l'est pas : sa
// session en cours n'est pas fermée, et son mot de passe local reste valable.
func HandleTrameRevocation(trames storage.Trames_struct_client, _ *storage.DuckySession) string {
	sous := "??"
	if len(trames.Message_Order) > 1 {
		sous = trames.Message_Order[1]
	}
	revocations.Add(1)
	logs.Write_log("WARNING", fmt.Sprintf(
		"révocation : trame 06_%s reçue et NON appliquée (agent Windows V1) — "+
			"le compte ne pourra plus s'authentifier, mais sa session en cours n'est pas fermée", sous))
	return ""
}

var revocations atomic.Int64

// Revocations rend le nombre de trames de révocation reçues.
func Revocations() int64 { return revocations.Load() }
