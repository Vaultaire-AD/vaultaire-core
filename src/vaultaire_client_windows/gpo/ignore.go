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
	"strconv"
	"strings"
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
//
// # Et le DIRE au core — TO-DO 167
//
// L'agent ne répondait rien. Le core, qui rejoue ce qui n'est pas acquitté,
// lui remettait donc ses ordres toutes les cinq minutes, pour toujours, et
// « kill --status » les montrait « en attente ».
//
// Il répond maintenant 06_03 avec le code « unsupported ». Le core range alors
// TOUTES les cibles de cette machine dans un état à part, « non pris en
// charge », affiché tel quel et plus rejoué. Surtout PAS 06_02 : un ordre
// acquitté se lit comme un compte coupé, et il ne l'est pas.
func HandleTrameRevocation(trames storage.Trames_struct_client, _ *storage.DuckySession) string {
	sous := "??"
	if len(trames.Message_Order) > 1 {
		sous = trames.Message_Order[1]
	}
	revocations.Add(1)
	logs.Write_log("WARNING", fmt.Sprintf(
		"révocation : trame 06_%s reçue et NON appliquée (agent Windows V1) — "+
			"le compte ne pourra plus s'authentifier, mais sa session en cours n'est pas fermée", sous))
	ordre := PremierOrdre(sous, trames.Content)
	if ordre <= 0 {
		return ""
	}
	return ReponseNonPrisEnCharge(trames.SessionIntegritykey, storage.Computeur_ID, ordre)
}

// CodeNonPrisEnCharge est le code d'erreur que le core reconnaît
// (revocation.ErrUnsupported). Recopié, pas importé : l'agent Windows ne
// dépend pas du module du serveur.
const CodeNonPrisEnCharge = "unsupported"

// MotifNonPrisEnCharge est ce que le core affiche dans « kill --status ».
const MotifNonPrisEnCharge = "agent Windows V1 : révocation non appliquée, session ouverte non fermée"

// PremierOrdre rend l'identifiant du premier ordre d'une trame 06_01 (un ordre)
// ou 06_05 (une liste), 0 s'il n'y en a pas. Une seule réponse suffit : le
// core range sur elle TOUS les ordres de la machine.
func PremierOrdre(sous, contenu string) int {
	lignes := strings.Split(contenu, "\n")
	switch sous {
	case "01":
		id, err := strconv.Atoi(strings.TrimSpace(lignes[0]))
		if err != nil || id <= 0 {
			return 0
		}
		return id
	case "05":
		for _, l := range lignes[1:] { // la première ligne est le nombre d'ordres
			champs := strings.SplitN(strings.TrimSpace(l), "|", 2)
			if id, err := strconv.Atoi(strings.TrimSpace(champs[0])); err == nil && id > 0 {
				return id
			}
		}
	}
	return 0
}

// ReponseNonPrisEnCharge construit la trame 06_03, au format de l'agent Linux
// (src/vaultaire_client/revocation, errorFrame).
func ReponseNonPrisEnCharge(cleDeSession, machine string, ordre int) string {
	return strings.Join([]string{
		"06_03", "serveur_central", cleDeSession, "vaultaire", machine,
		strconv.Itoa(ordre), CodeNonPrisEnCharge, MotifNonPrisEnCharge,
	}, "\n")
}

var revocations atomic.Int64

// Revocations rend le nombre de trames de révocation reçues.
func Revocations() int64 { return revocations.Load() }

// HandleTrameMiseAJour répond aux ordres de mise à jour (TO-DO 115) : l'agent
// Windows ne sait pas se mettre à jour — c'est le point 118 —, il le DIT, par
// un compte rendu « non pris en charge ». Le core le range et cesse de lui
// pousser cet ordre ; « vlt agent » montre pourquoi la machine ne bouge pas.
//
// Il ne DEMANDE pas son ordre (09_01) : seules les poussées lui arrivent.
func HandleTrameMiseAJour(trames storage.Trames_struct_client, _ *storage.DuckySession) string {
	if len(trames.Message_Order) < 2 {
		return ""
	}
	switch trames.Message_Order[1] {
	case "02", "06":
	default:
		return ""
	}
	version := strings.TrimSpace(strings.SplitN(trames.Content, "\n", 2)[0])
	if version == "" {
		return ""
	}
	logs.Write_log("WARNING", "mise à jour : ordre de passer en "+version+
		" reçu et NON appliqué (la mise à jour de l'agent Windows n'est pas écrite)")
	return ReponseMiseAJourNonPriseEnCharge(trames.SessionIntegritykey, storage.Computeur_ID, version)
}

// ResultatNonPrisEnCharge : la chaîne que le core reconnaît
// (miseajour.ResultatNonPrisEnCharge). Recopiée, comme CodeNonPrisEnCharge.
const ResultatNonPrisEnCharge = "non_pris_en_charge"

// ReponseMiseAJourNonPriseEnCharge compose la 09_04.
func ReponseMiseAJourNonPriseEnCharge(cleDeSession, machine, version string) string {
	return strings.Join([]string{
		"09_04", "serveur_central", cleDeSession, "vaultaire", machine,
		version, ResultatNonPrisEnCharge, "agent Windows : mise à jour non écrite (TO-DO 118)",
	}, "\n")
}
