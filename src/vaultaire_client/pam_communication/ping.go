package pamcommunication

import (
	"encoding/json"
	"fmt"
	"net"

	"duckynetworkclient/V1/duckynetwork/logs"
	sto_session "duckynetworkclient/V1/duckynetwork/storage/stosession"

	"vaultaire_client/version"
)

// La sonde de la porte de santé — TO-DO 116.
//
//	→ {"ping":{}}
//	← {"status":"pong","version":"2.4.0","tunnel":true}
//
// Sans identifiants : elle ne doit exiger aucun compte pour être jouée, et ne
// révèle rien qu'un root ne sache déjà. Elle passe pourtant par le même chemin
// qu'une authentification — l'écoute, le contrôle de l'appelant (root
// seulement, plus haut), le décodage, le routage —, et c'est ce chemin dont
// dépendent toutes les ouvertures de session.
//
// « tunnel » dit si l'agent tient une session authentifiée avec le core : la
// deuxième condition de la porte, lue au même endroit.

// Pong est la réponse.
type Pong struct {
	Status  string `json:"status"`
	Version string `json:"version"`
	Tunnel  bool   `json:"tunnel"`
}

// tunnelEtabli : remplaçable par les tests.
var tunnelEtabli = func() bool { return sto_session.SessionsUser.GetValidVaultaireSession() != nil }

func repondreAuPing(conn net.Conn) {
	if err := json.NewEncoder(conn).Encode(Pong{Status: "pong", Version: version.Version, Tunnel: tunnelEtabli()}); err != nil {
		logs.Write_log("ERROR", fmt.Sprintf("socket PAM : réponse à la sonde non envoyée : %v", err))
	}
}
