// Package ducky est le point d'entrée du paquet Ducky Network.
//
// Il rassemble en un seul appel ce qu'un client service doit faire pour exister
// sur le réseau Vaultaire :
//
//	connexion TCP  →  clé publique du core  →  01 auth serveur  →  02 auth client
//
// # Utilisation
//
//	ducky.Handle("06", gpo.Handler)          // AVANT Start
//
//	session, err := ducky.Start(ducky.Options{
//	    ConfigPath:  "/etc/mon-service/servers.json",
//	    KeyPath:     "/etc/mon-service/.ssh",
//	    ComputeurID: "SRV-PROXY-01",
//	})
//
// # Ce que ce paquet NE fait pas
//
//   - l'enrôlement : la paire de clés doit déjà être en place, et la clé
//     publique déjà connue du core ;
//   - la gestion du cluster (catégorie 04) ;
//   - toute catégorie autre que 01 et 02, qui sont le socle commun. Le reste se
//     branche par Handle.
package ducky
