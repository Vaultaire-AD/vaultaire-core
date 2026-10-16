package main

import (
	"database/sql"
	"fmt"

	configurationfile "vaultaire/core/configuration_file"
	db "vaultaire/core/database"
	"vaultaire/core/paquetagent/outil"
	"vaultaire/core/storage"
	keymanagement "vaultaire/ducky-network/key_management"
)

// ouvrirClesPaquets donne aux sous-commandes de paquet (TO-DO 113) l'accès à
// la clé pkg_signing en base.
//
// Une seule tentative de connexion, contrairement à db.InitDatabase qui
// réessaie indéfiniment : c'est le bon choix pour un core qui démarre avant sa
// base, pas pour une commande tapée à la main, qui doit rendre la main avec
// une erreur.
//
// Ni schéma, ni amorçage : une base sans clé pkg_signing est celle d'un core
// qui n'a jamais démarré, et générer la clé ici la ferait naître hors du
// chemin ordinaire.
func ouvrirClesPaquets() (outil.Cles, error) {
	chemin, consultes := configurationfile.CheminConfig()
	if err := configurationfile.LoadConfig(chemin); err != nil {
		return outil.Cles{}, configurationfile.ErreurConfigIntrouvable(consultes, err)
	}
	conn, err := sql.Open("mysql", storage.Database_username+":"+storage.Database_password+
		"@tcp("+storage.Database_iPDatabase+":"+storage.Database_portDatabase+")/"+
		storage.Database_databaseName+"?parseTime=true")
	if err == nil {
		err = conn.Ping()
	}
	if err != nil {
		return outil.Cles{}, fmt.Errorf("base injoignable (%s:%s) : %w",
			storage.Database_iPDatabase, storage.Database_portDatabase, err)
	}
	db.DB = conn
	return outil.Cles{
		Privee:      keymanagement.ClePriveePaquets,
		PubliquePEM: keymanagement.ClePubliquePaquetsPEM,
		Oublier:     keymanagement.OublierClePriveePaquets,
	}, nil
}
