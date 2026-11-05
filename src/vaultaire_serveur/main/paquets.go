package main

import (
	"database/sql"
	"fmt"

	configurationfile "vaultaire/core/configuration_file"
	db "vaultaire/core/database"
	dbsettings "vaultaire/core/database/db_settings"
	"vaultaire/core/miseajour"
	"vaultaire/core/paquetagent/outil"
	"vaultaire/core/storage"
	hosthandler "vaultaire/ducky-network/host_handler"
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
		Magasin:     keymanagement.MagasinPaquets{},
		Nexus:       func() ([]outil.NexusCible, error) { return nexusDuCluster(conn) },
		Depot: func() (string, error) {
			d, _, err := dbsettings.GetString(conn, miseajour.CleReglageDepot)
			return d, err
		},
	}, nil
}

// nexusDuCluster : les Nexus enrôlés, pour --publish-package (TO-DO 206).
func nexusDuCluster(conn *sql.DB) ([]outil.NexusCible, error) {
	enroles, err := hosthandler.NexusDuCluster(conn)
	if err != nil {
		return nil, err
	}
	out := make([]outil.NexusCible, 0, len(enroles))
	for _, n := range enroles {
		out = append(out, outil.NexusCible{Nom: n.Nom, URL: n.URL, EnLigne: n.EnLigne,
			ExposeAgents: n.ExposeAgents, Maintenance: n.Maintenance, Probleme: n.Probleme})
	}
	return out, nil
}
