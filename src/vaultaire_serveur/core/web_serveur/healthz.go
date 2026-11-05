package webserveur

import (
	"context"
	"database/sql"
	"net/http"
	"time"

	"vaultaire/core/database"
)

// /healthz — point de santé du core, pour les sondes (TO-DO 258).
//
// # Ce qu'il dit
//
// 200 « ok » quand le portail répond ET que la base répond à un ping en moins
// de deux secondes ; 503 sinon. Un core sans base n'authentifie plus personne :
// il doit sortir du Service Kubernetes (sonde de disponibilité) plutôt que de
// recevoir des binds qu'il refusera.
//
// # Ce qu'il ne dit pas
//
// Rien d'autre : ni version, ni nom d'hôte, ni cause. Il répond sans
// authentification, à quiconque joint le portail ; la cause d'une panne est
// dans le journal, pas dans une réponse anonyme.
//
// # Pourquoi pas une sonde TCP sur le LDAPS
//
// Chaque poignée de main TLS avortée y est journalisée : une sonde toutes les
// dix secondes écrivait une ligne WARNING toutes les dix secondes (recette du
// 05/11). Ce point-ci ne journalise rien.

// DelaiSante borne le ping de la base.
const DelaiSante = 2 * time.Second

// baseDeSante est une variable pour les tests.
var baseDeSante = database.GetDatabase

// SanteHandler sert /healthz.
func SanteHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "méthode non autorisée", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	if !basePrete(r.Context(), baseDeSante()) {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte("indisponible\n"))
		return
	}
	_, _ = w.Write([]byte("ok\n"))
}

func basePrete(parent context.Context, db *sql.DB) bool {
	if db == nil {
		return false
	}
	ctx, annuler := context.WithTimeout(parent, DelaiSante)
	defer annuler()
	return db.PingContext(ctx) == nil
}
