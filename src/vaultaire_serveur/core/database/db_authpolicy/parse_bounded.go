package dbauthpolicy

import (
	"fmt"
	"strconv"
	"vaultaire/core/logs"
)

// parseBounded lit un entier et le ramène dans ses bornes.
//
// Une valeur illisible ou hors bornes retombe sur la valeur par défaut plutôt
// que d'échouer : la table est administrable, et une saisie fautive ne doit pas
// empêcher l'authentification de fonctionner.
func parseBounded(raw string, min, max, def int) int {
	if raw == "" {
		return def
	}
	v, err := strconv.Atoi(raw)
	if err != nil {
		logs.Write_Log("WARNING", "authpolicy: valeur de réglage illisible "+strconv.Quote(raw)+", valeur par défaut appliquée")
		return def
	}
	if v < min || v > max {
		logs.Write_Log("WARNING", fmt.Sprintf(
			"authpolicy: réglage hors bornes (%d), valeur par défaut appliquée", v))
		return def
	}
	return v
}
