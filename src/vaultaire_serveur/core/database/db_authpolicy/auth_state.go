package dbauthpolicy

import (
	"time"
)

// AuthState rassemble tout ce qu'un chemin d'authentification doit savoir d'un
// compte, en une seule lecture.
//
// Une seule requête et non trois : ces champs sont lus à chaque tentative de
// connexion, sur les trois chemins. Les séparer multiplierait les allers-retours
// sur le trajet le plus chaud du serveur, et surtout ouvrirait une fenêtre où le
// second facteur serait lu avant une désactivation et l'expiration après.
type AuthState struct {
	Username          string
	MFAEnabled        bool
	MFASecret         string
	MFALastCounter    int64
	HasMFALastCounter bool
	PasswordChangedAt time.Time
	HasPasswordDate   bool
}
