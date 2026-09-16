package database

import (
	"runtime"
)

// callerName retourne le nom de la fonction appelante, pour les journaux.
//
// Niveau 2 : callerName elle-même, puis la fonction de filtrage, puis
// l'appelant réel — c'est lui qu'on veut voir dans le journal.
func callerName() string {
	pc, _, _, _ := runtime.Caller(2)
	return runtime.FuncForPC(pc).Name()
}
