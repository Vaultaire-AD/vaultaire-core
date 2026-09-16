package dbauthpolicy

import (
	"time"
)

// Bornes de validation.
//
// Le maximum à 3650 jours n'est pas une limite de sécurité mais un garde-fou de
// saisie : une valeur absurde entrée par erreur — un horodatage collé dans le
// champ, par exemple — désactiverait la politique sans le dire, alors qu'un
// refus explicite se voit.
const (
	maxAgeDaysLimit  = 3650
	warnDaysLimit    = 365
	defaultWarnDays  = 7
	settingsCacheTTL = 30 * time.Second
)
