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

// Bornes de la longueur minimale — TO-DO 100.
//
// # Le plancher ne se désactive pas, et c'est le point
//
// Un réglage de sécurité que l'on peut mettre à zéro finit à zéro : il suffit
// d'une installation pressée, d'un script de déploiement recopié, ou d'un
// administrateur qui veut « juste tester ». La valeur 0 est donc refusée à
// l'écriture et relevée au plancher à la lecture.
//
// HUIT et non douze pour le plancher : douze est la bonne valeur par défaut,
// mais l'imposer sans recours enfermerait dehors une installation dont
// l'annuaire existant ne s'y conforme pas encore et qui a besoin de créer un
// compte de dépannage. Huit reste au-dessus de ce qu'une attaque en ligne
// atteint dans les conditions du produit.
//
// # Pourquoi la LONGUEUR et pas la complexité
//
// Une règle de complexité — majuscule, chiffre, caractère spécial — pousse à
// « Password1! », qui figure dans toutes les listes. La longueur est ce qui
// coûte à l'attaquant, et c'est aussi la recommandation de l'ANSSI et du NIST.
// Le maximum à 128 n'est pas une protection : c'est un garde-fou de saisie, et
// argon2id n'a pas de limite d'entrée qui l'exigerait.
const (
	MinLengthPlancher = 8
	MinLengthDefaut   = 12
	minLengthLimit    = 128
)
