package dbrevocation

import (
	"database/sql"
	"vaultaire/core/revocation"
)

// TargetRecord est l'état d'un ordre pour une machine.
type TargetRecord struct {
	ComputeurID string
	Status      revocation.TargetStatus
	LastAttempt sql.NullTime
	Detail      string

	// Attempts : combien de fois l'ordre a été REMIS à cette machine — poussée
	// initiale, réponse à une demande, rejeu du core (TO-DO 49).
	Attempts int

	// DepuisLeDernier : secondes écoulées depuis le dernier échange avec la
	// machine au sujet de cet ordre — une remise, un acquittement ou un échec.
	//
	// Calculé PAR LA BASE (TIMESTAMPDIFF … NOW()), comme pour le rejeu :
	// last_attempt est écrit par NOW(), dans le fuseau du serveur de base, et
	// le soustraire à l'horloge du core donnerait un âge faux dès que les deux
	// ne sont pas au même fuseau. Invalide tant que rien n'a été échangé.
	DepuisLeDernier sql.NullInt64
}
