package duckytool

import (
	"duckynetworkclient/V1/duckynetwork/storage/stosession"
)

// IsDuckySessionActive vérifie s'il existe au moins une session "vaultaire"
// authentifiée et utilisable (il peut y en avoir plusieurs ; on n'a besoin
// de savoir que si au moins une est disponible).
func IsDuckySessionActive() bool {
	return stosession.SessionsUser.GetValidVaultaireSession() != nil
}
