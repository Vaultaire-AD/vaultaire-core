package stosession

import (
	"time"
	"vaultaire_client/sessionmgr"
)

var SessionsUser = sessionmgr.NewManager(10 * time.Minute)
