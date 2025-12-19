package storage

import (
	"time"
	"vaultaire_client/sessionmgr"
)

var SessionsUser = sessionmgr.NewManager(1 * time.Minute)
