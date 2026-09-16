package stosession

import (
	"duckynetworkclient/V1/sessionmgr"
	"time"
)

var SessionsUser = sessionmgr.NewManager(10 * time.Minute)
