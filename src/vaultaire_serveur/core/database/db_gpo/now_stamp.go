package dbgpo

import (
	"time"
)

// nowStamp est utilisé par les logs d'audit des modules.
func nowStamp() string { return time.Now().Format("2006-01-02 15:04:05") }
