package dbauthpolicy

import (
	"sync"
	"time"
)

var (
	settingsMu      sync.RWMutex
	cachedPolicy    = DisabledPolicy
	cachedPolicySet bool
	cachedPolicyAt  time.Time
)
