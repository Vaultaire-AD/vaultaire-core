package config

import (
	"sync"
)

var (
	Configuration Config
	configMutex   sync.RWMutex
)

func GetServers() []ServerConfig {
	configMutex.RLock()
	defer configMutex.RUnlock()

	servers := make([]ServerConfig, len(Configuration.Servers))
	copy(servers, Configuration.Servers)

	return servers
}
