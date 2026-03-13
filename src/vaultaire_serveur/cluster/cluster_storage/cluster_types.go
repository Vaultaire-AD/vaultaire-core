package clusterstorage

import "time"

type Node struct {
	ID            int
	Hostname      string
	FQDN          string
	IPAddress     string
	Role          string
	Status        string
	VersionCode   string
	Capabilities  string // JSON string
	LastHeartbeat time.Time
}
