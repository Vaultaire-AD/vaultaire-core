package storage

var SocketPath = "/tmp/vaultaire_client.sock"

type AuthResult struct {
	Keys    string
	IsAdmin bool
}

var SilentConsole = false
