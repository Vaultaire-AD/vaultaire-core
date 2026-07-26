package storage

var SocketPath = "/tmp/vaultaire_client.sock"

type AuthResult struct {
	Type    string `json:"type"` // "AUTH" ou "CHECK"
	Salt    string `json:"salt"`
	Nonce   string `json:"nonce"`
	IsAdmin bool   `json:"is_admin"`
	SSHKeys string `json:"ssh_keys"`
}

var SilentConsole = false
