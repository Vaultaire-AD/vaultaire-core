package storage

type Authentification struct {
	RandomAuth       []byte
	AuthID           string
	Username         string
	Password         string
	ClientSoftwareID string
}

type Authentification_Challenge_server struct {
	AuthID    string
	Challenge string
}

var StorageAuth []Authentification
