// Package storage porte les types partagés du protocole Ducky.
//
// Volontairement sans dépendance : tout le reste du dossier en dépend, il ne
// doit dépendre de rien.
package storage

import "net"

// Trames_struct_client est une trame reçue, découpée.
//
// Les noms reprennent ceux du core et de l'agent : ce dossier est destiné à
// être copié dans des programmes qui parlent au même serveur, et diverger sur
// le vocabulaire coûterait plus que la laideur d'un identifiant mixte.
type Trames_struct_client struct {
	Message_Order       []string
	Destination_Server  string
	SessionIntegritykey string
	Username            string
	ClientSoftwareID    string
	Content             string
}

// Category retourne les deux premiers chiffres du code de trame.
//
// C'est sur elle que le Spliter décide à qui remettre la trame.
func (t Trames_struct_client) Category() string {
	if len(t.Message_Order) == 0 {
		return ""
	}
	return t.Message_Order[0]
}

// Code retourne le code complet, « 04_09 ».
func (t Trames_struct_client) Code() string {
	if len(t.Message_Order) < 2 {
		return t.Category()
	}
	return t.Message_Order[0] + "_" + t.Message_Order[1]
}

// DuckySession est une connexion au core.
//
// IsSafe est LE drapeau du protocole : tant qu'il est faux, tout passe en RSA
// avec la clé publique du serveur ; une fois vrai, tout passe en AES-GCM avec la
// clé de session. Se tromper dessus produit un échec de déchiffrement qui
// ressemble en tout point à une mauvaise clé.
type DuckySession struct {
	SessionID  string
	Conn       net.Conn
	IsSafe     bool
	SessionKey []byte

	// ComputeurID et Username sont réémis dans chaque trame montante.
	ComputeurID string
	Username    string

	// ClientType est renseigné à l'enrôlement. Purement informatif côté client :
	// c'est le core qui décide de ce qu'on a le droit d'émettre.
	ClientType string
}
