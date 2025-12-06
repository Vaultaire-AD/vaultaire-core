package storage

type UserConnected struct {
	ID          int
	Username    string
	CreatedAt   string
	TokenExpiry string
}

type GetUserInfoSingle struct {
	Username    string   `json:"username"`
	Firstname   string   `json:"firstname"`
	Lastname    string   `json:"lastname"`
	Email       string   `json:"email"`
	DateOfBirth string   `json:"date_naissance"`
	Groups      []string `json:"groups"`
	Connected   bool     `json:"connected"`
}

// PublicKey représente une clé publique d'un utilisateur
type PublicKey struct {
	ID        int
	UserID    int
	Key       string
	Label     string
	CreatedAt string
}

type GroupInfoLDAP struct {
	ID         int
	Name       string
	DomainName string
}
