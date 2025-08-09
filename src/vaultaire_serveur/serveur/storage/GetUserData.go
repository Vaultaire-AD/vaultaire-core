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
