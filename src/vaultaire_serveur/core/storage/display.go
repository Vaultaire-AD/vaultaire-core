package storage

type DisplayUsersByPermission struct {
	Username    string `json:"username"`
	DateOfBirth string `json:"date_naissance"`
	Connected   bool   `json:"connected"`
}

type DisplayUsersByGroup struct {
	Username    string `json:"username"`
	DateOfBirth string `json:"date_naissance"`
	Connected   bool   `json:"connected"`
}

type GroupDetails struct {
	GroupName               string
	DomainName              string
	LogicielPermissionCount int
	UserPermissionCount     int
	UserCount               int
	ClientCount             int
}

type GetClientsByGroup struct {
	ID           int    // ID du logiciel
	LogicielType string // Type de logiciel
	ComputeurID  string // ID du computeur
	Hostname     string // Nom de l'hôte
	Serveur      bool   // Si c'est un serveur
	Processeur   int    // Nombre de processeurs
	RAM          string // RAM
	OS           string // Système d'exploitation
}

type Software struct {
	ID           int
	LogicielType string
	ComputeurID  string
	Hostname     string
	Serveur      bool
	Processeur   int
	RAM          string
	OS           string
	Groups       []string
	Permissions  []string
}

type GetPermissionByGroup struct {
	ID      int    // ID de la permission
	Name    string // Nom de la permission
	IsAdmin bool   // Si la permission est une permission d'administration
}

type ClientPermission struct {
	ID      int
	Name    string
	IsAdmin bool
}

type UserPermission struct {
	ID          int
	Name        string
	Description string
	None        string
	Auth        string
	Compare     string
	Search      string
	Web_admin   string
}

type GetClientsByPermission struct {
	ID           int    `json:"id_logiciel"`
	LogicielType string `json:"logiciel_type"`
	ComputeurID  string `json:"computeur_id"`
	Hostname     string `json:"hostname"`
	Serveur      bool   `json:"serveur"`
	Processeur   int    `json:"processeur"`
	RAM          string `json:"ram"`
	OS           string `json:"os"`
}

type GetUsers struct {
	ID            int    `json:"id_user"`
	Username      string `json:"username"`
	Email         string `json:"email"`
	DateNaissance string `json:"date_naissance"`
	CreatedAt     string `json:"created_at"`
}

type GroupInfo struct {
	ID          int
	Name        string
	DomainName  string
	Users       []string
	Permissions []string
	Clients     []string
	ClientPerms []string
	GPOs        []string
}

// Les GPO ne sont plus décrites ici : leur modèle (Policy, Module, Scope) vit
// dans le package core/gpo, avec son catalogue et ses garde-fous. L'ancien type
// LinuxGPO portait une commande shell par distribution, ce que le modèle
// déclaratif remplace entièrement.

type GroupDomain struct {
	GroupName  string
	DomainName string
}

type DomainNode struct {
	Name       string
	Children   map[string]*DomainNode
	Groups     []string
	FullDomain string // nouveau champ pour garder le domaine complet
}
