package sessionmgr

import (
	"net"
	"sync"
	"time"
	"vaultaire/core/storage"
)

type SessionStatus int

const (
	SessionPending SessionStatus = iota
	SessionAuthenticated
	SessionFailed
)

func (s SessionStatus) String() string {
	switch s {
	case SessionPending:
		return "pending"
	case SessionAuthenticated:
		return "authenticated"
	case SessionFailed:
		return "failed"
	default:
		return "unknown"
	}
}

// Session représente une connexion TCP active côté serveur, de l'accept()
// jusqu'à sa fermeture. SessionID est la clé primaire, source de vérité :
// voir NewSessionID et Manager.Rekey.
type Session struct {
	SessionID string

	// Username / ClientSoftwareID sont ceux ANNONCÉS par le client dès le
	// premier message (voir SetIdentity), pas nécessairement encore
	// authentifiés : utile pour tracer une tentative même si elle échoue.
	Username         string
	ClientSoftwareID string

	RemoteAddr   string
	Conn         net.Conn
	DuckySession *storage.DuckySession
	Status       SessionStatus
	CreatedAt    time.Time
	LastSeen     time.Time

	// ActualTrame / TrameIsSafe portent le suivi de l'ordre des trames
	// attendu par le protocole (anciennement ConnData, dans
	// ducky-network/sync). TrameIsSafe passe à true une fois la séquence
	// obligatoire terminée (dernière trame de networkSecurity.ExpectedTrames,
	// ou "04_01" pour un host) : au-delà, l'ordre n'est plus contrôlé. Nom
	// volontairement différent de storage.DuckySession.IsSafe (qui lui
	// indique le mode de chiffrement, symétrique ou non) pour ne pas
	// confondre les deux notions.
	ActualTrame string
	TrameIsSafe bool
}

// Manager est un registre de sessions actives, indexé par SessionID et
// protégé par un sync.RWMutex classique (pas de sync.Map : on a besoin
// d'itérer proprement pour ListAuthenticatedByUsername et de faire des
// opérations composées comme Rekey).
type Manager struct {
	sessions map[string]*Session
	mu       sync.RWMutex
}

func NewManager() *Manager {
	return &Manager{
		sessions: make(map[string]*Session),
	}
}
