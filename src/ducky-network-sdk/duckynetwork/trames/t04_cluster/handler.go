package cluster

import (
	"strings"
	"sync"

	"duckynetwork/duckynetwork/logs"
	"duckynetwork/duckynetwork/storage"
)

// ErrUnknownService est le code renvoyé par le core quand il ne connaît plus le
// service : sa ligne a disparu de la table du cluster.
const ErrUnknownService = "unknown_service"

// State retient ce que le core a répondu à nos trames 04.
//
// Il existe parce que la réception est asynchrone : Register rend la main dès
// l'envoi, et la réponse arrive plus tard par le Spliter. Sans point de rendez-
// vous, la boucle de session n'aurait aucun moyen d'apprendre qu'elle a été
// désenregistrée.
type State struct {
	mu           sync.Mutex
	registered   bool
	needRegister bool
}

// Registered indique si le dernier 04_09 a été accepté.
func (s *State) Registered() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.registered
}

// NeedsRegister indique que le core réclame un nouvel enregistrement.
//
// Lire remet le drapeau à zéro : la boucle de session le consomme une fois et
// rejoue 04_09, sans boucler si l'enregistrement échoue à nouveau.
func (s *State) NeedsRegister() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	need := s.needRegister
	s.needRegister = false
	return need
}

// Handler traite les réponses du core à nos trames 04.
func (s *State) Handler(trames storage.Trames_struct_client, session *storage.DuckySession) string {
	switch trames.Code() {
	case RegisterOK:
		s.mu.Lock()
		s.registered = true
		s.mu.Unlock()
		logs.Write("INFO", "service enregistré dans le cluster")

	case HeartbeatOK:
		logs.Write("DEBUG", "battement de cœur acquitté")

	case ServiceError:
		code := firstLine(trames.Content)
		if code == ErrUnknownService {
			// Le core a perdu notre ligne : on se réenregistrera, mais
			// l'identité reste valable — inutile de se réenrôler.
			s.mu.Lock()
			s.registered = false
			s.needRegister = true
			s.mu.Unlock()
			logs.Write("WARNING", "service inconnu du cluster, réenregistrement nécessaire")
		} else {
			logs.Write("ERROR", "erreur cluster : "+strings.TrimSpace(trames.Content))
		}

	default:
		logs.Write("DEBUG", "trame 04 non traitée : "+trames.Code())
	}
	return ""
}

func firstLine(content string) string {
	lines := strings.Split(strings.TrimSpace(content), "\n")
	if len(lines) == 0 {
		return ""
	}
	return strings.TrimSpace(lines[0])
}
