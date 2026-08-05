package ssh

import (
	"strings"
	"sync"
)

// Answer est ce que le core a répondu au sujet d'un utilisateur.
type Answer struct {
	// Kind vaut « login », « salt », « keys » ou « denied ».
	Kind string
	// Username tel que le core l'a renvoyé, domaine compris.
	Username string
	// IsAdmin et PublicKeys sont renseignés par 03_02.
	IsAdmin    bool
	PublicKeys string
	// Salt et Nonce sont renseignés par 03_05.
	Salt  string
	Nonce string
	// Reason est renseignée par 03_03.
	Reason string
}

// Genres de réponse.
const (
	AnswerLogin  = "login"
	AnswerSalt   = "salt"
	AnswerKeys   = "keys"
	AnswerDenied = "denied"
)

// Pending associe une demande en cours à qui l'attend.
//
// # Pourquoi un registre et pas un simple retour de fonction
//
// Les réponses 03 n'arrivent pas dans le fil de la demande : elles remontent par
// la boucle de réception, plus tard, et rien dans la trame ne dit quelle
// goroutine attendait. La seule chose qui les relie à une demande est le NOM
// D'UTILISATEUR concerné. C'est donc la clé du registre.
//
// Conséquence à connaître : deux demandes simultanées sur le même utilisateur se
// marchent dessus. Register remplace l'attente précédente et ferme son canal,
// pour que la première ne reste pas bloquée indéfiniment.
type Pending struct {
	mu       sync.Mutex
	requests map[string]chan Answer
}

// Register ouvre l'attente d'une réponse concernant username.
//
// À appeler AVANT d'envoyer la demande. L'inverse laisse une fenêtre où la
// réponse arrive avant que quiconque ne l'attende, et elle est alors perdue —
// un échec qui n'apparaît qu'en charge.
func (p *Pending) Register(username string) <-chan Answer {
	key := normalize(username)
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.requests == nil {
		p.requests = make(map[string]chan Answer)
	}
	if previous, exists := p.requests[key]; exists {
		close(previous)
	}
	ch := make(chan Answer, 1)
	p.requests[key] = ch
	return ch
}

// Pop retire l'attente et rend son canal.
func (p *Pending) Pop(username string) (chan Answer, bool) {
	key := normalize(username)
	p.mu.Lock()
	defer p.mu.Unlock()
	ch, exists := p.requests[key]
	if exists {
		delete(p.requests, key)
	}
	return ch, exists
}

// deliver remet une réponse à qui l'attend, sans jamais bloquer.
//
// Le canal est tamponné à un élément ; un second message pour la même demande
// est abandonné plutôt que de figer la boucle de réception, dont dépendent
// toutes les autres trames.
func (p *Pending) deliver(username string, answer Answer) bool {
	ch, exists := p.Pop(username)
	if !exists {
		return false
	}
	select {
	case ch <- answer:
	default:
	}
	close(ch)
	return true
}

// normalize retire le domaine et l'espacement.
//
// Le core répond « alice@vaultaire.fr » à une demande portant sur « alice » :
// sans normalisation, la réponse ne retrouverait pas son attente et le
// demandeur expirerait en silence.
func normalize(username string) string {
	name := strings.TrimSpace(username)
	if at := strings.Index(name, "@"); at > 0 {
		name = name[:at]
	}
	return strings.ToLower(name)
}
