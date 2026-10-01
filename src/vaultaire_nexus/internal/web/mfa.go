package web

import (
	"sync"
	"time"

	"vaultaire_nexus/internal/auth"
)

// Étape « second facteur » de la connexion.
//
// Le core répond « mfa_required » APRÈS avoir vérifié le mot de passe. Pour ne
// pas le redemander, et surtout pour ne pas le renvoyer au navigateur dans un
// champ caché, l'identifiant et le mot de passe sont gardés ici, en mémoire,
// deux minutes au plus, sous un jeton aléatoire. Ils ne sont jamais écrits et
// sont effacés dès la tentative suivante — réussie ou non.
type mfaPending struct {
	mu sync.Mutex
	m  map[string]pendingLogin
}

type pendingLogin struct {
	user, password, ip, next string
	expires                  time.Time
	tries                    int
}

const (
	mfaPendingTTL   = 2 * time.Minute
	mfaPendingTries = 3
	mfaPendingMax   = 1000
)

func (p *mfaPending) put(user, password, ip, next string) string {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.m == nil {
		p.m = map[string]pendingLogin{}
	}
	now := time.Now()
	for k, v := range p.m {
		if now.After(v.expires) {
			delete(p.m, k)
		}
	}
	if len(p.m) >= mfaPendingMax {
		return ""
	}
	id := auth.RandomSecret(24)
	p.m[id] = pendingLogin{user: user, password: password, ip: ip, next: next, expires: now.Add(mfaPendingTTL)}
	return id
}

// take rend l'étape en cours et la consomme ; une étape d'une autre adresse ou
// échue n'existe pas.
func (p *mfaPending) take(id, ip string) (pendingLogin, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	v, ok := p.m[id]
	delete(p.m, id)
	if !ok || v.ip != ip || time.Now().After(v.expires) {
		return pendingLogin{}, false
	}
	return v, true
}

// again remet une étape en place après un code faux, dans la limite des essais.
func (p *mfaPending) again(v pendingLogin) string {
	v.tries++
	if v.tries >= mfaPendingTries || time.Now().After(v.expires) {
		return ""
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	id := auth.RandomSecret(24)
	p.m[id] = v
	return id
}
