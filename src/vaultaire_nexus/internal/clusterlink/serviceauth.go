package clusterlink

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"time"

	"duckynetworkclient/V1/duckynetwork/storage"

	"vaultaire_nexus/internal/auth"
)

// Vérification des comptes par le core — trames 08_01 à 08_06
// (ducky-network/serviceauth côté core).
//
// # Corrélation
//
// Chaque demande porte « ref:<aléa> », que le core renvoie tel quel. Les
// réponses sont rangées par ref : deux connexions simultanées ne peuvent pas
// recevoir la réponse l'une de l'autre. Une réponse dont le ref n'est attendu
// par personne (arrivée après le délai) est ignorée.

type attente struct {
	ch   chan reponse
	user string
}

type reponse struct {
	code   string
	champs map[string]string
}

type correlateur struct {
	mu      sync.Mutex
	pending map[string]attente
}

func (c *correlateur) ouvrir(user string) (string, chan reponse) {
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	ref := hex.EncodeToString(b)
	ch := make(chan reponse, 1)
	c.mu.Lock()
	if c.pending == nil {
		c.pending = map[string]attente{}
	}
	c.pending[ref] = attente{ch: ch, user: user}
	c.mu.Unlock()
	return ref, ch
}

func (c *correlateur) fermer(ref string) {
	c.mu.Lock()
	delete(c.pending, ref)
	c.mu.Unlock()
}

// livrer range une réponse ; faux si personne ne l'attend.
func (c *correlateur) livrer(code string, champs map[string]string) bool {
	c.mu.Lock()
	a, ok := c.pending[champs["ref"]]
	delete(c.pending, champs["ref"])
	c.mu.Unlock()
	if !ok {
		return false
	}
	a.ch <- reponse{code: code, champs: champs}
	return true
}

func lireChamps(contenu string) map[string]string {
	m := map[string]string{}
	for _, l := range strings.Split(contenu, "\n") {
		k, v, ok := strings.Cut(l, ":")
		if !ok {
			continue
		}
		k = strings.ToLower(strings.TrimSpace(k))
		if _, deja := m[k]; !deja {
			m[k] = strings.TrimSpace(v)
		}
	}
	return m
}

func liste(v string) []string {
	var out []string
	for _, p := range strings.Split(v, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// erreurDe traduit un code 08_03 / 08_06 en erreur d'authentification.
func erreurDe(code, raison string) error {
	switch code {
	case "bad_credentials", "invalid_request":
		return auth.ErrBadCredentials
	case "mfa_required":
		return auth.ErrMFARequired
	case "mfa_invalid":
		return auth.ErrMFAInvalid
	case "mfa_enroll_required":
		return auth.ErrMFAEnroll
	case "expired":
		return auth.ErrExpired
	case "locked":
		return auth.ErrLocked
	case "revoked":
		return auth.ErrRevoked
	case "deleted":
		return auth.ErrDeleted
	case "unknown":
		return auth.ErrUnknown
	case "denied":
		return auth.ErrDenied
	default: // unavailable, ou code inconnu d'un core plus récent
		return fmt.Errorf("%w : le core répond « %s » (%s)", auth.ErrUnavailable, code, raison)
	}
}

// handle08 reçoit les réponses de catégorie 08.
func (l *Link) handle08(t storage.Trames_struct_client, _ *storage.DuckySession) string {
	if len(t.Message_Order) < 2 {
		return ""
	}
	code := t.Message_Order[0] + "_" + t.Message_Order[1]
	if !l.corr.livrer(code, lireChamps(t.Content)) {
		l.log.Debug("cluster: réponse 08 sans demande en attente", "trame", code)
	}
	return ""
}

// connecte dit si une demande a une chance d'aboutir.
func (l *Link) connecte() bool {
	if l == nil {
		return false
	}
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.state == "connecté" || l.state == "enregistré" || l.state == "refusé"
}

func (l *Link) demander(action, user string, lignes ...string) (reponse, error) {
	if !l.connecte() {
		return reponse{}, fmt.Errorf("%w : cluster non raccordé", auth.ErrUnavailable)
	}
	ref, ch := l.corr.ouvrir(user)
	defer l.corr.fermer(ref)
	if !l.send(action, append(lignes, "ref:"+ref)...) {
		return reponse{}, fmt.Errorf("%w : aucune session Ducky", auth.ErrUnavailable)
	}
	select {
	case r := <-ch:
		return r, nil
	case <-time.After(l.timeout):
		return reponse{}, fmt.Errorf("%w : pas de réponse du core en %s", auth.ErrUnavailable, l.timeout)
	}
}

// identite lit 08_02 / 08_05 et vérifie qu'elle concerne bien le compte
// demandé — seconde garde derrière le ref.
func identite(r reponse, demande string) (auth.Identity, error) {
	c := r.champs
	short, _, _ := strings.Cut(demande, "@")
	if !strings.EqualFold(c["user"], short) {
		return auth.Identity{}, fmt.Errorf("%w : réponse pour « %s », demande pour « %s »", auth.ErrUnavailable, c["user"], short)
	}
	return auth.Identity{User: c["user"], Name: c["name"], Groups: liste(c["groups"]), Rights: liste(c["rights"])}, nil
}

// VerifyUser fait vérifier un compte par le core (08_01).
func (l *Link) VerifyUser(user, password, otp, from string) (auth.Identity, error) {
	if strings.ContainsAny(user+password+otp+from, "\r\n") {
		return auth.Identity{}, auth.ErrBadCredentials
	}
	lignes := []string{user, password}
	if otp != "" {
		lignes = append(lignes, "otp:"+otp)
	}
	if from != "" {
		lignes = append(lignes, "from:"+from)
	}
	r, err := l.demander("08_01", user, lignes...)
	if err != nil {
		return auth.Identity{}, err
	}
	switch r.code {
	case "08_02":
		return identite(r, user)
	case "08_03":
		return auth.Identity{}, erreurDe(r.champs["code"], r.champs["reason"])
	default:
		return auth.Identity{}, fmt.Errorf("%w : réponse inattendue %s", auth.ErrUnavailable, r.code)
	}
}

// RefreshUser relit un compte déjà vérifié (08_04).
func (l *Link) RefreshUser(user string) (auth.Identity, error) {
	r, err := l.demander("08_04", user, "user:"+user)
	if err != nil {
		return auth.Identity{}, err
	}
	switch r.code {
	case "08_05":
		return identite(r, user)
	case "08_06":
		return auth.Identity{}, erreurDe(r.champs["code"], r.champs["reason"])
	default:
		return auth.Identity{}, fmt.Errorf("%w : réponse inattendue %s", auth.ErrUnavailable, r.code)
	}
}
