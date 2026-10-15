package sessionmgr

import (
	"net"
	"sort"
	"strings"
)

// ParSource : la part du registre qui arrive d'une adresse source donnée —
// TO-DO 176, la purge d'un proxy.
//
// Un proxy relaie en TCP : chaque session qu'il porte arrive au core avec,
// pour source, l'adresse du proxy. La vue garde les sessions dont l'hôte de
// RemoteAddr est l'une des adresses données, SAUF celles du proxy lui-même
// (sa session de contrôle : ClientSoftwareID égal à `exclure`). Un proxy en
// maintenance bat toujours, et reçoit encore sa configuration de relais.
//
// Elle offre ce qu'emploie le purgeur — MachinesConnectees, IDs, Fermer —, et
// chaque méthode relit le registre : une session ouverte pendant la purge, par
// ce proxy, est vue au moment où elle est relue.
type ParSource struct {
	m        *Manager
	adresses map[string]bool
	exclure  string
}

// VueParSource construit la vue. Sans adresse, elle est vide : on ne purge
// jamais tout un core faute d'avoir su reconnaître le proxy.
func (m *Manager) VueParSource(adresses []string, exclure string) ParSource {
	v := ParSource{m: m, adresses: map[string]bool{}, exclure: strings.ToLower(strings.TrimSpace(exclure))}
	for _, a := range adresses {
		if h := hoteSource(a); h != "" {
			v.adresses[h] = true
		}
	}
	return v
}

// AdressesDe rend les hôtes sources des sessions AUTHENTIFIÉES d'une machine —
// pour un proxy, celles par lesquelles CE core le voit, en plus de ce que dit
// la base.
//
// Authentifiées seulement : l'identifiant d'une session en poignée de main est
// ANNONCÉ, pas prouvé. Le compter ferait accorder la confiance des proxies
// (TO-DO 184 : l'en-tête PROXY du LDAPS) à quiconque annonce l'identifiant
// d'un proxy.
func (m *Manager) AdressesDe(clientSoftwareID string) []string {
	id := strings.ToLower(strings.TrimSpace(clientSoftwareID))
	if id == "" {
		return nil
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	vues := map[string]bool{}
	var out []string
	for _, s := range m.sessions {
		if s.Status != SessionAuthenticated || s.DuckySession == nil ||
			strings.ToLower(strings.TrimSpace(s.ClientSoftwareID)) != id {
			continue
		}
		if h := hoteSource(s.RemoteAddr); h != "" && !vues[h] {
			vues[h] = true
			out = append(out, h)
		}
	}
	sort.Strings(out)
	return out
}

func hoteSource(adresse string) string {
	a := strings.TrimSpace(adresse)
	if a == "" {
		return ""
	}
	if h, _, err := net.SplitHostPort(a); err == nil {
		a = h
	}
	return strings.ToLower(strings.Trim(a, "[]"))
}

// retenue : la session arrive par une des adresses, et n'est pas le proxy.
// À appeler sous le verrou.
func (v ParSource) retenue(s *Session) bool {
	if len(v.adresses) == 0 || !v.adresses[hoteSource(s.RemoteAddr)] {
		return false
	}
	return v.exclure == "" || strings.ToLower(strings.TrimSpace(s.ClientSoftwareID)) != v.exclure
}

// MachinesConnectees : comme celle du registre, restreinte à la vue.
func (v ParSource) MachinesConnectees() []string {
	v.m.mu.RLock()
	defer v.m.mu.RUnlock()
	vues := map[string]bool{}
	var out []string
	for _, s := range v.m.sessions {
		if !v.retenue(s) || s.Status != SessionAuthenticated || s.Username != CompteMachine || s.DuckySession == nil {
			continue
		}
		id := strings.TrimSpace(s.ClientSoftwareID)
		cle := strings.ToLower(id)
		if id == "" || vues[cle] {
			continue
		}
		vues[cle] = true
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// IDs : les sessions de la vue.
func (v ParSource) IDs() []string {
	v.m.mu.RLock()
	defer v.m.mu.RUnlock()
	var out []string
	for id, s := range v.m.sessions {
		if v.retenue(s) {
			out = append(out, id)
		}
	}
	sort.Strings(out)
	return out
}

// Fermer ferme une session de la vue — et seulement elle : un identifiant qui
// n'y est plus (session partie, puis identifiant repris) n'est pas fermé.
func (v ParSource) Fermer(sessionID string) bool {
	v.m.mu.RLock()
	s, ok := v.m.sessions[sessionID]
	garder := ok && v.retenue(s)
	v.m.mu.RUnlock()
	if !garder {
		return false
	}
	return v.m.Fermer(sessionID)
}
