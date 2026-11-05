package sessionmgr

import "strings"

// Comptage dit ce qu'un core porte en ce moment — TO-DO 148.
//
// # Pourquoi le core doit le PUBLIER
//
// Les sessions Ducky d'un core vivent dans son registre en mémoire, que les
// autres cores ne voient pas : la table user_sessions a pour clé (compte,
// machine), sans le core qui tient la session. Pour savoir combien un core
// porte, il faut donc que lui-même le dise — avec son battement, dans la même
// table que les mesures des proxies (TO-DO 108).
//
// C'est aussi le préalable du 147 : on ne purge pas un nœud sans voir son
// compteur descendre.
//
// # Ce que chaque nombre compte
//
//   - Machines : machines DISTINCTES qui tiennent un tunnel authentifié sous le
//     compte machine — postes, proxies, Nexus. Une machine en a parfois
//     plusieurs (le tunnel, plus les connexions de quelques secondes du
//     « --fetch-key » de sshd) : elle compte une fois ;
//   - Tunnels : ces sessions-là, sans dédoublonner. L'écart avec Machines est
//     le bruit normal des « --fetch-key » ; un écart qui grossit ne l'est pas ;
//   - Comptes : sessions authentifiées sous un compte de l'annuaire (autre que
//     le compte machine). Ce ne sont PAS les sessions SSH ouvertes sur les
//     postes : celles-ci passent dans le tunnel de la machine (TO-DO 68) ;
//   - Poignees : connexions en poignée de main, pas encore authentifiées. Une
//     population qui gonfle est la signature d'ouvertures muettes, ou d'un
//     balayage qui ne fait pas son travail.
//
// Les sessions en échec ne sont pas comptées : elles sont sur le départ, et les
// additionner aux autres ferait lire une charge qui n'existe pas.
type Comptage struct {
	Machines int
	Tunnels  int
	Comptes  int
	Poignees int
}

// Compter rend le comptage, pris sous le verrou en une seule passe : les quatre
// nombres décrivent le même instant.
func (m *Manager) Compter() Comptage {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var c Comptage
	machines := map[string]bool{}
	for _, s := range m.sessions {
		switch s.Status {
		case SessionPending:
			c.Poignees++
		case SessionAuthenticated:
			if s.Username == CompteMachine {
				c.Tunnels++
				if id := strings.ToLower(strings.TrimSpace(s.ClientSoftwareID)); id != "" {
					machines[id] = true
				}
			} else {
				c.Comptes++
			}
		}
	}
	c.Machines = len(machines)
	return c
}

// IDs rend les identifiants des sessions présentes, par valeur.
//
// Pour la purge d'un core en maintenance (TO-DO 147) : la liste est prise en
// une fois, puis fermée session par session hors verrou — chaque fermeture
// reprend le verrou elle-même.
func (m *Manager) IDs() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]string, 0, len(m.sessions))
	for id := range m.sessions {
		out = append(out, id)
	}
	return out
}

// Fermer ferme une session et dit si elle était encore là.
//
// RemoveSession ne le dit pas ; la purge compte ce qu'elle a réellement fermé,
// et une session partie d'elle-même entre-temps — l'agent qui a basculé — ne
// doit pas être comptée comme fermée par elle.
func (m *Manager) Fermer(sessionID string) bool {
	m.mu.Lock()
	s, ok := m.sessions[sessionID]
	if ok {
		delete(m.sessions, sessionID)
	}
	m.mu.Unlock()
	if ok && s.Conn != nil {
		_ = s.Conn.Close()
	}
	return ok
}
