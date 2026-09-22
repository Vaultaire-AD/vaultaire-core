package relais

import (
	"errors"
	"fmt"
	"io"
	"net"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// Resolveur rend les cibles à essayer, dans l'ordre. Appelé à CHAQUE
// connexion : la liste suit le cluster sans redémarrage.
type Resolveur func() []string

// Journal reçoit les événements (niveau, message). Injecté pour ne pas lier le
// paquet au socle de journalisation, et pour les tests.
type Journal func(niveau, message string)

// Stats est l'état d'un relais, par valeur.
type Stats struct {
	Nom            string
	Type           Type
	Ecoute         string
	Actives        int64
	Total          int64
	Refusees       int64 // aucune cible joignable : refus franc
	Rejetees       int64 // plafond atteint
	OctetsMontants int64 // client → cible
	OctetsDescend  int64 // cible → client
	ParCible       map[string]int64
	DernierRefus   time.Time
}

// Serveur fait tourner un relais.
type Serveur struct {
	cfg     Relais
	cibles  Resolveur
	journal Journal
	dial    func(network, addr string, d time.Duration) (net.Conn, error)

	actives, total, refusees, rejetees atomic.Int64
	montants, descendants              atomic.Int64

	mu         sync.Mutex
	parSource  map[string]int
	parCible   map[string]int64
	dernierRef time.Time

	ln net.Listener
}

// Nouveau prépare un relais. cibles ne doit pas être nil.
func Nouveau(cfg Relais, cibles Resolveur, journal Journal) *Serveur {
	if journal == nil {
		journal = func(string, string) {}
	}
	return &Serveur{cfg: cfg, cibles: cibles, journal: journal, dial: net.DialTimeout,
		parSource: map[string]int{}, parCible: map[string]int64{}}
}

// Ecouter ouvre le port. Séparé de Servir pour qu'un port occupé soit une
// erreur de DÉMARRAGE, visible, et non une goroutine qui meurt en silence.
func (s *Serveur) Ecouter() error {
	ln, err := net.Listen("tcp", s.cfg.Ecoute)
	if err != nil {
		return fmt.Errorf("relais %s : écoute sur %s impossible : %w", s.cfg.Nom, s.cfg.Ecoute, err)
	}
	s.ln = ln
	return nil
}

// Adresse rend l'adresse d'écoute effective (utile quand le port vaut 0).
func (s *Serveur) Adresse() string {
	if s.ln == nil {
		return s.cfg.Ecoute
	}
	return s.ln.Addr().String()
}

// Fermer arrête l'écoute. Les connexions en cours vont à leur terme.
func (s *Serveur) Fermer() error {
	if s.ln == nil {
		return nil
	}
	return s.ln.Close()
}

// Servir accepte les connexions jusqu'à Fermer.
func (s *Serveur) Servir() error {
	if s.ln == nil {
		if err := s.Ecouter(); err != nil {
			return err
		}
	}
	s.journal("INFO", fmt.Sprintf("relais %s (%s) : écoute sur %s", s.cfg.Nom, s.cfg.Type, s.Adresse()))
	for {
		c, err := s.ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			s.journal("WARNING", fmt.Sprintf("relais %s : accept : %v", s.cfg.Nom, err))
			time.Sleep(100 * time.Millisecond)
			continue
		}
		go s.traiter(c)
	}
}

func source(c net.Conn) string {
	h, _, err := net.SplitHostPort(c.RemoteAddr().String())
	if err != nil {
		return c.RemoteAddr().String()
	}
	return h
}

// prendre réserve une place ; rend faux si un plafond est atteint.
func (s *Serveur) prendre(src string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.actives.Load() >= int64(s.cfg.maxConnexions()) || s.parSource[src] >= s.cfg.maxParSource() {
		return false
	}
	s.parSource[src]++
	s.actives.Add(1)
	return true
}

func (s *Serveur) rendre(src string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.actives.Add(-1)
	if s.parSource[src] <= 1 {
		delete(s.parSource, src)
	} else {
		s.parSource[src]--
	}
}

func (s *Serveur) traiter(client net.Conn) {
	src := source(client)
	if !s.prendre(src) {
		s.rejetees.Add(1)
		s.journal("WARNING", fmt.Sprintf("relais %s : connexion de %s rejetée, plafond atteint", s.cfg.Nom, src))
		_ = client.Close()
		return
	}
	defer s.rendre(src)
	s.total.Add(1)

	cible, amont := s.joindre()
	if amont == nil {
		// REFUS FRANC : fermer tout de suite. Le client essaie le suivant de
		// sa liste — un core, puisqu'ils y figurent toujours. Faire attendre
		// ferait du proxy un trou noir au lieu d'un nœud qu'on contourne.
		s.refusees.Add(1)
		s.mu.Lock()
		s.dernierRef = time.Now()
		s.mu.Unlock()
		s.journal("WARNING", fmt.Sprintf("relais %s : aucune cible joignable pour %s — connexion refusée", s.cfg.Nom, src))
		_ = client.Close()
		return
	}
	s.mu.Lock()
	s.parCible[cible]++
	s.mu.Unlock()
	s.journal("DEBUG", fmt.Sprintf("relais %s : %s → %s", s.cfg.Nom, src, cible))

	s.recopier(client, amont)
}

// joindre essaie les cibles dans l'ordre et rend la première qui accepte.
//
// L'ordre est celui du résolveur, sans rotation : le même client retombe sur la
// même cible tant qu'elle répond. Un agent garde en cache UNE clé de core ; le
// promener d'un core à l'autre à chaque connexion ferait échouer la poignée de
// main dès que les cores n'ont pas la même clé.
func (s *Serveur) joindre() (string, net.Conn) {
	for _, c := range s.cibles() {
		conn, err := s.dial("tcp", c, s.cfg.DelaiConnexion())
		if err == nil {
			return c, conn
		}
		s.journal("DEBUG", fmt.Sprintf("relais %s : cible %s injoignable : %v", s.cfg.Nom, c, err))
	}
	return "", nil
}

// recopier transporte les octets dans les deux sens, sans les lire.
//
// Fin propre d'un sens (EOF) : on ferme seulement l'ÉCRITURE de l'autre côté,
// pour que l'autre sens finisse de passer (demi-fermeture TCP). Erreur ou
// inactivité : on ferme tout, ce qui débloque aussi l'autre sens.
func (s *Serveur) recopier(client, amont net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	sens := func(dst, src net.Conn, compteur *atomic.Int64) {
		defer wg.Done()
		n, err := copierAvecInactivite(dst, src, s.cfg.Inactivite())
		compteur.Add(n)
		tc, demi := dst.(*net.TCPConn)
		if errors.Is(err, io.EOF) && demi {
			_ = tc.CloseWrite()
			return
		}
		_ = src.Close()
		_ = dst.Close()
	}
	go sens(amont, client, &s.montants)
	go sens(client, amont, &s.descendants)
	wg.Wait()
	_ = client.Close()
	_ = amont.Close()
}

// copierAvecInactivite recopie src vers dst ; une lecture sans rien pendant
// « inactivite » termine la copie.
func copierAvecInactivite(dst io.Writer, src net.Conn, inactivite time.Duration) (int64, error) {
	buf := make([]byte, 32*1024)
	var total int64
	for {
		_ = src.SetReadDeadline(time.Now().Add(inactivite))
		n, err := src.Read(buf)
		if n > 0 {
			w, errW := dst.Write(buf[:n])
			total += int64(w)
			if errW != nil {
				return total, errW
			}
		}
		if err != nil {
			return total, err
		}
	}
}

// Stats rend l'état du relais.
func (s *Serveur) Stats() Stats {
	s.mu.Lock()
	par := make(map[string]int64, len(s.parCible))
	for k, v := range s.parCible {
		par[k] = v
	}
	dr := s.dernierRef
	s.mu.Unlock()
	return Stats{Nom: s.cfg.Nom, Type: s.cfg.Type, Ecoute: s.Adresse(),
		Actives: s.actives.Load(), Total: s.total.Load(), Refusees: s.refusees.Load(),
		Rejetees: s.rejetees.Load(), OctetsMontants: s.montants.Load(), OctetsDescend: s.descendants.Load(),
		ParCible: par, DernierRefus: dr}
}

// Resume rend une ligne de journal.
func (st Stats) Resume() string {
	cibles := make([]string, 0, len(st.ParCible))
	for k, v := range st.ParCible {
		cibles = append(cibles, fmt.Sprintf("%s=%d", k, v))
	}
	sort.Strings(cibles)
	return fmt.Sprintf("relais %s (%s, %s) : %d active(s), %d au total, %d refusée(s) faute de cible, %d rejetée(s) au plafond, %d o ↑ / %d o ↓, cibles [%v]",
		st.Nom, st.Type, st.Ecoute, st.Actives, st.Total, st.Refusees, st.Rejetees, st.OctetsMontants, st.OctetsDescend, cibles)
}
