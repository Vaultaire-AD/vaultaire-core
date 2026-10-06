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

// reglage est ce qu'un relais applique à une connexion : sa configuration et
// ses cibles. Les deux bougent ENSEMBLE — changer la source des cibles change
// le résolveur — et c'est pourquoi ils sont remplacés d'un seul geste.
type reglage struct {
	cfg    Relais
	cibles Resolveur
}

// Serveur fait tourner un relais.
type Serveur struct {
	// etat est remplacé en entier par Reconfigurer (TO-DO 141). Un pointeur
	// atomique : il est lu à chaque connexion et à chaque lecture de compteur,
	// écrit quelques fois dans la vie du proxy.
	etat    atomic.Pointer[reglage]
	journal Journal
	dial    func(network, addr string, d time.Duration) (net.Conn, error)

	// inactiviteMin, s'il est posé, relève l'inactivité tolérée sur une
	// connexion relayée. Voir DefinirInactiviteMin. Atomique : il est relu par
	// chaque connexion en cours pendant qu'une reconfiguration peut le changer.
	inactiviteMin atomic.Pointer[func() time.Duration]

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
	s := &Serveur{journal: journal, dial: net.DialTimeout,
		parSource: map[string]int{}, parCible: map[string]int64{}}
	s.etat.Store(&reglage{cfg: cfg, cibles: cibles})
	return s
}

// Config rend la configuration en vigueur.
func (s *Serveur) Config() Relais { return s.etat.Load().cfg }

// Cibles rend les cibles que le relais essaierait MAINTENANT, dans l'ordre.
// Pour le compte rendu au core : « vers quoi ce relais redirige » est la
// première chose qu'on veut lire, et la configuration seule ne le dit pas
// quand la source est « cores » ou « service: ».
func (s *Serveur) Cibles() []string {
	r := s.etat.Load()
	if r.cibles == nil {
		return nil
	}
	return r.cibles()
}

// Reconfigurer change la configuration d'un relais QUI ÉCOUTE DÉJÀ, sans
// fermer son port ni ses connexions (TO-DO 141).
//
// # Ce qui se change en place, et ce qui ne s'y change pas
//
// Les cibles, les plafonds, les délais et le type : ils ne s'appliquent qu'à
// la connexion suivante, et les connexions en cours gardent le réglage sous
// lequel elles ont été acceptées. L'adresse d'ÉCOUTE, elle, ne se change pas
// ici — il faut un autre port, donc un autre relais : c'est Parc qui ouvre le
// nouveau avant de fermer l'ancien.
//
// Un relais reconfiguré garde ses compteurs. Le fermer pour le rouvrir les
// aurait remis à zéro, et laissé « actives » compter des connexions qui
// vivent encore dans l'objet qu'on vient de jeter.
func (s *Serveur) Reconfigurer(cfg Relais, cibles Resolveur) {
	avant := s.etat.Load().cfg
	// L'écoute reste celle qui est ouverte, quoi que dise la nouvelle
	// configuration : ce champ décrit un fait, pas une intention.
	cfg.Ecoute = avant.Ecoute
	s.etat.Store(&reglage{cfg: cfg, cibles: cibles})
	s.journal("INFO", fmt.Sprintf("relais %s (%s) : reconfiguré sans coupure, écoute inchangée sur %s",
		cfg.Nom, cfg.Type, s.Adresse()))
}

// DefinirInactiviteMin pose — ou retire, avec nil — un plancher à l'inactivité
// tolérée sur une connexion relayée : la valeur appliquée est la plus grande
// des deux.
//
// Pour le relais Ducky (TO-DO 110) : le seul trafic régulier d'un tunnel est
// le battement du core, dont la cadence se règle jusqu'à une heure. À quinze
// minutes d'inactivité fixe, un proxy coupait tous les tunnels qu'il relayait
// dès que cette cadence les dépassait. La fonction est relue à CHAQUE
// lecture : une connexion ouverte avant un changement de cadence le suit.
func (s *Serveur) DefinirInactiviteMin(f func() time.Duration) {
	if f == nil {
		s.inactiviteMin.Store(nil)
		return
	}
	s.inactiviteMin.Store(&f)
}

// inactivite rend l'inactivité tolérée à cet instant.
func (s *Serveur) inactivite(cfg Relais) time.Duration {
	d := cfg.Inactivite()
	if f := s.inactiviteMin.Load(); f != nil {
		if min := (*f)(); min > d {
			return min
		}
	}
	return d
}

// Ecouter ouvre le port. Séparé de Servir pour qu'un port occupé soit une
// erreur de DÉMARRAGE, visible, et non une goroutine qui meurt en silence.
func (s *Serveur) Ecouter() error {
	cfg := s.Config()
	ln, err := net.Listen("tcp", cfg.Ecoute)
	if err != nil {
		return fmt.Errorf("relais %s : écoute sur %s impossible : %w", cfg.Nom, cfg.Ecoute, err)
	}
	s.ln = ln
	return nil
}

// Adresse rend l'adresse d'écoute effective (utile quand le port vaut 0).
func (s *Serveur) Adresse() string {
	if s.ln == nil {
		return s.Config().Ecoute
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
	s.journal("INFO", fmt.Sprintf("relais %s (%s) : écoute sur %s", s.Config().Nom, s.Config().Type, s.Adresse()))
	for {
		c, err := s.ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			s.journal("WARNING", fmt.Sprintf("relais %s : accept : %v", s.Config().Nom, err))
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
func (s *Serveur) prendre(src string, cfg Relais) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.actives.Load() >= int64(cfg.maxConnexions()) || s.parSource[src] >= cfg.maxParSource() {
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
	// Le réglage est lu UNE fois : la connexion vit jusqu'au bout sous celui
	// qui l'a acceptée, même si le relais est reconfiguré entre-temps.
	r := s.etat.Load()
	cfg := r.cfg

	src := source(client)
	if !s.prendre(src, cfg) {
		s.rejetees.Add(1)
		s.journal("WARNING", fmt.Sprintf("relais %s : connexion de %s rejetée, plafond atteint", cfg.Nom, src))
		_ = client.Close()
		return
	}
	defer s.rendre(src)
	s.total.Add(1)

	cible, amont := s.joindre(client, r)
	if amont == nil {
		// REFUS FRANC : fermer tout de suite. Le client essaie le suivant de
		// sa liste — un core, puisqu'ils y figurent toujours. Faire attendre
		// ferait du proxy un trou noir au lieu d'un nœud qu'on contourne.
		s.refusees.Add(1)
		s.mu.Lock()
		s.dernierRef = time.Now()
		s.mu.Unlock()
		s.journal("WARNING", fmt.Sprintf("relais %s : aucune cible joignable pour %s — connexion refusée", cfg.Nom, src))
		_ = client.Close()
		return
	}
	s.mu.Lock()
	s.parCible[cible]++
	s.mu.Unlock()
	s.journal("DEBUG", fmt.Sprintf("relais %s : %s → %s", cfg.Nom, src, cible))

	s.recopier(client, amont, cfg)
}

// joindre essaie les cibles dans l'ordre et rend la première qui accepte.
//
// L'ordre est celui du résolveur, sans rotation : le même client retombe sur la
// même cible tant qu'elle répond. Un agent garde en cache UNE clé de core ; le
// promener d'un core à l'autre à chaque connexion ferait échouer la poignée de
// main dès que les cores n'ont pas la même clé.
//
// Pour LDAPS, l'en-tête PROXY v2 est écrit ICI, avant tout octet du client :
// une cible qui ne l'accepte pas est traitée comme une cible injoignable, et
// la suivante est essayée.
func (s *Serveur) joindre(client net.Conn, r *reglage) (string, net.Conn) {
	cfg := r.cfg
	var entete []byte
	if cfg.EnvoieEnteteProxy() {
		var err error
		if entete, err = enteteV2(client.RemoteAddr(), client.LocalAddr()); err != nil {
			// Sans en-tête, le core compterait ce client sous l'adresse du
			// proxy : mieux vaut refuser que fausser la limitation.
			s.journal("WARNING", fmt.Sprintf("relais %s : en-tête PROXY impossible : %v", cfg.Nom, err))
			return "", nil
		}
	}
	if r.cibles == nil {
		return "", nil
	}
	for _, c := range r.cibles() {
		conn, err := s.dial("tcp", c, cfg.DelaiConnexion())
		if err == nil && entete != nil {
			_ = conn.SetWriteDeadline(time.Now().Add(cfg.DelaiConnexion()))
			if _, err = conn.Write(entete); err != nil {
				_ = conn.Close()
			} else {
				_ = conn.SetWriteDeadline(time.Time{})
			}
		}
		if err == nil {
			return c, conn
		}
		s.journal("DEBUG", fmt.Sprintf("relais %s : cible %s injoignable : %v", cfg.Nom, c, err))
	}
	return "", nil
}

// recopier transporte les octets dans les deux sens, sans les lire.
//
// Fin propre d'un sens (EOF) : on ferme seulement l'ÉCRITURE de l'autre côté,
// pour que l'autre sens finisse de passer (demi-fermeture TCP). Erreur ou
// inactivité : on ferme tout, ce qui débloque aussi l'autre sens.
func (s *Serveur) recopier(client, amont net.Conn, cfg Relais) {
	var wg sync.WaitGroup
	wg.Add(2)
	sens := func(dst, src net.Conn, compteur *atomic.Int64) {
		defer wg.Done()
		n, err := copierAvecInactivite(dst, src, func() time.Duration { return s.inactivite(cfg) })
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
//
// Une FONCTION, relue avant chaque lecture : le délai peut suivre un réglage
// qui change pendant que la connexion vit (voir Serveur.InactiviteMin).
func copierAvecInactivite(dst io.Writer, src net.Conn, inactivite func() time.Duration) (int64, error) {
	buf := make([]byte, 32*1024)
	var total int64
	for {
		_ = src.SetReadDeadline(time.Now().Add(inactivite()))
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
	cfg := s.Config()
	return Stats{Nom: cfg.Nom, Type: cfg.Type, Ecoute: s.Adresse(),
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
