// Package certimporte sert des certificats TLS fournis par fichier — TO-DO 262.
//
// # Pourquoi
//
// Le core produit lui-même ses certificats LDAPS, portail et API : auto-signés,
// rangés en base au premier démarrage. C'est commode sur une machine isolée, et
// c'est un obstacle dès qu'une autorité existe déjà. En Kubernetes, cert-manager
// émet le certificat, le range dans un Secret `kubernetes.io/tls` et le
// renouvelle seul, tous les deux mois environ. Les applications clientes du
// LDAPS (Keycloak, un connecteur) font alors confiance à l'AUTORITÉ, et non plus
// à l'empreinte d'un certificat qu'il faut réimporter chez chacune à chaque
// changement.
//
// # Ce que fait le paquet
//
// Pour chaque service déclaré (certificat ET clé, les deux ou aucun) :
//
//   - au démarrage, il lit la paire, vérifie que la clé correspond au
//     certificat et que celui-ci est en cours de validité. Un défaut ARRÊTE le
//     core : démarrer sur le certificat auto-signé à la place servirait aux
//     clients un certificat qu'ils refusent, sans que personne ne le voie ;
//   - pendant le service, il RELIT la paire une fois par Intervalle — à
//     l'occasion d'une poignée de main, et en tâche de fond pour qu'un
//     renouvellement raté se voie au journal même sans trafic. Le Secret mis à jour par cert-manager
//     est donc servi sans redémarrage, et les connexions ouvertes ne sont pas
//     coupées. Une paire illisible ou incohérente n'est jamais servie : le core
//     garde la précédente et le dit.
//
// Le certificat importé ne passe JAMAIS en base : la base garde l'auto-signé, que
// le core retrouve si l'on retire l'import.
package certimporte

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Services connus. Les noms sont ceux de la commande `vlt certificate`.
const (
	ServiceLDAPS = "ldaps"
	ServiceWeb   = "web"
	ServiceAPI   = "api"
)

// Intervalle sépare deux relectures des fichiers. Assez court pour qu'un
// renouvellement soit servi dans la minute ; assez long pour que relire deux
// petits fichiers ne pèse rien, même sous une rafale de connexions.
var Intervalle = 30 * time.Second

// TailleMax borne la lecture d'un fichier : une chaîne de certificats, une clé.
// Un chemin qui désignerait autre chose n'est pas lu en entier en mémoire.
const TailleMax = 256 << 10

// Journal reçoit les événements du rechargement (niveau, message). Branché sur
// logs.Write_Log par le core ; les tests le remplacent.
var Journal = func(niveau, message string) {}

// Source est une paire certificat + clé lue sur disque.
type Source struct {
	Service  string
	CertFile string
	KeyFile  string

	mu             sync.RWMutex
	actuel         *tls.Certificate
	feuille        *x509.Certificate
	certPEM        []byte
	empreinte      [32]byte // de la paire servie (certificat + clé)
	chargeLe       time.Time
	prochaineVue   time.Time
	derniereErr    string
	echecSignale   [32]byte // paire refusée déjà dite au journal
	echecEnAttente [32]byte // paire refusée une fois : peut-être lue en pleine écriture

	maintenant func() time.Time
	arret      chan struct{}
	fini       chan struct{}
}

// Nouvelle prépare une source ; rien n'est lu avant Charger.
func Nouvelle(service, certFile, keyFile string) *Source {
	return &Source{Service: service, CertFile: certFile, KeyFile: keyFile, maintenant: time.Now}
}

// Charger lit la paire pour la première fois. Toute anomalie est une erreur.
func (s *Source) Charger() error {
	certPEM, keyPEM, err := s.lire()
	if err != nil {
		return err
	}
	paire, feuille, err := analyser(certPEM, keyPEM, s.maintenant())
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.poser(paire, feuille, certPEM, keyPEM)
	return nil
}

// GetCertificate se branche sur tls.Config.GetCertificate.
func (s *Source) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	s.Rafraichir(false)
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.actuel == nil {
		return nil, fmt.Errorf("certificat %s non chargé", s.Service)
	}
	return s.actuel, nil
}

// Rafraichir relit la paire si l'intervalle est écoulé (ou tout de suite si
// force). Rend vrai quand un nouveau certificat est désormais servi.
func (s *Source) Rafraichir(force bool) bool {
	maintenant := s.maintenant()
	s.mu.Lock()
	if !force && maintenant.Before(s.prochaineVue) {
		s.mu.Unlock()
		return false
	}
	s.prochaineVue = maintenant.Add(Intervalle)
	s.mu.Unlock()

	certPEM, keyPEM, err := s.lire()
	if err != nil {
		s.refus(sha256.Sum256([]byte(err.Error())), err, true)
		return false
	}
	emp := empreintePaire(certPEM, keyPEM)

	s.mu.RLock()
	inchange := emp == s.empreinte
	s.mu.RUnlock()
	if inchange {
		s.mu.Lock()
		s.derniereErr = ""
		s.echecEnAttente = [32]byte{}
		s.mu.Unlock()
		return false
	}

	paire, feuille, err := analyser(certPEM, keyPEM, maintenant)
	if err != nil {
		s.refus(emp, err, false)
		return false
	}

	s.mu.Lock()
	s.poser(paire, feuille, certPEM, keyPEM)
	s.mu.Unlock()
	Journal("INFO", fmt.Sprintf("%s: certificat rechargé depuis %s — %s", s.Service, s.CertFile, Resume(feuille)))
	return true
}

// refus garde la paire servie et le dit — une fois par contenu refusé.
//
// Une paire refusée UNE fois n'est pas encore signalée : Kubernetes remplace
// les fichiers d'un Secret d'un seul geste, mais une lecture qui tombe entre le
// certificat et la clé d'un autre outil verrait une paire incohérente le temps
// d'une écriture. La relecture suivante (dans Intervalle) tranche.
func (s *Source) refus(emp [32]byte, err error, lecture bool) {
	s.mu.Lock()
	s.derniereErr = err.Error()
	dejaDit := emp == s.echecSignale
	premiere := emp != s.echecEnAttente
	s.echecEnAttente = emp
	if premiere && !lecture {
		// On revient vite : c'est peut-être une écriture en cours.
		s.prochaineVue = s.maintenant().Add(2 * time.Second)
	}
	if dejaDit || (premiere && !lecture) {
		s.mu.Unlock()
		return
	}
	s.echecSignale = emp
	s.mu.Unlock()
	Journal("ERROR", fmt.Sprintf("%s: nouveau certificat refusé, l'ancien reste servi — %v", s.Service, err))
}

func (s *Source) poser(paire *tls.Certificate, feuille *x509.Certificate, certPEM, keyPEM []byte) {
	s.actuel = paire
	s.feuille = feuille
	s.certPEM = certPEM
	s.empreinte = empreintePaire(certPEM, keyPEM)
	s.chargeLe = s.maintenant()
	s.derniereErr = ""
	s.echecEnAttente = [32]byte{}
}

// CertPEM rend le certificat servi (la chaîne entière, partie publique).
func (s *Source) CertPEM() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return string(s.certPEM)
}

// Etat décrit la source pour `vlt certificate show`.
type Etat struct {
	CertFile, KeyFile string
	Sujet             string
	Emetteur          string
	NonApres          time.Time
	ChargeLe          time.Time
	DerniereErreur    string
}

// Etat rend l'état courant.
func (s *Source) Etat() Etat {
	s.mu.RLock()
	defer s.mu.RUnlock()
	e := Etat{CertFile: s.CertFile, KeyFile: s.KeyFile, ChargeLe: s.chargeLe, DerniereErreur: s.derniereErr}
	if s.feuille != nil {
		e.Sujet = s.feuille.Subject.String()
		e.Emetteur = s.feuille.Issuer.String()
		e.NonApres = s.feuille.NotAfter
	}
	return e
}

// lire rend le contenu des deux fichiers.
func (s *Source) lire() ([]byte, []byte, error) {
	certPEM, err := lireFichier(s.CertFile)
	if err != nil {
		return nil, nil, fmt.Errorf("certificat %s : %w", s.CertFile, err)
	}
	keyPEM, err := lireFichier(s.KeyFile)
	if err != nil {
		return nil, nil, fmt.Errorf("clé %s : %w", s.KeyFile, err)
	}
	return certPEM, keyPEM, nil
}

// lireFichier lit par un os.Root ouvert sur le répertoire du fichier.
//
// Un Secret Kubernetes monté en volume est fait de liens : tls.crt →
// ..data/tls.crt, ..data → ..2026_11_05_…/. Tous restent DANS le répertoire
// monté : os.Root les suit, et refuserait un lien qui en sortirait.
func lireFichier(chemin string) ([]byte, error) {
	racine, err := os.OpenRoot(filepath.Dir(chemin))
	if err != nil {
		return nil, err
	}
	defer func() { _ = racine.Close() }()
	f, err := racine.Open(filepath.Base(chemin))
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	contenu, err := io.ReadAll(io.LimitReader(f, TailleMax+1))
	if err != nil {
		return nil, err
	}
	if len(contenu) > TailleMax {
		return nil, fmt.Errorf("plus de %d octets : ce n'est pas un fichier PEM", TailleMax)
	}
	if len(bytes.TrimSpace(contenu)) == 0 {
		return nil, errors.New("fichier vide")
	}
	return contenu, nil
}

// analyser valide une paire et en rend la forme servie.
func analyser(certPEM, keyPEM []byte, maintenant time.Time) (*tls.Certificate, *x509.Certificate, error) {
	if b, _ := pem.Decode(certPEM); b == nil || b.Type != "CERTIFICATE" {
		return nil, nil, errors.New("le fichier de certificat ne commence pas par un bloc PEM CERTIFICATE (clé et certificat inversés ?)")
	}
	paire, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, nil, fmt.Errorf("paire refusée : %v", err)
	}
	feuille, err := x509.ParseCertificate(paire.Certificate[0])
	if err != nil {
		return nil, nil, fmt.Errorf("certificat illisible : %v", err)
	}
	paire.Leaf = feuille
	switch {
	case maintenant.After(feuille.NotAfter):
		return nil, nil, fmt.Errorf("certificat expiré le %s", feuille.NotAfter.Format("2006-01-02 15:04"))
	case maintenant.Before(feuille.NotBefore):
		return nil, nil, fmt.Errorf("certificat pas encore valide (début le %s) — vérifiez l'horloge", feuille.NotBefore.Format("2006-01-02 15:04"))
	}
	if feuille.IsCA && len(feuille.DNSNames) == 0 && len(feuille.IPAddresses) == 0 {
		return nil, nil, errors.New("le premier certificat du fichier est une autorité, pas le certificat du serveur : mettre le certificat du serveur en tête de la chaîne")
	}
	return &paire, feuille, nil
}

func empreintePaire(certPEM, keyPEM []byte) [32]byte {
	h := sha256.New()
	h.Write(certPEM)
	h.Write([]byte{0})
	h.Write(keyPEM)
	var e [32]byte
	copy(e[:], h.Sum(nil))
	return e
}

// Resume décrit un certificat en une ligne, pour le journal.
func Resume(c *x509.Certificate) string {
	noms := append([]string{}, c.DNSNames...)
	for _, ip := range c.IPAddresses {
		noms = append(noms, ip.String())
	}
	if len(noms) == 0 {
		noms = []string{"aucun SAN"}
	}
	return fmt.Sprintf("émis par %q, valide jusqu'au %s, couvre %s",
		c.Issuer.CommonName, c.NotAfter.Format("2006-01-02"), strings.Join(noms, ", "))
}

// ---------------------------------------------------------------------------
// Registre des services importés
// ---------------------------------------------------------------------------

var (
	registreMu sync.RWMutex
	registre   = map[string]*Source{}
)

// Configurer valide la déclaration d'un service et l'enregistre.
//
// Les deux chemins vides : rien n'est importé, le service garde son certificat
// en base. Un seul des deux : erreur — une clé sans certificat (ou l'inverse)
// est toujours une faute de frappe, et la laisser passer ferait servir
// l'auto-signé en silence.
func Configurer(service, certFile, keyFile string) error {
	certFile, keyFile = strings.TrimSpace(certFile), strings.TrimSpace(keyFile)
	registreMu.Lock()
	if ancien := registre[service]; ancien != nil {
		ancien.arreter()
	}
	delete(registre, service)
	registreMu.Unlock()
	switch {
	case certFile == "" && keyFile == "":
		return nil
	case certFile == "":
		return fmt.Errorf("%s : clé déclarée (%s) sans certificat", service, keyFile)
	case keyFile == "":
		return fmt.Errorf("%s : certificat déclaré (%s) sans clé", service, certFile)
	}
	s := Nouvelle(service, certFile, keyFile)
	if err := s.Charger(); err != nil {
		return fmt.Errorf("%s : %v", service, err)
	}
	registreMu.Lock()
	registre[service] = s
	registreMu.Unlock()
	s.surveiller()
	return nil
}

// surveiller relit la paire à chaque Intervalle, trafic ou pas.
//
// La relecture à la poignée de main suffit à SERVIR un renouvellement ; elle ne
// suffit pas à le SIGNALER : sur un service peu sollicité (l'API, un LDAPS
// qu'interroge une seule application la nuit), un Secret cassé ne serait dit
// au journal qu'à la première connexion — peut-être après l'expiration de
// l'ancien certificat.
func (s *Source) surveiller() {
	s.mu.Lock()
	if s.arret != nil {
		s.mu.Unlock()
		return
	}
	arret, fini := make(chan struct{}), make(chan struct{})
	s.arret, s.fini = arret, fini
	s.mu.Unlock()
	go func() {
		defer close(fini)
		t := time.NewTicker(Intervalle)
		defer t.Stop()
		for {
			select {
			case <-arret:
				return
			case <-t.C:
				s.Rafraichir(false)
			}
		}
	}()
}

// arreter met fin à la surveillance et attend qu'elle soit finie.
func (s *Source) arreter() {
	s.mu.Lock()
	arret, fini := s.arret, s.fini
	s.arret, s.fini = nil, nil
	s.mu.Unlock()
	if arret != nil {
		close(arret)
		<-fini
	}
}

// Pour rend la source d'un service, ou nil s'il garde son certificat en base.
func Pour(service string) *Source {
	registreMu.RLock()
	defer registreMu.RUnlock()
	return registre[service]
}
