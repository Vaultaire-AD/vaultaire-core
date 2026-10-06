package relais

import (
	"fmt"
	"net"
	"sync"
	"time"
)

// Parc tient l'ensemble des relais d'un proxy et sait en CHANGER pendant
// qu'ils tournent (TO-DO 141).
//
// # Ce qui manquait
//
// Les relais étaient lus dans le fichier au démarrage, ouverts, et plus rien
// ne bougeait : en ajouter un demandait de modifier un fichier sur la machine
// et de redémarrer le proxy — donc de couper tous les tunnels qu'il relayait.
// Le core ne savait de ces relais que leurs compteurs.
//
// # Ce que fait Appliquer
//
// Elle reçoit la liste VOULUE et amène le parc à cet état en touchant le moins
// possible à ce qui tourne :
//
//   - un relais qui n'est plus demandé cesse d'écouter ; ses connexions en
//     cours vont à leur terme ;
//   - un relais demandé sur la MÊME écoute est reconfiguré en place — cibles,
//     plafonds, délais — sans fermer son port ni perdre ses compteurs ;
//   - un relais demandé sur une AUTRE écoute ouvre d'abord le nouveau port, et
//     ne ferme l'ancien que si le nouveau est obtenu ;
//   - un relais nouveau est ouvert.
//
// # Seul le proxy sait s'il a obtenu un port
//
// Le core peut demander « :443 ». Le proxy tourne peut-être sans le droit
// d'ouvrir un port bas, ou ce port est déjà pris par un autre programme. Rien
// de cela ne se sait d'ailleurs que d'ici : chaque relais demandé reçoit donc
// un ÉTAT — actif, ou refusé avec le motif — et c'est cet état que le proxy
// remonte. Un relais refusé n'empêche pas les autres de tourner.
type Parc struct {
	mu sync.Mutex

	portAnnonce int
	resolveur   func(Relais) Resolveur
	journal     Journal

	// Lancer démarre la boucle d'un relais. Injecté : le proxy y met son
	// lanceur de goroutines surveillées, les tests un simple « go ».
	Lancer func(nom string, f func())

	// InactiviteMinDucky est posé sur chaque relais Ducky ouvert. Voir
	// Serveur.DefinirInactiviteMin.
	InactiviteMinDucky func() time.Duration

	actifs map[string]*Serveur
	ordre  []string
	refus  []Refus
}

// NouveauParc prépare un parc vide. resolveur rend, pour un relais, la
// fonction qui donne ses cibles.
func NouveauParc(portAnnonce int, resolveur func(Relais) Resolveur, journal Journal) *Parc {
	if journal == nil {
		journal = func(string, string) {}
	}
	return &Parc{
		portAnnonce: portAnnonce,
		resolveur:   resolveur,
		journal:     journal,
		Lancer:      func(_ string, f func()) { go f() },
		actifs:      map[string]*Serveur{},
	}
}

// Statuts d'un relais dans un compte rendu.
const (
	StatutActif  = "actif"
	StatutRefuse = "refuse"
)

// Etat est un relais tel que le parc le tient : sa configuration, s'il tourne,
// et sinon pourquoi.
type Etat struct {
	Relais Relais
	Statut string
	Motif  string
	// Ecoute est l'adresse réellement ouverte ; Cibles, celles que le relais
	// essaierait maintenant. Vides pour un relais refusé.
	Ecoute string
	Cibles []string
}

// ErrSansRelaisDucky est rendue quand une liste ne porte pas de relais Ducky
// utilisable.
//
// # Pourquoi c'est la liste entière qui est refusée
//
// Le proxy est annoncé aux agents comme un nœud Ducky, sur le port qu'il a
// déclaré au cluster. Appliquer une liste sans ce relais en ferait un trou
// noir : les agents s'y présenteraient et rien ne répondrait. Mieux vaut
// garder l'état d'avant, entier, et dire au core que sa demande est refusée.
type ErrSansRelaisDucky struct {
	PortAnnonce int
	// Motif est celui du refus du relais Ducky présenté, s'il y en avait un.
	Motif string
}

func (e ErrSansRelaisDucky) Error() string {
	if e.Motif != "" {
		return fmt.Sprintf("liste refusée en entier : son relais Ducky est inutilisable (%s), "+
			"et ce proxy est annoncé aux agents sur le port %d", e.Motif, e.PortAnnonce)
	}
	return fmt.Sprintf("liste refusée en entier : elle ne porte aucun relais Ducky, "+
		"alors que ce proxy est annoncé aux agents sur le port %d", e.PortAnnonce)
}

// Appliquer amène le parc à la liste voulue. Rend l'état de chaque relais
// demandé, dans l'ordre de la liste.
//
// Une erreur veut dire que RIEN n'a été touché : la liste est refusée en
// entier (voir ErrSansRelaisDucky). Un relais refusé individuellement n'est
// pas une erreur — il figure dans les états rendus.
func (p *Parc) Appliquer(liste []Relais) ([]Etat, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	retenus, refus := Trier(liste, p.portAnnonce)
	if !PorteUnRelaisDucky(retenus) {
		err := ErrSansRelaisDucky{PortAnnonce: p.portAnnonce}
		for _, r := range refus {
			if r.Relais.Type == TypeDucky || r.Relais.Type == "" {
				err.Motif = r.Motif
				break
			}
		}
		return nil, err
	}

	voulus := map[string]bool{}
	for _, r := range retenus {
		voulus[r.Nom] = true
	}
	// Un relais qui TOURNE et dont la nouvelle version est refusée n'est pas
	// retiré pour autant : on ne coupe pas ce qui marche parce qu'on a reçu,
	// sous le même nom, une demande qu'on ne peut pas honorer.
	var gardes []string
	for i, r := range refus {
		nom := r.Relais.Nom
		if nom == "" || voulus[nom] {
			continue
		}
		if _, tourne := p.actifs[nom]; tourne {
			voulus[nom] = true
			gardes = append(gardes, nom)
			refus[i].Motif += " — l'ancienne configuration reste en service"
		}
	}

	// 1. Ce qui n'est plus demandé cesse d'écouter. AVANT les ouvertures : un
	// relais nouveau peut reprendre le port d'un relais retiré.
	for nom, srv := range p.actifs {
		if voulus[nom] {
			continue
		}
		_ = srv.Fermer()
		delete(p.actifs, nom)
		p.journal("INFO", fmt.Sprintf("relais %s : retiré, écoute %s fermée — les connexions en cours vont à leur terme",
			nom, srv.Adresse()))
	}

	// 2. Reconfigurer, déplacer, ouvrir.
	var ordre []string
	for _, r := range retenus {
		ancien, tourne := p.actifs[r.Nom]
		switch {
		case tourne && memeEcoute(ancien.Config().Ecoute, r.Ecoute):
			ancien.Reconfigurer(r, p.resolveur(r))
			p.poserInactivite(ancien, r)

		case tourne:
			// Autre écoute : le nouveau port d'abord. S'il n'est pas obtenu,
			// l'ancien reste en service — on ne coupe pas ce qui marche pour
			// une demande qu'on ne peut pas honorer.
			nouveau, err := p.ouvrir(r)
			if err != nil {
				refus = append(refus, Refus{Relais: r, err: err,
					Motif: err.Error() + " — l'ancienne écoute " + ancien.Adresse() + " reste en service"})
				ordre = append(ordre, r.Nom)
				continue
			}
			_ = ancien.Fermer()
			p.actifs[r.Nom] = nouveau
			p.journal("INFO", fmt.Sprintf("relais %s : déplacé de %s vers %s", r.Nom, ancien.Adresse(), nouveau.Adresse()))

		default:
			nouveau, err := p.ouvrir(r)
			if err != nil {
				refus = append(refus, refuser(r, err))
				continue
			}
			p.actifs[r.Nom] = nouveau
		}
		ordre = append(ordre, r.Nom)
	}

	p.ordre = append(ordre, gardes...)
	p.refus = refus
	return p.etats(), nil
}

// ouvrir ouvre le port d'un relais et lance sa boucle.
func (p *Parc) ouvrir(r Relais) (*Serveur, error) {
	srv := Nouveau(r, p.resolveur(r), p.journal)
	p.poserInactivite(srv, r)
	if err := srv.Ecouter(); err != nil {
		return nil, err
	}
	p.Lancer("relais "+r.Nom, func() {
		if err := srv.Servir(); err != nil {
			p.journal("ERROR", fmt.Sprintf("relais arrêté : %v", err))
		}
	})
	return srv, nil
}

func (p *Parc) poserInactivite(srv *Serveur, r Relais) {
	if r.Type == TypeDucky {
		srv.DefinirInactiviteMin(p.InactiviteMinDucky)
	} else {
		srv.DefinirInactiviteMin(nil)
	}
}

// memeEcoute compare deux adresses d'écoute. « :6666 » et « 0.0.0.0:6666 »
// désignent la même écoute : les traiter comme différentes ferait rouvrir un
// port déjà ouvert, donc échouer sur « adresse déjà utilisée » contre soi-même.
func memeEcoute(a, b string) bool {
	if a == b {
		return true
	}
	ha, pa, errA := net.SplitHostPort(a)
	hb, pb, errB := net.SplitHostPort(b)
	if errA != nil || errB != nil || pa != pb {
		return false
	}
	toutes := func(h string) bool { return h == "" || h == "0.0.0.0" || h == "::" }
	return ha == hb || (toutes(ha) && toutes(hb))
}

// Etats rend l'état de chaque relais : ceux qui tournent, dans l'ordre de la
// dernière liste appliquée, puis ceux qu'elle demandait et qui sont refusés.
func (p *Parc) Etats() []Etat {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.etats()
}

func (p *Parc) etats() []Etat {
	out := make([]Etat, 0, len(p.ordre)+len(p.refus))
	refuses := map[string]bool{}
	for _, r := range p.refus {
		if r.Relais.Nom != "" {
			refuses[r.Relais.Nom] = true
		}
	}
	for _, nom := range p.ordre {
		srv, ok := p.actifs[nom]
		// Un relais dont le DÉPLACEMENT a été refusé tourne encore sur son
		// ancienne écoute : il sort plus bas, comme refusé, avec ce motif.
		if !ok || refuses[nom] {
			continue
		}
		out = append(out, Etat{Relais: srv.Config().Effectif(), Statut: StatutActif,
			Ecoute: srv.Adresse(), Cibles: srv.Cibles()})
	}
	for _, r := range p.refus {
		out = append(out, Etat{Relais: r.Relais, Statut: StatutRefuse, Motif: r.Motif})
	}
	return out
}

// Serveurs rend les relais qui tournent, dans l'ordre de la liste. Pour les
// compteurs remontés au core.
func (p *Parc) Serveurs() []*Serveur {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]*Serveur, 0, len(p.actifs))
	vus := map[string]bool{}
	for _, nom := range p.ordre {
		if srv, ok := p.actifs[nom]; ok && !vus[nom] {
			vus[nom] = true
			out = append(out, srv)
		}
	}
	return out
}

// Fermer arrête toutes les écoutes.
func (p *Parc) Fermer() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, srv := range p.actifs {
		_ = srv.Fermer()
	}
}
