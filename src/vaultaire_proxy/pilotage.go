package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"duckynetworkclient/V1/ducky"
	"duckynetworkclient/V1/duckynetwork/decouverte"
	"duckynetworkclient/V1/duckynetwork/enligne"
	"duckynetworkclient/V1/duckynetwork/logs"
	"duckynetworkclient/V1/duckynetwork/storage"

	"vaultaire_proxy/relais"
)

// Le pilotage des relais par le core (TO-DO 141).
//
// # Où vit la vérité
//
// Jusqu'ici, dans le fichier de configuration du proxy, et seulement là :
// changer un relais demandait de modifier ce fichier sur la machine et de
// redémarrer. Désormais :
//
//   - le FICHIER amorce. Un proxy que le core ne pilote pas applique son
//     fichier, comme avant, et le dit au core — c'est ce que la page Cluster
//     affiche ;
//   - le CORE fait foi dès qu'il a une liste pour ce proxy. Il la pousse, le
//     proxy l'applique à chaud, et rend compte de ce qu'il a obtenu ;
//   - la COPIE LOCALE de la dernière liste reçue sert au DÉMARRAGE. Un proxy
//     qui redémarre rouvre ce qu'il appliquait avant de s'arrêter, sans
//     attendre que le core le lui redise : sans elle, il ouvrirait d'abord les
//     relais de son fichier, puis les refermerait une minute plus tard pour
//     ceux du core — et, entre les deux, les relais posés par le core
//     n'écouteraient pas.
//
// # À froid, sans core
//
// La copie locale sert aussi à cela (TO-DO 158) : les relais s'ouvrent avant
// que le proxy n'ait une session, depuis elle ou depuis le fichier. Un proxy
// qui redémarre pendant une coupure du lien rouvre donc ce qu'il appliquait —
// et ses relais vers des cibles locales relaient. Jusque-là, ils ne
// s'ouvraient qu'une fois la session établie, et un proxy qui n'en obtenait
// pas en trente secondes s'arrêtait : la copie n'était jamais lue à froid.
// Un proxy DÉJÀ démarré qui perd ses cores garde ses relais ouverts, comme
// avant : le SDK retente la connexion, et rien ne touche au parc entre-temps.
//
// # Ce que le core ne décide pas
//
// S'il a obtenu un port. Le proxy tourne souvent sans le droit d'ouvrir un
// port bas, et un port peut être pris : chaque relais demandé reçoit un état,
// actif ou refusé avec son motif, et c'est le proxy qui le dit.

// NomCopieLocale est le fichier, dans le répertoire des clés, où le proxy
// garde la dernière liste reçue du core.
//
// À côté de l'identité et non du fichier de configuration : ce dernier est
// souvent monté en lecture seule et partagé entre plusieurs proxies ; le
// répertoire des clés est celui que le proxy écrit déjà, et qui lui est propre.
const NomCopieLocale = "relais_du_core.json"

// CadenceCompteRendu espace deux comptes rendus spontanés.
//
// Une minute : c'est le délai au bout duquel un proxy raccordé à un AUTRE core
// que celui où l'administrateur a fait son changement le reçoit — le core qui
// a écrit ne peut pousser qu'aux proxies qu'il tient lui-même. C'est aussi
// l'âge maximal de ce que la page Cluster affiche.
const CadenceCompteRendu = time.Minute

// MotifPilotageRefuse est rendu au core par un proxy qui garde la main.
const MotifPilotageRefuse = "ce proxy garde la main sur ses relais : son fichier de configuration porte « pilotage_par_le_core: false »"

// copieLocale est le contenu du fichier NomCopieLocale.
type copieLocale struct {
	Revision int             `json:"revision"`
	Relais   []relais.Relais `json:"relais"`
	Recue    string          `json:"recue"`
}

// pilote tient les relais du proxy et leur provenance.
type pilote struct {
	mu sync.Mutex

	parc         *relais.Parc
	cheminConfig string
	cheminCopie  string
	portAnnonce  int
	autorise     bool

	origine         string
	revision        int
	revisionRefusee int
	refus           string

	// rendreCompte émet le compte rendu. Injecté pour les tests.
	rendreCompte func(document string) bool
}

// nouveauPilote prépare le pilotage. Rien n'est ouvert avant demarrer.
func nouveauPilote(cheminConfig string, portAnnonce int) *pilote {
	journal := func(niveau, message string) { logs.Write_log(niveau, message) }
	parc := relais.NouveauParc(portAnnonce, resolveurPour, journal)
	parc.Lancer = func(nom string, f func()) { logs.Go(nom, f) }
	// Un tunnel relayé ne doit pas être coupé par le proxy avant que ses deux
	// bouts ne le fassent (TO-DO 110) : le délai suit la cadence du core.
	parc.InactiviteMinDucky = enligne.DelaiDeFermeture

	return &pilote{
		parc:         parc,
		cheminConfig: cheminConfig,
		cheminCopie:  storage.CheminDansKeyPath(NomCopieLocale),
		portAnnonce:  portAnnonce,
		autorise:     relais.PilotageAutorise(cheminConfig),
		origine:      relais.OrigineFichier,
		rendreCompte: func(document string) bool {
			return decouverte.EmettreEtatRelais(ducky.CleDeSession, document)
		},
	}
}

// demarrer ouvre les relais : ceux de la copie locale si le core pilotait ce
// proxy à son dernier arrêt, ceux du fichier sinon.
//
// Une erreur est FATALE pour l'appelant : ce proxy est annoncé aux agents sur
// son port Ducky, et y laisser un port mort en ferait un trou noir.
func (p *pilote) demarrer(duFichier []relais.Relais) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.autorise {
		if copie, ok := p.lireCopie(); ok {
			etats, err := p.parc.Appliquer(copie.Relais)
			if err == nil && relaisDuckyActif(etats) {
				p.origine, p.revision = relais.OrigineCore, copie.Revision
				logs.Write_log("INFO", fmt.Sprintf(
					"relais : démarrage sur la copie locale de la liste du core (révision %d, reçue le %s) — "+
						"le fichier de configuration n'est pas appliqué", copie.Revision, copie.Recue))
				p.journaliserLesRefus(etats)
				p.apresApplication()
				return nil
			}
			// La copie ne tient plus debout sur cette machine — le port annoncé
			// a changé, par exemple. Le fichier reprend la main, et on le dit.
			logs.Write_log("WARNING", fmt.Sprintf(
				"relais : copie locale de la liste du core inapplicable (%v) — démarrage sur le fichier de configuration",
				motifDe(err, etats)))
		}
	} else {
		logs.Write_log("INFO", "relais : "+MotifPilotageRefuse)
	}

	etats, err := p.parc.Appliquer(duFichier)
	if err != nil {
		return err
	}
	// Le fichier reste STRICT, comme avant : quelqu'un vient de l'écrire, et
	// un relais qu'il déclare et qui n'écoute pas doit arrêter le démarrage.
	for _, e := range etats {
		if e.Statut == relais.StatutRefuse {
			return fmt.Errorf("relais %s : %s", e.Relais.Nom, e.Motif)
		}
	}
	p.origine, p.revision = relais.OrigineFichier, 0
	p.apresApplication()
	return nil
}

func relaisDuckyActif(etats []relais.Etat) bool {
	for _, e := range etats {
		if e.Relais.Type == relais.TypeDucky && e.Statut == relais.StatutActif {
			return true
		}
	}
	return false
}

func motifDe(err error, etats []relais.Etat) string {
	if err != nil {
		return err.Error()
	}
	for _, e := range etats {
		if e.Relais.Type == relais.TypeDucky && e.Statut == relais.StatutRefuse {
			return e.Motif
		}
	}
	return "relais Ducky absent"
}

// apresApplication publie les relais pour les compteurs du battement et fait
// suivre au SDK les types de services dont ils ont besoin.
func (p *pilote) apresApplication() {
	serveurs := p.parc.Serveurs()
	relaisVivants.Store(&serveurs)

	var suivis []relais.Relais
	for _, s := range serveurs {
		suivis = append(suivis, s.Config())
	}
	decouverte.SuivreServicesEnPlus(relais.ServicesSuivis(suivis))
}

func (p *pilote) journaliserLesRefus(etats []relais.Etat) {
	for _, e := range etats {
		if e.Statut == relais.StatutRefuse {
			logs.Write_log("WARNING", fmt.Sprintf("relais %s : REFUSÉ — %s", e.Relais.Nom, e.Motif))
		}
	}
}

// surConfiguration applique une 04_19, puis rend compte.
func (p *pilote) surConfiguration(cfg decouverte.ConfigurationRelais) {
	p.mu.Lock()
	switch cfg.Mode {
	case decouverte.ModeCore:
		p.appliquerDuCore(cfg)
	case decouverte.ModeFichier:
		p.revenirAuFichier()
	}
	document := p.document()
	p.mu.Unlock()

	p.rendreCompte(document)
}

// appliquerDuCore applique la liste d'une révision du core.
func (p *pilote) appliquerDuCore(cfg decouverte.ConfigurationRelais) {
	if !p.autorise {
		if p.revisionRefusee != cfg.Revision {
			logs.Write_log("WARNING", fmt.Sprintf("relais : révision %d du core refusée — %s", cfg.Revision, MotifPilotageRefuse))
		}
		p.revisionRefusee, p.refus = cfg.Revision, MotifPilotageRefuse
		return
	}
	if p.origine == relais.OrigineCore && p.revision == cfg.Revision {
		// Déjà appliquée : le core la renvoie parce que notre compte rendu ne
		// lui est pas encore parvenu. Rien à refaire.
		return
	}

	demande, err := relais.LireDemande(cfg.Document)
	if err == nil {
		var etats []relais.Etat
		if etats, err = p.parc.Appliquer(demande.Relais); err == nil {
			p.origine, p.revision = relais.OrigineCore, cfg.Revision
			p.revisionRefusee, p.refus = 0, ""
			logs.Write_log("INFO", fmt.Sprintf("relais : révision %d du core appliquée (%d relais demandé(s))",
				cfg.Revision, len(demande.Relais)))
			p.journaliserLesRefus(etats)
			p.ecrireCopie(cfg.Revision, demande.Relais)
			p.apresApplication()
			return
		}
	}
	// Refus de la liste ENTIÈRE : rien n'a été touché.
	logs.Write_log("ERROR", fmt.Sprintf("relais : révision %d du core REFUSÉE, rien n'a changé — %v", cfg.Revision, err))
	p.revisionRefusee, p.refus = cfg.Revision, err.Error()
}

// revenirAuFichier réapplique le fichier de configuration : le core ne pilote
// pas, ou plus, ce proxy.
func (p *pilote) revenirAuFichier() {
	if p.origine == relais.OrigineFichier {
		return
	}
	liste, err := relais.Charger(p.cheminConfig, p.portAnnonce)
	if err == nil {
		_, err = p.parc.Appliquer(liste)
	}
	if err != nil {
		// On garde ce qui tourne : un fichier devenu illisible ne doit pas
		// couper un site au moment où l'on rend la main.
		logs.Write_log("ERROR", fmt.Sprintf(
			"relais : retour au fichier de configuration impossible, la liste du core reste appliquée — %v", err))
		p.refus = "retour au fichier de configuration impossible : " + err.Error()
		return
	}
	p.origine, p.revision = relais.OrigineFichier, 0
	p.revisionRefusee, p.refus = 0, ""
	if err := os.Remove(p.cheminCopie); err != nil && !os.IsNotExist(err) {
		logs.Write_log("WARNING", "relais : copie locale non retirée : "+err.Error())
	}
	logs.Write_log("INFO", "relais : le core a rendu la main — fichier de configuration réappliqué")
	p.apresApplication()
}

// document compose le compte rendu courant. À appeler sous le verrou.
func (p *pilote) document() string {
	return relais.CompteRendu{
		Version:         relais.VersionDuDocument,
		Revision:        p.revision,
		Origine:         p.origine,
		Pilotage:        p.autorise,
		PortAnnonce:     p.portAnnonce,
		RevisionRefusee: p.revisionRefusee,
		Refus:           p.refus,
		Relais:          relais.Composer(p.parc.Etats()),
	}.Encoder()
}

// Document rend le compte rendu courant.
func (p *pilote) Document() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.document()
}

// boucleDeCompteRendu rend compte tout de suite, puis à chaque cadence. Ne
// rend jamais la main : à lancer dans une goroutine.
//
// Vers un core qui n'annonce pas la capacité, rien ne part — voir
// decouverte.EmettreEtatRelais. Le proxy se comporte alors comme avant.
func (p *pilote) boucleDeCompteRendu() {
	for {
		p.rendreCompte(p.Document())
		time.Sleep(CadenceCompteRendu)
	}
}

// lireCopie relit la dernière liste reçue du core.
func (p *pilote) lireCopie() (copieLocale, bool) {
	data, err := os.ReadFile(p.cheminCopie)
	if err != nil {
		if !os.IsNotExist(err) {
			logs.Write_log("WARNING", "relais : copie locale illisible : "+err.Error())
		}
		return copieLocale{}, false
	}
	var c copieLocale
	if err := json.Unmarshal(data, &c); err != nil || c.Revision < 1 || len(c.Relais) == 0 {
		logs.Write_log("WARNING", fmt.Sprintf("relais : copie locale %s inutilisable, ignorée", p.cheminCopie))
		return copieLocale{}, false
	}
	return c, true
}

// ecrireCopie garde la liste qui vient d'être appliquée.
//
// Écrite à côté puis renommée : un proxy arrêté au milieu de l'écriture ne
// doit pas redémarrer sur une moitié de liste.
func (p *pilote) ecrireCopie(revision int, liste []relais.Relais) {
	data, err := json.MarshalIndent(copieLocale{
		Revision: revision, Relais: liste, Recue: time.Now().Format("2006-01-02 15:04:05"),
	}, "", "  ")
	if err == nil {
		provisoire := p.cheminCopie + ".tmp"
		if err = os.MkdirAll(filepath.Dir(p.cheminCopie), 0o700); err == nil {
			if err = os.WriteFile(provisoire, data, 0o600); err == nil {
				err = os.Rename(provisoire, p.cheminCopie)
			}
		}
	}
	if err != nil {
		// Pas fatal : la liste est appliquée. Ce qui est perdu est la reprise
		// immédiate au prochain démarrage, et c'est ce que la ligne dit.
		logs.Write_log("WARNING", fmt.Sprintf(
			"relais : copie locale non écrite (%v) — au prochain démarrage, ce proxy ouvrira d'abord les relais "+
				"de son fichier de configuration, jusqu'à ce que le core lui renvoie sa liste", err))
	}
}

// relaisActifs compte les relais qui écoutent.
func (p *pilote) relaisActifs() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	n := 0
	for _, e := range p.parc.Etats() {
		if e.Statut == relais.StatutActif {
			n++
		}
	}
	return n
}

// fermer arrête les écoutes et rend le dernier bilan.
func (p *pilote) fermer() {
	for _, srv := range p.parc.Serveurs() {
		_ = srv.Fermer()
		logs.Write_log("INFO", srv.Stats().Resume())
	}
}
