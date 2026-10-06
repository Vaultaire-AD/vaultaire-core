package dbjournaux

import (
	"database/sql"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"vaultaire/core/logs"
)

// L'écrivain : ce qui fait passer les lignes de journal en base.
//
// # Pourquoi une file, et pas un INSERT par ligne
//
// `logs.Write_Log` est appelé depuis toutes les goroutines du serveur, souvent
// au milieu d'une requête. Écrire en base à cet endroit ferait dépendre CHAQUE
// requête de la latence de la base, et une base arrêtée figerait le core au
// premier journal — y compris celui qui dit que la base est arrêtée.
//
// La ligne est donc posée dans une file bornée, sans attendre, et une goroutine
// unique l'insère par lots.
//
// # Ce qui se passe quand ça ne suit pas
//
// File pleine ou base injoignable : la ligne est PERDUE pour la base, et
// comptée. Elle reste sur la sortie standard et dans la mémoire du core, donc
// elle n'est pas perdue tout court. Le compte est dit une fois par minute, en
// WARNING, pour qu'un trou dans le journal commun se lise comme un trou et non
// comme une période calme.
//
// Attendre plutôt que perdre bloquerait les appelants — le défaut exact que la
// file existe pour éviter. Grossir la file sans borne déplacerait le problème
// dans la mémoire du core.

const (
	// CapaciteFile borne ce que l'écrivain garde en attente.
	//
	// Dix mille : la taille de la mémoire du portail (logs.CapaciteMemoire).
	// Au rythme d'un core sain, quelques minutes de base injoignable ; au-delà,
	// la base ne rattraperait de toute façon pas son retard avant longtemps.
	CapaciteFile = 10000

	// TailleLot est le nombre maximal de lignes par INSERT.
	//
	// Assez pour qu'un emballement ne fasse pas un aller-retour par ligne, assez
	// peu pour qu'une requête reste loin de max_allowed_packet même avec des
	// messages longs (200 × 8 Ko = 1,6 Mo, sous les 4 Mo par défaut de MariaDB).
	TailleLot = 200

	// IntervalleVidage est le délai maximal entre l'émission et l'insertion.
	//
	// Une seconde : sur le portail, une ligne qu'on vient de provoquer doit
	// apparaître à l'actualisation suivante.
	IntervalleVidage = time.Second

	// IntervalleSignalement espace les avertissements de lignes perdues.
	//
	// Base arrêtée, chaque lot échoue : un avertissement par lot en ferait un
	// par seconde, et le journal ne parlerait plus que de lui-même.
	IntervalleSignalement = time.Minute
)

// Ecrivain insère les lignes de journal en base, par lots, hors du chemin des
// appelants.
type Ecrivain struct {
	file    chan logs.LogEntry
	inserer func([]logs.LogEntry) error

	// perdues compte les lignes qui n'ont pas atteint la base depuis le dernier
	// signalement. Atomique : Recevoir l'incrémente depuis n'importe quelle
	// goroutine quand la file déborde.
	perdues atomic.Int64

	mu                 sync.Mutex
	derniereErreur     string
	dernierSignalement time.Time

	maintenant func() time.Time
}

// NouvelEcrivain prépare un écrivain autour d'une fonction d'insertion.
//
// La fonction est injectée plutôt qu'une *sql.DB : c'est ce qui permet
// d'éprouver les lots, les pertes et les signalements sans base.
func NouvelEcrivain(inserer func([]logs.LogEntry) error) *Ecrivain {
	return &Ecrivain{
		file:       make(chan logs.LogEntry, CapaciteFile),
		inserer:    inserer,
		maintenant: time.Now,
	}
}

// Recevoir est la sortie branchée sur le paquet logs. Ne bloque jamais.
func (e *Ecrivain) Recevoir(entree logs.LogEntry) {
	if !VaEnBase(entree) {
		return
	}
	select {
	case e.file <- entree:
	default:
		e.perdues.Add(1)
	}
}

// VaEnBase dit si une entrée a sa place dans le journal commun.
//
// Tout sauf le DEBUG — voir la documentation du paquet pour le seuil.
func VaEnBase(entree logs.LogEntry) bool {
	return entree.Severity < logs.SeverityDebug
}

// Tourner vide la file jusqu'à fermeture de `arret`. Nil : jamais.
//
// À l'arrêt, ce qui reste dans la file est inséré avant de rendre la main :
// les dernières lignes d'un core qu'on arrête sont souvent celles qui disent
// pourquoi.
func (e *Ecrivain) Tourner(arret <-chan struct{}) {
	minuterie := time.NewTicker(IntervalleVidage)
	defer minuterie.Stop()

	lot := make([]logs.LogEntry, 0, TailleLot)
	for {
		select {
		case entree := <-e.file:
			lot = append(lot, entree)
			if len(lot) >= TailleLot {
				e.traiter(lot)
				lot = lot[:0]
			}
		case <-minuterie.C:
			if len(lot) > 0 {
				e.traiter(lot)
				lot = lot[:0]
			}
			e.signalerPertes()
		case <-arret:
			e.viderFile(lot)
			return
		}
	}
}

// viderFile insère le lot en cours et tout ce qui attend encore dans la file.
//
// Une fonction à part plutôt qu'une boucle dans le `case` : un `break` dans un
// `select` ne sort que du `select`, et la boucle d'arrêt ne se serait jamais
// terminée.
func (e *Ecrivain) viderFile(lot []logs.LogEntry) {
	for {
		select {
		case entree := <-e.file:
			lot = append(lot, entree)
			if len(lot) >= TailleLot {
				e.traiter(lot)
				lot = lot[:0]
			}
		default:
			if len(lot) > 0 {
				e.traiter(lot)
			}
			return
		}
	}
}

// traiter insère un lot, et compte ses lignes comme perdues s'il échoue.
//
// Pas de nouvel essai : la base qui vient de refuser un lot refusera
// vraisemblablement le suivant, et retenter accumulerait en mémoire exactement
// ce que la file bornée existe pour éviter.
func (e *Ecrivain) traiter(lot []logs.LogEntry) {
	if err := e.inserer(lot); err != nil {
		e.perdues.Add(int64(len(lot)))
		e.mu.Lock()
		e.derniereErreur = err.Error()
		e.mu.Unlock()
	}
}

// signalerPertes dit, au plus une fois par IntervalleSignalement, combien de
// lignes n'ont pas atteint la base.
//
// L'avertissement passe par le journal ordinaire, donc revient dans cette file :
// base rétablie, il est lui-même inséré, et le trou se lit dans le journal
// commun à l'endroit où il s'est produit. Base toujours arrêtée, il est perdu à
// son tour et compté au signalement suivant — une ligne par minute, pas une
// boucle.
func (e *Ecrivain) signalerPertes() {
	e.mu.Lock()
	defer e.mu.Unlock()

	maintenant := e.maintenant()
	if !e.dernierSignalement.IsZero() &&
		maintenant.Sub(e.dernierSignalement) < IntervalleSignalement {
		return
	}
	n := e.perdues.Swap(0)
	if n == 0 {
		return
	}
	e.dernierSignalement = maintenant

	cause := "file d'attente pleine"
	if e.derniereErreur != "" {
		cause = "dernière erreur : " + e.derniereErreur
	}
	e.derniereErreur = ""
	logs.Write_LogCode("WARNING", logs.CodeLogCentral, fmt.Sprintf(
		"journaux: %d ligne(s) de ce core n'ont pas atteint le journal commun (%s). "+
			"Elles restent sur la sortie standard du core.", n, cause))
}

// --- insertion ---------------------------------------------------------------

// colonnes est l'ordre des valeurs d'une ligne insérée.
const colonnes = "created_at, severity, level, code, core_name, message, request_id, user_id"

// nbColonnes est tenu à côté de `colonnes` : un test vérifie qu'ils concordent.
const nbColonnes = 8

// requeteInsertion rend l'INSERT pour n lignes.
func requeteInsertion(n int) string {
	ligne := "(" + strings.TrimSuffix(strings.Repeat("?, ", nbColonnes), ", ") + ")"
	valeurs := make([]string, n)
	for i := range valeurs {
		valeurs[i] = ligne
	}
	return "INSERT INTO " + Table + " (" + colonnes + ") VALUES " + strings.Join(valeurs, ", ")
}

// valeursDe rend les valeurs d'une entrée, dans l'ordre de `colonnes`.
//
// L'heure est stockée en UTC : le pilote la relit en UTC (DSN sans `loc`), et
// deux cores réglés sur des fuseaux différents rangeraient sinon leurs lignes
// à des heures incomparables.
func valeursDe(e logs.LogEntry) []any {
	return []any{
		e.Timestamp.UTC(),
		e.Severity,
		tronquerCaracteres(e.Level, tailleNiveau),
		tronquerCaracteres(e.Code, tailleCode),
		tronquerCaracteres(e.Hostname, tailleCore),
		tronquerOctets(e.Message, tailleMessage),
		tronquerCaracteres(e.RequestID, tailleMeta),
		tronquerCaracteres(e.UserID, tailleMeta),
	}
}

// InsererLot écrit un lot de lignes en une requête.
func InsererLot(db *sql.DB, lot []logs.LogEntry) error {
	if len(lot) == 0 {
		return nil
	}
	if db == nil {
		return fmt.Errorf("connexion base indisponible")
	}
	args := make([]any, 0, len(lot)*nbColonnes)
	for _, e := range lot {
		args = append(args, valeursDe(e)...)
	}
	_, err := db.Exec(requeteInsertion(len(lot)), args...)
	return err
}

// marqueTroncature signale un message coupé : un message tronqué sans marque
// se lit comme complet, et la fin qui manque est souvent la cause.
const marqueTroncature = " […tronqué]"

// tronquerOctets coupe à `max` octets sans couper un caractère en deux — une
// séquence UTF-8 incomplète serait refusée par la colonne utf8mb4.
func tronquerOctets(s string, max int) string {
	if len(s) <= max {
		return s
	}
	coupe := max - len(marqueTroncature)
	for coupe > 0 && !utf8.RuneStart(s[coupe]) {
		coupe--
	}
	return s[:coupe] + marqueTroncature
}

// tronquerCaracteres coupe à `max` caractères : VARCHAR(n) se mesure en
// caractères.
func tronquerCaracteres(s string, max int) string {
	if utf8.RuneCountInString(s) <= max {
		return s
	}
	r := []rune(s)
	return string(r[:max])
}

// --- démarrage ---------------------------------------------------------------

// Demarrer branche le journal commun sur le paquet logs.
//
// `db` est une fonction et non une connexion : elle est relue à chaque lot,
// comme partout ailleurs par database.GetDatabase().
//
// À appeler APRÈS CreateTables : un lot inséré dans une table absente échoue,
// et les lignes seraient comptées perdues sans raison.
func Demarrer(db func() *sql.DB) *Ecrivain {
	e := NouvelEcrivain(func(lot []logs.LogEntry) error {
		return InsererLot(db(), lot)
	})
	go e.Tourner(nil)
	logs.BrancherSortie(e.Recevoir)
	return e
}
