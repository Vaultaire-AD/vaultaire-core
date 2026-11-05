package miseajour

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"duckynetworkclient/V1/duckynetwork/enligne"
	"duckynetworkclient/V1/duckynetwork/logs"
	"duckynetworkclient/V1/duckynetwork/storage"

	"vaultaire_client/pamstate"
	"vaultaire_client/version"
)

// L'ordre de mise à jour — catégorie 09 (TO-DO 115).
//
//	09_01  demander l'ordre        agent → core    au démarrage et à chaque tunnel rétabli
//	  09_02  ordre                 core → agent    version, dépôt, rétrogradation
//	  09_03  rien à faire          core → agent    motif
//	09_04  compte rendu            agent → core    version, résultat, motif
//	  09_05  accusé                core → agent
//	09_06  ordre poussé            core → agent    même contenu que 09_02
//
// # Ce que l'agent garde pour lui
//
// Le core dit QUELLE version prendre ; l'agent refuse de toute façon une
// version inférieure à la sienne, sauf rétrogradation explicitement demandée
// par l'ordre. C'est ce qui ferme la rejouabilité d'un manifeste qui ne nomme
// aucune machine (Mise_a_jour_du_parc.md § 4.3) : il faudrait à la fois le
// dépôt ET le tunnel pour ramener une version ancienne.
//
// # Appliquer, depuis le 116
//
// Appliquer lance le déroulé en arrière-plan et rend « en cours » (résultat
// vide) : le compte rendu part plus tard, de l'état écrit par celui qui sait
// — voir appliquer.go et bascule.go.

// Résultats d'un compte rendu. Les mêmes chaînes vivent dans le core
// (vaultaire_serveur/core/miseajour) : des tests jumeaux les figent.
const (
	ResultatInstalle        = "installe"
	ResultatEchec           = "echec"
	ResultatRefuse          = "refuse"
	ResultatNonPrisEnCharge = "non_pris_en_charge"
)

// Ordre est le contenu d'une 09_02 ou d'une 09_06.
type Ordre struct {
	Version     string
	Depot       string
	Retrograder bool
}

var (
	formeVersion = regexp.MustCompile(`^[0-9]{1,6}\.[0-9]{1,6}\.[0-9]{1,6}$`)
	formeDepot   = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
)

// LireOrdre analyse le contenu d'une 09_02 / 09_06. Strict : un ordre qui ne
// se lit pas exactement n'est pas exécuté.
func LireOrdre(contenu string) (Ordre, error) {
	l := strings.Split(strings.TrimRight(strings.ReplaceAll(contenu, "\r", ""), "\n"), "\n")
	if len(l) != 3 {
		return Ordre{}, fmt.Errorf("ordre de %d ligne(s), 3 attendues", len(l))
	}
	o := Ordre{Version: strings.TrimSpace(l[0]), Depot: strings.TrimSpace(l[1])}
	switch strings.TrimSpace(l[2]) {
	case "oui":
		o.Retrograder = true
	case "non":
	default:
		return Ordre{}, fmt.Errorf("rétrogradation %q : oui ou non attendu", l[2])
	}
	if !formeVersion.MatchString(o.Version) {
		return Ordre{}, fmt.Errorf("version %q illisible", o.Version)
	}
	if !formeDepot.MatchString(o.Depot) {
		return Ordre{}, fmt.Errorf("dépôt %q illisible", o.Depot)
	}
	return o, nil
}

// triplet lit les trois nombres de tête d'une version (« 2.3.0+g… (date) »).
func triplet(v string) ([3]int, bool) {
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	if i := strings.IndexAny(v, "+ -("); i >= 0 {
		v = v[:i]
	}
	p := strings.Split(v, ".")
	var out [3]int
	if len(p) != 3 {
		return out, false
	}
	for i, s := range p {
		n, err := strconv.Atoi(s)
		if err != nil || n < 0 {
			return out, false
		}
		out[i] = n
	}
	return out, true
}

// comparer rend -1, 0 ou 1.
func comparer(a, b [3]int) int {
	for i := range a {
		switch {
		case a[i] < b[i]:
			return -1
		case a[i] > b[i]:
			return 1
		}
	}
	return 0
}

// Appliquer installe une version (appliquer.go). Rend le résultat et son
// motif, ou un résultat VIDE quand le déroulé est lancé : le compte rendu
// viendra de l'état. Remplaçable par les tests.
var Appliquer func(o Ordre) (resultat, motif string)

// versionEnPlace : remplaçable par les tests.
var versionEnPlace = func() string { return version.Version }

// Traiter décide de ce que l'agent fait d'un ordre, et rend son compte rendu.
func Traiter(o Ordre) (resultat, motif string) {
	enPlace, ok := triplet(versionEnPlace())
	if !ok {
		return ResultatRefuse, "version en place illisible (" + versionEnPlace() + ")"
	}
	voulue, _ := triplet(o.Version)
	switch c := comparer(voulue, enPlace); {
	case c == 0:
		return ResultatInstalle, "déjà en place"
	case c < 0 && !o.Retrograder:
		logs.Write_log("SECURITY", fmt.Sprintf(
			"mise à jour : ordre de passer en %s REFUSÉ — c'est une rétrogradation (en place : %s), "+
				"et l'ordre ne la demande pas", o.Version, versionEnPlace()))
		return ResultatRefuse, "rétrogradation non demandée (en place : " + versionEnPlace() + ")"
	case c < 0:
		logs.Write_log("SECURITY", fmt.Sprintf(
			"mise à jour : rétrogradation demandée par le core, de %s vers %s", versionEnPlace(), o.Version))
	}
	return Appliquer(o)
}

// CompteRendu compose la 09_04. Le motif est borné et tient sur une ligne :
// il part vers le core et finit en base.
func CompteRendu(sessionKey, version, resultat, motif string) string {
	motif = strings.ReplaceAll(strings.ReplaceAll(motif, "\r", " "), "\n", " ")
	if r := []rune(motif); len(r) > 240 {
		motif = string(r[:240])
	}
	return strings.Join([]string{
		"09_04", "serveur_central", sessionKey, pamstate.Username, storage.Computeur_ID,
		version, resultat, motif,
	}, "\n")
}

// Demande compose la 09_01 : aucun contenu, le core lit la machine dans
// l'en-tête authentifié.
func Demande(sessionKey string) string {
	return strings.Join([]string{"09_01", "serveur_central", sessionKey, pamstate.Username, storage.Computeur_ID}, "\n")
}

// HandleTrame traite une trame 09_xx reçue du core, et rend la réponse.
func HandleTrame(t storage.Trames_struct_client, _ *storage.DuckySession) string {
	if len(t.Message_Order) < 2 {
		return ""
	}
	switch t.Message_Order[1] {
	case "02", "06":
		o, err := LireOrdre(t.Content)
		if err != nil {
			logs.Write_log("WARNING", "mise à jour : ordre 09_"+t.Message_Order[1]+" refusé : "+err.Error())
			// Pas de compte rendu : sans version lisible, le core ne saurait
			// pas à quoi le rattacher.
			return ""
		}
		logs.Write_log("INFO", fmt.Sprintf("mise à jour : ordre reçu — %s depuis le dépôt %s%s",
			o.Version, o.Depot, map[bool]string{true: " (rétrogradation demandée)", false: ""}[o.Retrograder]))
		resultat, motif := Traiter(o)
		if resultat == "" {
			// En cours : le compte rendu viendra de l'état.
			return ""
		}
		logs.Write_log("INFO", fmt.Sprintf("mise à jour : %s — %s (%s)", o.Version, resultat, motif))
		return CompteRendu(t.SessionIntegritykey, o.Version, resultat, motif)
	case "03":
		logs.Write_log("DEBUG", "mise à jour : rien à faire — "+strings.TrimSpace(t.Content))
	case "05":
		logs.Write_log("DEBUG", "mise à jour : compte rendu reçu par le core")
	case "08":
		// L'accusé du compte rendu de configuration (09_07, TO-DO 117).
		logs.Write_log("DEBUG", "configuration système : compte rendu reçu par le core")
	case "10":
		// Le jeu de clés de confiance des paquets (TO-DO 207).
		return recevoirJeu(t)
	default:
		logs.Write_log("WARNING", "mise à jour : sous-ordre 09_"+t.Message_Order[1]+" inattendu côté agent")
	}
	return ""
}

// --- la demande, à chaque tunnel ---------------------------------------------

var (
	envoyerMu sync.RWMutex
	envoyer   func(trame string)
)

// Configure branche l'émetteur des trames.
func Configure(f func(trame string)) {
	envoyerMu.Lock()
	envoyer = f
	envoyerMu.Unlock()
}

func emettre(trame string) bool {
	envoyerMu.RLock()
	f := envoyer
	envoyerMu.RUnlock()
	if f == nil {
		return false
	}
	f(trame)
	return true
}

// coreSait : remplaçable par les tests.
var coreSait = func() bool { return enligne.CoreSait(enligne.CapaciteMiseAJour) }

// suivi décide quand demander : une fois par clé de session — donc au
// démarrage et à chaque tunnel rétabli —, et seulement vers un core qui
// annonce la capacité. Un core plus ancien FERMERAIT la connexion sur une
// 09_01 : on attend qu'un core la connaisse, sans rien émettre.
type suivi struct{ derniereCle string }

func (s *suivi) doitDemander(cle string, sait bool) bool {
	return cle != "" && cle != s.derniereCle && sait
}

// SurveillerLesOrdres demande l'ordre à chaque session neuve. Ne rend jamais
// la main : à lancer dans une goroutine.
func SurveillerLesOrdres(cleDeSession func() string) {
	var s suivi
	for {
		cle := cleDeSession()
		// Un compte rendu en attente part d'abord : celui d'une bascule faite
		// pendant que l'agent redémarrait, ou d'un refus de préparation.
		if cle != "" && coreSait() {
			if trame, marquer := compteRenduEnAttente(cheminsAgent, cle); trame != "" && emettre(trame) {
				marquer()
				logs.Write_log("INFO", "mise à jour : compte rendu envoyé au core")
			}
		}
		if s.doitDemander(cle, coreSait()) {
			if emettre(Demande(cle)) {
				s.derniereCle = cle
				logs.Write_log("DEBUG", "mise à jour : ordre demandé au core")
			}
		}
		time.Sleep(2 * time.Second)
	}
}
